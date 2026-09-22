//! `ledger`: reads the chain behind a settlement receipt, so that a success is not only the facilitator's word.
//!
//! Three questions, each answered from the transaction receipt a JSON-RPC node returns: is the transaction included
//! and successful on the paid network; does it carry exactly one transfer of the offered amount of the asset from
//! the payer to `payTo`; did the asset record the expected authorization as used (EIP-3009 `AuthorizationUsed` with
//! the payer and the nonce: the nonce `pay` chose, or the one given to the `ledger` command). The last question ties
//! the transfer to this payment as far as two events in one transaction can: a compatible transfer without that
//! event proves that someone paid, not that this authorization was consumed.
//!
//! What a node says about a mined block is one step further than the facilitator, not a proof of finality, and the
//! server under test is not the one who wrote the block. A chain that contradicts the receipt is therefore never
//! attributed to the server alone: the finding is blocked with an unknown attribution and listed as not
//! demonstrated.

use std::time::Duration;

use alloy_primitives::{Address, B256, U256};
use url::Url;
use x402_checker_evm::Eip3009Offer;
use x402_checker_ledger::{Ledger, TransactionReceipt, Wait, public_rpc};
use x402_checker_types::Caip2;

use crate::check::{Attribution, Check, Finding, LedgerSnapshot, Level, Source};

/// How the chain is read.
#[derive(Debug, Clone)]
pub struct LedgerOptions {
    /// JSON-RPC endpoint; a public endpoint of the paid test network when `None`.
    pub rpc_url: Option<Url>,
    /// How long the whole reading may take, chain id check and every request included.
    pub wait: Duration,
}

/// What the transaction must show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expected {
    /// EVM chain id of the paid network.
    pub chain_id: u64,
    /// Token contract.
    pub asset: Address,
    /// Recipient of the offer.
    pub pay_to: Address,
    /// Amount of the offer, atomic units.
    pub amount: U256,
    /// The paying wallet.
    pub payer: Address,
    /// Nonce of the authorization the tool signed, when known.
    pub nonce: Option<B256>,
}

impl Expected {
    /// The expectation for `offer` paid by `payer`.
    pub fn of_offer(offer: &Eip3009Offer, payer: Address, nonce: Option<B256>) -> Self {
        Self {
            chain_id: offer.chain_id,
            asset: offer.asset,
            pay_to: offer.pay_to,
            amount: offer.amount,
            payer,
            nonce,
        }
    }
}

const ENDPOINT: Check = Check {
    id: "LEDGER-RPC",
    title: "the node the tool read",
    level: Level::Optional,
    source: Source::Policy,
    clause: "extensions/offer-receipt 5.5: \"verifiers MAY check the blockchain to confirm the transaction exists and matches expected parameters\"",
    ambiguity: None,
};
const INCLUDED: Check = Check {
    id: "LEDGER-TX",
    title: "the receipt's transaction is included on the paid network and succeeded",
    level: Level::Required,
    source: Source::Prose,
    clause: "x402-specification-v2.md 5.3.2: success \"Whether the settlement succeeded\", transaction \"Blockchain transaction hash\"",
    ambiguity: Some(
        "a chain that contradicts the receipt is not attributed: the server relays its facilitator's word and, from outside, nothing says which of them named the transaction. One node's receipt describes a mined block, not a final one",
    ),
};
const TRANSFER: Check = Check {
    id: "EXACT-017",
    title: "the transaction carries exactly one transfer of amount of asset from the payer to payTo",
    level: Level::Required,
    source: Source::ExplicitMust,
    clause: "schemes/exact/scheme_exact.md: \"settlement MUST produce exactly one identifiable transfer of amount of asset to payTo. Operations incidental to that transfer ... do not disqualify it\"",
    ambiguity: Some(
        "judged on the Transfer events the asset emitted in this transaction, not on balances; several identical transfers (a batch) leave the binding ambiguous and are reported as not assessable, not as a double charge",
    ),
};
const BINDING: Check = Check {
    id: "EVM-006",
    title: "the asset recorded the expected authorization as used (AuthorizationUsed with the payer and the nonce)",
    level: Level::Required,
    source: Source::Prose,
    clause: "schemes/exact/scheme_exact_evm.md: \"the Facilitator cannot modify the amount or destination. They serve only as the transaction broadcaster\"; EIP-3009 (spec/external): \"event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce)\"",
    ambiguity: Some(
        "an asset that emits no EIP-3009 event leaves the binding unestablished: reported as not assessable, since the core text does not require the event",
    ),
};

const JUDGED: [&Check; 3] = [&INCLUDED, &TRANSFER, &BINDING];

/// The three judged checks with the same verdict.
fn each(make: impl Fn(&Check) -> Finding) -> Vec<Finding> {
    JUDGED.iter().map(|check| make(check)).collect()
}

/// The ledger checks, skipped for `why`.
pub fn skipped(why: &str) -> Verified {
    Verified {
        findings: each(|check| Finding::skip(check, why)),
        snapshot: None,
    }
}

/// What a reading produced: the findings, and the receipt they were judged on when one was obtained.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    /// In evaluation order.
    pub findings: Vec<Finding>,
    /// The node's answer, for the report.
    pub snapshot: Option<LedgerSnapshot>,
}

impl Verified {
    fn without_receipt(findings: Vec<Finding>) -> Self {
        Self {
            findings,
            snapshot: None,
        }
    }
}

/// Reads the chain for `transaction` and judges it against `expected`. `receipt_network` is the network the
/// receipt names, checked against the paid one before any node is contacted. `ev` points at the exchange that
/// carried the receipt.
pub async fn verify(
    expected: &Expected,
    transaction: &str,
    receipt_network: Option<&str>,
    options: Option<&LedgerOptions>,
    ev: &[usize],
) -> Verified {
    let Some(options) = options else {
        return skipped("chain not read (--no-ledger): the transfer is not established");
    };
    if let Some(network) = receipt_network
        && network.parse::<Caip2>().ok().and_then(|n| n.evm_chain_id()) != Some(expected.chain_id)
    {
        let why = format!(
            "the receipt names {network}, the paid offer is eip155:{}; the tool does not pick a chain from an inconsistent receipt",
            expected.chain_id
        );
        return Verified::without_receipt(each(|check| {
            Finding::blocked(check, Attribution::Unknown, why.clone(), ev)
        }));
    }
    let Ok(hash) = transaction.parse::<B256>() else {
        let why = format!("transaction {transaction:?} is not a 32-byte hash, nothing to look up");
        return Verified::without_receipt(each(|check| {
            Finding::blocked(check, Attribution::Unknown, why.clone(), ev)
        }));
    };
    let url = match &options.rpc_url {
        Some(url) => url.clone(),
        None => match public_rpc(expected.chain_id).and_then(|u| u.parse().ok()) {
            Some(url) => url,
            None => {
                return skipped(&format!(
                    "no public endpoint known for eip155:{}: pass --rpc-url",
                    expected.chain_id
                ));
            }
        },
    };
    let ledger = match Ledger::new(url) {
        Ok(ledger) => ledger,
        Err(error) => {
            let why = format!("no HTTP client for the node: {error}");
            return Verified::without_receipt(each(|check| {
                Finding::blocked(check, Attribution::Harness, why.clone(), ev)
            }));
        }
    };
    let mut findings = vec![Finding::info(
        &ENDPOINT,
        format!("eip155:{} read through {}", expected.chain_id, ledger.url()),
        ev,
    )];
    let mut verified = read(&ledger, expected, hash, options.wait, ev).await;
    findings.append(&mut verified.findings);
    verified.findings = findings;
    verified
}

async fn read(ledger: &Ledger, expected: &Expected, hash: B256, wait: Duration, ev: &[usize]) -> Verified {
    let dependency = |why: String| {
        Verified::without_receipt(each(|check| {
            Finding::blocked(check, Attribution::Dependency, why.clone(), ev)
        }))
    };
    let started = tokio::time::Instant::now();
    let chain_id = match tokio::time::timeout(wait, ledger.chain_id()).await {
        Err(_elapsed) => {
            return dependency(format!(
                "{} did not answer eth_chainId within the {}s deadline",
                ledger.url(),
                wait.as_secs()
            ));
        }
        Ok(Ok(id)) if id == expected.chain_id => id,
        Ok(Ok(id)) => {
            let why = format!(
                "the endpoint serves eip155:{id}, not eip155:{}: pass --rpc-url with a node of the paid network",
                expected.chain_id
            );
            return Verified::without_receipt(each(|check| {
                Finding::blocked(check, Attribution::Harness, why.clone(), ev)
            }));
        }
        Ok(Err(error)) => return dependency(format!("the node could not be read: {error}")),
    };
    let seconds = wait.as_secs();
    let remaining = wait.saturating_sub(started.elapsed());
    let (on_chain, state) = match ledger.wait_for_receipt(hash, remaining).await {
        Ok(Wait::Sealed(receipt)) => (receipt, "sealed"),
        Ok(Wait::Preconfirmed(receipt)) => (receipt, "preconfirmed"),
        Ok(Wait::Unknown { polls }) => {
            return Verified::without_receipt(vec![
                Finding::blocked(
                    &INCLUDED,
                    Attribution::Unknown,
                    format!(
                        "{} answered null to {polls} polls over {seconds}s: no inclusion receipt for {hash} from that node, pending, dropped or unknown to it",
                        ledger.url()
                    ),
                    ev,
                ),
                Finding::cannot_assess(&TRANSFER, "no transaction to read", ev),
                Finding::cannot_assess(&BINDING, "no transaction to read", ev),
            ]);
        }
        Ok(Wait::Unanswered { polls }) => {
            return dependency(format!(
                "no complete answer from {} before the {seconds}s deadline ({polls} answered polls, all null): the node's state was not observed",
                ledger.url()
            ));
        }
        Err(error) => return dependency(format!("the node could not be read: {error}")),
    };
    let snapshot = Some(LedgerSnapshot {
        node: ledger.url().to_string(),
        observed_at: jiff::Timestamp::now()
            .round(jiff::Unit::Second)
            .unwrap_or_default(),
        chain_id,
        state,
        receipt: on_chain.clone(),
    });
    let findings = judge_receipt(ledger, &on_chain, state, expected, hash, seconds, ev);
    Verified { findings, snapshot }
}

/// The three claims on a receipt the node returned.
fn judge_receipt(
    ledger: &Ledger,
    on_chain: &TransactionReceipt,
    state: &str,
    expected: &Expected,
    hash: B256,
    seconds: u64,
    ev: &[usize],
) -> Vec<Finding> {
    if state == "preconfirmed" {
        return vec![
            Finding::cannot_assess(
                &INCLUDED,
                format!(
                    "{} only returned a receipt with a zero block hash within {seconds}s (a sequencer preconfirmation, block {} not sealed): inclusion not observed; run `ledger {hash}` later",
                    ledger.url(),
                    on_chain.block_number
                ),
                ev,
            ),
            Finding::cannot_assess(&TRANSFER, "the transaction is not in a sealed block yet", ev),
            Finding::cannot_assess(&BINDING, "the transaction is not in a sealed block yet", ev),
        ];
    }
    if !on_chain.succeeded() {
        return vec![
            Finding::blocked(
                &INCLUDED,
                Attribution::Unknown,
                format!(
                    "{hash} reverted in block {} while the receipt says success",
                    on_chain.block_number
                ),
                ev,
            ),
            Finding::cannot_assess(&TRANSFER, "the transaction reverted, no transfer", ev),
            Finding::cannot_assess(&BINDING, "the transaction reverted", ev),
        ];
    }
    vec![
        Finding::pass(
            &INCLUDED,
            format!(
                "included in block {} ({}), status 1, submitted by {}, as seen by {} at {}; sealed, finality not assessed",
                on_chain.block_number,
                on_chain.block_hash,
                on_chain.from,
                ledger.url(),
                jiff::Timestamp::now()
                    .round(jiff::Unit::Second)
                    .unwrap_or_default()
            ),
            ev,
        ),
        transfer_finding(on_chain, expected, ev),
        binding_finding(on_chain, expected, ev),
    ]
}

/// Exactly one `Transfer(payer, payTo, amount)` from the asset; other transfers are incidental.
fn transfer_finding(on_chain: &TransactionReceipt, expected: &Expected, ev: &[usize]) -> Finding {
    let transfers = on_chain.transfers(expected.asset);
    let matching = transfers
        .iter()
        .filter(|t| t.from == expected.payer && t.to == expected.pay_to && t.value == expected.amount)
        .count();
    let listed = transfers
        .iter()
        .map(|t| format!("{} -> {}: {}", t.from, t.to, t.value))
        .collect::<Vec<_>>()
        .join("; ");
    match matching {
        1 => Finding::pass(
            &TRANSFER,
            format!(
                "one Transfer of {} from {} to {} by {}{}",
                expected.amount,
                expected.payer,
                expected.pay_to,
                expected.asset,
                if transfers.len() > 1 {
                    format!(
                        " among {} Transfer events of the asset ({listed})",
                        transfers.len()
                    )
                } else {
                    String::new()
                }
            ),
            ev,
        ),
        0 => Finding::blocked(
            &TRANSFER,
            Attribution::Unknown,
            format!(
                "no Transfer of {} from {} to {} by {}; Transfer events of the asset: {}",
                expected.amount,
                expected.payer,
                expected.pay_to,
                expected.asset,
                if listed.is_empty() { "none" } else { &listed }
            ),
            ev,
        ),
        n => Finding::cannot_assess(
            &TRANSFER,
            format!(
                "{n} identical transfers of {} from {} to {} in one transaction (a batch?): which one is this payment is not decidable from the logs",
                expected.amount, expected.payer, expected.pay_to
            ),
            ev,
        ),
    }
}

/// `AuthorizationUsed(payer, nonce)` from the asset, in the same transaction.
fn binding_finding(on_chain: &TransactionReceipt, expected: &Expected, ev: &[usize]) -> Finding {
    let Some(nonce) = expected.nonce else {
        return Finding::skip(&BINDING, "the authorization's nonce was not given");
    };
    let used = on_chain.authorizations_used(expected.asset);
    if used.contains(&(expected.payer, nonce)) {
        return Finding::pass(
            &BINDING,
            format!(
                "AuthorizationUsed({}, {nonce}) emitted by {} in this transaction",
                expected.payer, expected.asset
            ),
            ev,
        );
    }
    if used.is_empty() {
        return Finding::cannot_assess(
            &BINDING,
            format!(
                "{} emitted no AuthorizationUsed event in this transaction: the binding to the tool's authorization is not established",
                expected.asset
            ),
            ev,
        );
    }
    Finding::blocked(
        &BINDING,
        Attribution::Unknown,
        format!(
            "AuthorizationUsed emitted for {}, not for ({}, {nonce}): the transaction consumed other authorizations than the tool's",
            used.iter()
                .map(|(a, n)| format!("({a}, {n})"))
                .collect::<Vec<_>>()
                .join(", "),
            expected.payer
        ),
        ev,
    )
}
