//! `pay`: one real payment on a test network, through the server's own facilitator, then the negatives a real
//! facilitator refuses.
//!
//! Money is meant to move once: the honest payment. Every other request either replays that payment or carries an
//! authorization a conformant facilitator refuses (expired, not yet valid, and with `--spendable-negatives` wrong
//! amount and wrong recipient), so the expected cost of a run is the price of one call; a facilitator that settles
//! what it should refuse is reported as such, and the spendable negatives are opt-in because a dishonest server
//! could submit them. The receipt of the honest payment is then read on chain by the [`super::ledger`] checks,
//! unless the operator turns that off.

use alloy_primitives::{Address, U256};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use x402_checker_evm::{AuthorizationParams, Eip3009Offer, Payer, Window, random_nonce};
use x402_checker_types::{Caip2, PaymentRequired, PaymentRequirements, error_codes, headers};

use super::ledger::{self, Expected, LedgerOptions};
use super::{echoed_extensions, fresh_payment_id, member};
use crate::check::{Attribution, Check, Finding, Level, Source, SuiteResult, judge};
use crate::http::Exchange;
use crate::target::Context;

const fn check(
    id: &'static str,
    title: &'static str,
    level: Level,
    source: Source,
    clause: &'static str,
) -> Check {
    Check {
        id,
        title,
        level,
        source,
        clause,
        ambiguity: None,
    }
}

const fn with_note(check: Check, ambiguity: &'static str) -> Check {
    Check {
        ambiguity: Some(ambiguity),
        ..check
    }
}

const PAY_OFFER: Check = check(
    "PAY-OFFER",
    "the offer the tool pays",
    Level::Optional,
    Source::Prose,
    "x402-specification-v2.md 6.1: clients prefer the authorization flow; schemes/exact/scheme_exact_evm.md: eip3009 is the default method",
);
const HTTP_10: Check = check(
    "HTTP-013",
    "a valid payment is answered with status 200 and the resource",
    Level::Required,
    Source::FieldTable,
    "transports-v2/http.md, Error Handling: \"Success | 200 | Payment verified and settled successfully\"",
);
const HTTP_05: Check = check(
    "HTTP-005",
    "the paid response carries a PAYMENT-RESPONSE header",
    Level::Required,
    Source::Prose,
    "transports-v2/http.md, Settlement Response Delivery: \"Servers communicate payment settlement results using the PAYMENT-RESPONSE header\"",
);
const CORE_5_3_02: Check = check(
    "CORE-031",
    "the receipt has success (boolean), transaction (string) and network (string)",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.3.2: success Required boolean, transaction Required string, network Required string",
);
const CORE_5_3_03: Check = check(
    "CORE-034",
    "a successful receipt has no errorReason and a non-empty transaction",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.3.2: errorReason \"omitted if successful\"; transaction \"empty string if no transaction was broadcast\"",
);
const RECEIPT_SUCCESS: Check = check(
    "HTTP-013r",
    "a 200 carries a receipt with success true",
    Level::Required,
    Source::FieldTable,
    "transports-v2/http.md, Error Handling: 200 means \"Payment verified and settled successfully\"; Payment Failed is 402",
);
const RECEIPT_NETWORK: Check = with_note(
    check(
        "CORE-033",
        "the receipt's network is the network of the accepted offer",
        Level::Required,
        Source::FieldTable,
        "x402-specification-v2.md 5.3.2: network, \"Blockchain network identifier in CAIP-2 format\"",
    ),
    "the spec does not state the equality in so many words; a receipt naming another network than the one paid on would be meaningless",
);
const RECEIPT_PAYER: Check = check(
    "CORE-035",
    "the receipt's payer, when present, is the paying wallet",
    Level::Optional,
    Source::FieldTable,
    "x402-specification-v2.md 5.3.2: payer Optional, \"Address of the payer's wallet\"",
);
const REPLAY: Check = with_note(
    check(
        "CORE-072",
        "replaying the same PAYMENT-SIGNATURE does not settle a second time",
        Level::Required,
        Source::Prose,
        "x402-specification-v2.md 10.1: \"unique 32-byte nonce to prevent replay attacks\"; schemes/exact/scheme_exact.md: \"A consumed primitive MUST produce a settlement failure, never a success\"",
    ),
    "the spec fixes no status for a replay; delivering the cached resource again is allowed. The tool fails only on a second success receipt with another transaction",
);
const EXPIRED: Check = check(
    "CORE-073",
    "an expired authorization (validBefore in the past) is refused",
    Level::Required,
    Source::Prose,
    "x402-specification-v2.md 10.1: \"Authorizations have explicit valid time windows\"; 9: invalid_exact_evm_payload_authorization_valid_before",
);
const NOT_YET_VALID: Check = check(
    "CORE-073a",
    "an authorization that is not yet valid (validAfter in the future) is refused",
    Level::Required,
    Source::Prose,
    "x402-specification-v2.md 10.1: time windows; 9: invalid_exact_evm_payload_authorization_valid_after",
);
const WRONG_VALUE: Check = check(
    "EXACT-017v",
    "an authorization whose value differs from amount is refused",
    Level::Required,
    Source::ExplicitMust,
    "schemes/exact/scheme_exact.md: \"exactly one identifiable transfer of amount\"; scheme_exact_evm.md phase 2: \"Verify the authorization parameters (Amount ...) meet the PaymentRequirements\"",
);
const WRONG_RECIPIENT: Check = check(
    "EXACT-017r",
    "an authorization whose recipient differs from payTo is refused",
    Level::Required,
    Source::ExplicitMust,
    "schemes/exact/scheme_exact.md: \"transfer ... to payTo\"; x402-specification-v2.md 9: invalid_exact_evm_payload_recipient_mismatch",
);
const REASONS: Check = check(
    "CORE-070p",
    "error reasons given on refused payments",
    Level::Optional,
    Source::Prose,
    "x402-specification-v2.md 9: standard codes \"may be returned by facilitators or resource servers\"",
);

/// EVM chain ids the tool pays on without `--allow-mainnet`.
const TESTNETS: [u64; 8] = [84532, 11_155_111, 43113, 80002, 421_614, 11_155_420, 97, 59141];

/// What the operator gives the suite.
#[derive(Debug, Clone)]
pub struct PayOptions {
    /// The paying key.
    pub payer: Payer,
    /// Pay on networks the tool does not know as testnets.
    pub allow_mainnet: bool,
    /// Validity of the honest authorization, in seconds.
    pub validity: u64,
    /// Refuse offers above this many atomic units.
    pub max_amount: Option<U256>,
    /// Also send the wrong-value and wrong-recipient authorizations, which are spendable by whoever sees them.
    pub spendable_negatives: bool,
    /// How to read the chain after the honest payment; `None` leaves the transfer unestablished.
    pub ledger: Option<LedgerOptions>,
}

/// Runs the pay suite.
pub async fn run(ctx: &mut Context, options: &PayOptions) -> SuiteResult {
    let mut findings = Vec::new();
    let Some((terms_index, terms)) = terms(ctx, &mut findings).await else {
        return SuiteResult::new("pay", findings);
    };
    let Some((position, offer, evm)) = choose_offer(&terms, options, &mut findings, terms_index) else {
        return SuiteResult::new("pay", findings);
    };
    findings.push(Finding::info(
        &PAY_OFFER,
        format!(
            "accepts[{position}]: {} atomic units of {} on {} to {}, paid by {}",
            evm.amount,
            evm.asset,
            offer.network,
            evm.pay_to,
            options.payer.address()
        ),
        &[terms_index],
    ));
    let extensions = terms.extensions.clone();
    let now = now_seconds();

    // the honest payment, with a nonce the tool knows so that the chain can be asked whether it was consumed
    let nonce = random_nonce();
    let honest = AuthorizationParams {
        nonce: Some(nonce),
        ..AuthorizationParams::honest(&evm, now, options.validity)
    };
    let header = payment_header(&options.payer, &evm, offer, &honest, extensions.as_ref());
    let Ok(paid) = send(ctx, "honest payment", &header, &mut findings).await else {
        return SuiteResult::new("pay", findings);
    };
    let exchange = ctx.client.exchange(paid).clone();
    findings.extend(paid_response_checks(
        &exchange,
        offer,
        options.payer.address(),
        paid,
    ));
    let verified = match exchange.payment_response() {
        Some(receipt) if receipt.success && !receipt.transaction.is_empty() => {
            ledger::verify(
                &Expected::of_offer(&evm, options.payer.address(), Some(nonce)),
                &receipt.transaction,
                Some(&receipt.network),
                options.ledger.as_ref(),
                &[paid],
            )
            .await
        }
        _ => ledger::skipped(
            "no success receipt with a transaction on the paid response; a known transaction can be read later with the ledger command",
        ),
    };
    findings.extend(verified.findings);
    let snapshots: Vec<_> = verified.snapshot.into_iter().collect();

    // the same header again
    match ctx
        .client
        .send(
            "replay of the honest payment",
            ctx.resource_request(&[(headers::PAYMENT_SIGNATURE, &header)]),
        )
        .await
    {
        Ok(index) => findings.push(replay_check(
            &exchange,
            ctx.client.exchange(index),
            &[paid, index],
        )),
        Err(error) => findings.push(Finding::blocked(
            &REPLAY,
            Attribution::Dependency,
            format!("transport error: {error}"),
            &[paid],
        )),
    }

    findings.extend(refused_authorizations(ctx, options, offer, &evm, &honest, extensions.as_ref()).await);

    SuiteResult {
        ledger: snapshots,
        ..SuiteResult::new("pay", findings)
    }
}

/// Authorizations the facilitator must refuse. Each one is signed over its altered parameters, so the signature
/// itself is valid; the refusal is observed with its code, and the code names the cause when it is a standard one.
/// From outside, other causes (balance, changed terms, an unavailable facilitator) cannot be ruled out: the
/// `scenarios` suite isolates causes with the local facilitator. The expired one can never be spent, the "not yet
/// valid" one opens in 2100. The wrong-value and wrong-recipient ones are spendable by anyone who sees them (a
/// dishonest server could submit them on chain), so they are sent only with `spendable_negatives`; the
/// `scenarios` suite exercises them against the local facilitator at no risk.
async fn refused_authorizations(
    ctx: &mut Context,
    options: &PayOptions,
    offer: &PaymentRequirements,
    evm: &Eip3009Offer,
    honest: &AuthorizationParams,
    extensions: Option<&x402_checker_types::Extensions>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut reasons = Vec::new();
    let cases = refused_cases(options.spendable_negatives, evm, honest);
    if !options.spendable_negatives {
        let why = "not sent: this authorization would be spendable by whoever sees it; pass --spendable-negatives with a test wallet, or run the scenarios suite";
        findings.push(Finding::skip(&WRONG_VALUE, why));
        findings.push(Finding::skip(&WRONG_RECIPIENT, why));
    }
    for (check, label, params) in &cases {
        let header = payment_header(&options.payer, evm, offer, params, extensions);
        match ctx
            .client
            .send(
                *label,
                ctx.resource_request(&[(headers::PAYMENT_SIGNATURE, &header)]),
            )
            .await
        {
            Ok(index) => {
                let exchange = ctx.client.exchange(index);
                if let Some(reason) = refusal_reason(exchange) {
                    reasons.push(format!(
                        "{label}: {reason}{}",
                        if error_codes::is_standard(&reason) {
                            " (standard)"
                        } else {
                            ""
                        }
                    ));
                }
                findings.push(refused_check(check, exchange, index));
            }
            Err(error) => findings.push(Finding::blocked(
                check,
                Attribution::Dependency,
                format!("transport error: {error}"),
                &[],
            )),
        }
    }
    findings.push(Finding::info(
        &REASONS,
        if reasons.is_empty() {
            "no machine-readable reason found".to_owned()
        } else {
            reasons.join("; ")
        },
        &[],
    ));
    findings
}

/// The altered authorizations, each with its own nonce: with the honest one's, the server would rightly see a
/// replay.
fn refused_cases(
    spendable: bool,
    evm: &Eip3009Offer,
    honest: &AuthorizationParams,
) -> Vec<(&'static Check, &'static str, AuthorizationParams)> {
    const YEAR_2100: u64 = 4_102_444_800;
    let now = now_seconds();
    let fresh = AuthorizationParams {
        nonce: None,
        ..honest.clone()
    };
    let mut cases = vec![
        (
            &EXPIRED,
            "expired authorization",
            AuthorizationParams {
                window: Window {
                    valid_after: now - 7200,
                    valid_before: now - 3600,
                },
                ..fresh.clone()
            },
        ),
        (
            &NOT_YET_VALID,
            "not yet valid authorization",
            AuthorizationParams {
                window: Window {
                    valid_after: YEAR_2100,
                    valid_before: YEAR_2100 + 3600,
                },
                ..fresh.clone()
            },
        ),
    ];
    if spendable {
        cases.push((
            &WRONG_VALUE,
            "value differs from amount",
            AuthorizationParams {
                value: if evm.amount.is_zero() {
                    U256::from(1)
                } else {
                    evm.amount - U256::from(1)
                },
                ..fresh.clone()
            },
        ));
        cases.push((
            &WRONG_RECIPIENT,
            "recipient differs from payTo",
            AuthorizationParams {
                to: Address::random(),
                ..fresh
            },
        ));
    }
    cases
}

/// The terms, from a fresh unpaid request.
async fn terms(ctx: &mut Context, findings: &mut Vec<Finding>) -> Option<(usize, PaymentRequired)> {
    let index = match ctx
        .client
        .send("unpaid request for the terms", ctx.resource_request(&[]))
        .await
    {
        Ok(index) => index,
        Err(error) => {
            findings.push(Finding::cannot_assess(
                &PAY_OFFER,
                format!("the target could not be reached: {error}"),
                &[],
            ));
            return None;
        }
    };
    let exchange = ctx.client.exchange(index);
    match exchange.payment_required() {
        Some(terms) if exchange.status == 402 => Some((index, terms)),
        _ => {
            findings.push(Finding::cannot_assess(
                &PAY_OFFER,
                format!(
                    "no usable 402 with PAYMENT-REQUIRED (status {}); run `probe` for the details",
                    exchange.status
                ),
                &[index],
            ));
            None
        }
    }
}

/// The first offer the tool can pay: exact, eip3009, on an EVM testnet (or any EVM network with `--allow-mainnet`),
/// within the amount cap.
fn choose_offer<'a>(
    terms: &'a PaymentRequired,
    options: &PayOptions,
    findings: &mut Vec<Finding>,
    evidence: usize,
) -> Option<(usize, &'a PaymentRequirements, Eip3009Offer)> {
    let mut refusals = Vec::new();
    for (i, offer) in terms.accepts.iter().enumerate() {
        let evm = match Eip3009Offer::from_requirements(offer) {
            Ok(evm) => evm,
            Err(error) => {
                refusals.push(format!("accepts[{i}]: {error}"));
                continue;
            }
        };
        if !options.allow_mainnet && !TESTNETS.contains(&evm.chain_id) {
            refusals.push(format!(
                "accepts[{i}]: eip155:{} is not a known testnet (pass --allow-mainnet to pay there anyway)",
                evm.chain_id
            ));
            continue;
        }
        if let Some(cap) = options.max_amount
            && evm.amount > cap
        {
            refusals.push(format!(
                "accepts[{i}]: {} atomic units exceed --max-amount {cap}",
                evm.amount
            ));
            continue;
        }
        return Some((i, offer, evm));
    }
    let why = if refusals.is_empty() {
        "no offer at all".to_owned()
    } else {
        refusals.join("; ")
    };
    if refusals.iter().any(|r| r.contains("--max-amount")) {
        findings.push(Finding::skip(
            &PAY_OFFER,
            format!("no offer within the cap: {why}"),
        ));
    } else {
        findings.push(Finding::cannot_assess(
            &PAY_OFFER,
            format!("no offer this tool can pay: {why}"),
            &[evidence],
        ));
    }
    None
}

/// Sends a payment header, or records why it could not be sent.
async fn send(
    ctx: &mut Context,
    label: &str,
    header: &str,
    findings: &mut Vec<Finding>,
) -> Result<usize, ()> {
    match ctx
        .client
        .send(
            label,
            ctx.resource_request(&[(headers::PAYMENT_SIGNATURE, header)]),
        )
        .await
    {
        Ok(index) => Ok(index),
        Err(error) => {
            findings.push(Finding::blocked(
                &HTTP_10,
                Attribution::Dependency,
                format!("transport error: {error}"),
                &[],
            ));
            Err(())
        }
    }
}

/// The `PAYMENT-SIGNATURE` value for `params`, echoing the server's extensions as the core spec asks clients to.
fn payment_header(
    payer: &Payer,
    evm: &Eip3009Offer,
    offer: &PaymentRequirements,
    params: &AuthorizationParams,
    extensions: Option<&x402_checker_types::Extensions>,
) -> String {
    let payload = payer.sign(evm, params);
    let mut body = json!({ "x402Version": 2, "accepted": offer, "payload": payload.to_value() });
    if let Some(echoed) = echoed_extensions(extensions, Some(&fresh_payment_id())) {
        body["extensions"] = Value::Object(echoed);
    }
    STANDARD.encode(body.to_string())
}

fn paid_response_checks(
    exchange: &Exchange,
    offer: &PaymentRequirements,
    payer: Address,
    index: usize,
) -> Vec<Finding> {
    let ev = [index];
    let mut findings = Vec::new();
    let receipt = exchange.payment_response();
    let ok = (200..300).contains(&exchange.status);
    if ok {
        findings.push(Finding::pass(
            &HTTP_10,
            format!(
                "status {}, {} bytes of {}",
                exchange.status,
                exchange.body.text.len(),
                exchange.header("content-type").unwrap_or("unknown type")
            ),
            &ev,
        ));
    } else {
        let reason = refusal_reason(exchange);
        let attribution = match reason.as_deref() {
            Some(error_codes::INSUFFICIENT_FUNDS) => Attribution::Dependency,
            Some(r) if r.ends_with("_signature") => Attribution::Harness,
            _ => Attribution::Target,
        };
        let detail = format!(
            "status {}{}",
            exchange.status,
            reason.map(|r| format!(", reason {r}")).unwrap_or_default()
        );
        findings.push(match attribution {
            Attribution::Target => Finding::fail(&HTTP_10, detail, &ev),
            other => Finding::blocked(
                &HTTP_10,
                other,
                format!("{detail}: the refusal comes from the wallet or the tool, not from the server"),
                &ev,
            ),
        });
    }

    let Some(raw) = &exchange.payment_response else {
        findings.push(if ok {
            Finding::fail(&HTTP_05, "no PAYMENT-RESPONSE header on the paid response", &ev)
        } else {
            Finding::skip(&HTTP_05, "no paid response to inspect")
        });
        return findings;
    };
    findings.push(Finding::pass(&HTTP_05, "header present", &ev));
    findings.extend(receipt_checks(raw, receipt, ok, offer, payer, &ev));
    findings
}

/// The receipt, field by field.
fn receipt_checks(
    raw: &crate::http::DecodedHeader,
    receipt: Option<x402_checker_types::SettleResponse>,
    ok: bool,
    offer: &PaymentRequirements,
    payer: Address,
    ev: &[usize],
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(json) = &raw.json else {
        findings.push(Finding::fail(
            &CORE_5_3_02,
            format!(
                "PAYMENT-RESPONSE does not decode to a SettleResponse: {}",
                raw.error.clone().unwrap_or_default()
            ),
            ev,
        ));
        return findings;
    };
    let field_ok = member(json, "success").is_some_and(Value::is_boolean)
        && member(json, "transaction").is_some_and(Value::is_string)
        && member(json, "network").is_some_and(Value::is_string);
    findings.push(judge(&CORE_5_3_02, field_ok, format!("receipt: {json}"), ev));
    let Some(receipt) = receipt else {
        return findings;
    };
    if ok {
        findings.push(judge(
            &RECEIPT_SUCCESS,
            receipt.success,
            format!(
                "success = {}{}",
                receipt.success,
                receipt
                    .error_reason
                    .as_ref()
                    .map(|r| format!(", errorReason {r}"))
                    .unwrap_or_default()
            ),
            ev,
        ));
    }
    if receipt.success {
        findings.push(judge(
            &CORE_5_3_03,
            receipt.error_reason.is_none() && !receipt.transaction.is_empty(),
            format!(
                "transaction {:?}, errorReason {:?}",
                receipt.transaction, receipt.error_reason
            ),
            ev,
        ));
        let same_network = receipt.network.parse::<Caip2>().ok() == offer.network.parse::<Caip2>().ok();
        findings.push(judge(
            &RECEIPT_NETWORK,
            same_network,
            format!("receipt network {}, paid on {}", receipt.network, offer.network),
            ev,
        ));
        if let Some(p) = &receipt.payer {
            findings.push(judge(
                &RECEIPT_PAYER,
                p.parse::<Address>().ok() == Some(payer),
                format!("payer {p}"),
                ev,
            ));
        }
    }
    findings
}

/// Replay: no second success receipt with another transaction.
fn replay_check(first: &Exchange, replay: &Exchange, ev: &[usize]) -> Finding {
    let original = first
        .payment_response()
        .filter(|r| r.success)
        .map(|r| r.transaction);
    let again = replay.payment_response();
    match (&original, again) {
        (Some(tx), Some(r)) if r.success && &r.transaction != tx => Finding::fail(
            &REPLAY,
            format!(
                "status {} with a second success receipt, transaction {} after {}",
                replay.status, r.transaction, tx
            ),
            ev,
        ),
        (Some(_), Some(r)) if r.success => Finding::pass(
            &REPLAY,
            format!(
                "status {}, the original receipt came back (same transaction)",
                replay.status
            ),
            ev,
        ),
        (Some(_), Some(r)) => Finding::pass(
            &REPLAY,
            format!(
                "status {}, refused: {}",
                replay.status,
                r.error_reason.unwrap_or_default()
            ),
            ev,
        ),
        (Some(_), None) if replay.is_success() => Finding::cannot_assess(
            &REPLAY,
            format!(
                "status {} without a receipt: the resource was served again and nothing says whether a settlement happened; not observable from outside",
                replay.status
            ),
            ev,
        ),
        (Some(_), None) => Finding::pass(
            &REPLAY,
            format!(
                "status {}{}",
                replay.status,
                refusal_reason(replay)
                    .map(|r| format!(", reason {r}"))
                    .unwrap_or_default()
            ),
            ev,
        ),
        (None, _) => Finding::skip(&REPLAY, "the honest payment did not settle, nothing to replay"),
    }
}

/// A refused authorization: never 2xx; a 2xx with a success receipt means the facilitator accepted it.
fn refused_check(check: &Check, exchange: &Exchange, index: usize) -> Finding {
    let served = (200..300).contains(&exchange.status);
    let detail = format!(
        "status {}{}; the signature covers the altered parameters",
        exchange.status,
        refusal_reason(exchange)
            .map(|r| format!(", reason {r}"))
            .unwrap_or_default()
    );
    if served && exchange.payment_response().is_some_and(|r| r.success) {
        Finding::blocked(
            check,
            Attribution::Dependency,
            format!("{detail}: the facilitator settled an authorization it should have refused"),
            &[index],
        )
    } else {
        judge(check, !served, detail, &[index])
    }
}

fn refusal_reason(exchange: &Exchange) -> Option<String> {
    if let Some(r) = exchange.payment_response()
        && let Some(reason) = r.error_reason
    {
        return Some(reason);
    }
    if let Some(pr) = exchange.payment_required()
        && let Some(error) = pr.error
    {
        return Some(error);
    }
    exchange
        .body_json()
        .and_then(|b| member(&b, "error").and_then(Value::as_str).map(str::to_owned))
}

fn now_seconds() -> u64 {
    jiff::Timestamp::now().as_second().max(0).unsigned_abs()
}
