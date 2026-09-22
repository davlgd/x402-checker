//! The ledger checks against a JSON-RPC fixture: a node that answers `eth_chainId` and serves the receipts it is
//! given. Each case is one receipt shape the checks must read correctly.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use alloy_primitives::{Address, B256, U256, address};
use alloy_sol_types::SolEvent;
use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{Value, json};
use url::Url;
use x402_checker::check::{Attribution, Finding, Verdict};
use x402_checker::suites::ledger::{Expected, LedgerOptions, verify};
use x402_checker_ledger::{AuthorizationUsed, Transfer};

const ASSET: Address = address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e");
const PAYER: Address = address!("0x8621a1F258194f55fa11Eb5591DDaB439a18a677");
const PAY_TO: Address = address!("0x209693Bc6afc0C5328bA36FaF03C514EF312287C");
const TX: &str = "0x7046404f9aa49a9b855db795aa3eaa0738a43c7e8848199b3491d36b4b1d6f9f";

struct Node {
    chain_id: u64,
    receipts: HashMap<String, Value>,
    delay: Duration,
}

async fn rpc(State(node): State<Arc<Node>>, Json(request): Json<Value>) -> Json<Value> {
    tokio::time::sleep(node.delay).await;
    let id = request["id"].clone();
    let result = match request["method"].as_str() {
        Some("eth_chainId") => json!(format!("{:#x}", node.chain_id)),
        Some("eth_getTransactionReceipt") => {
            let hash = request["params"][0]
                .as_str()
                .unwrap_or_default()
                .to_ascii_lowercase();
            node.receipts.get(&hash).cloned().unwrap_or(Value::Null)
        }
        _ => {
            return Json(
                json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": "unknown"}}),
            );
        }
    };
    Json(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

async fn spawn(chain_id: u64, receipts: Vec<(&str, Value)>) -> Url {
    spawn_with_delay(chain_id, receipts, Duration::ZERO).await
}

async fn spawn_with_delay(chain_id: u64, receipts: Vec<(&str, Value)>, delay: Duration) -> Url {
    let node = Arc::new(Node {
        chain_id,
        receipts: receipts
            .into_iter()
            .map(|(h, r)| (h.to_ascii_lowercase(), r))
            .collect(),
        delay,
    });
    let app = Router::new().route("/", post(rpc)).with_state(node);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}/").parse().unwrap()
}

fn log<E: SolEvent>(address: Address, event: &E) -> Value {
    let data = event.encode_log_data();
    json!({
        "address": address,
        "topics": data.topics(),
        "data": data.data,
    })
}

fn receipt(status: u8, logs: &[Value]) -> Value {
    sealed(
        "0x65641a0e62f64aca8644939d53c24e61771e156bb1be58c5283eab53bb11448e",
        status,
        logs,
    )
}

fn sealed(block_hash: &str, status: u8, logs: &[Value]) -> Value {
    json!({
        "transactionHash": TX,
        "status": format!("{status:#x}"),
        "blockNumber": "0x2cf198f",
        "blockHash": block_hash,
        "from": "0xd407e409E34E0b9afb99EcCeb609bDbcD5e7f1bf",
        "to": ASSET,
        "logs": logs,
    })
}

fn transfer(from: Address, to: Address, value: u64) -> Value {
    log(
        ASSET,
        &Transfer {
            from,
            to,
            value: U256::from(value),
        },
    )
}

fn used(nonce: B256) -> Value {
    log(
        ASSET,
        &AuthorizationUsed {
            authorizer: PAYER,
            nonce,
        },
    )
}

fn expected(nonce: Option<B256>) -> Expected {
    Expected {
        chain_id: 84532,
        asset: ASSET,
        pay_to: PAY_TO,
        amount: U256::from(10_000),
        payer: PAYER,
        nonce,
    }
}

fn options(url: Url, wait: u64) -> LedgerOptions {
    LedgerOptions {
        rpc_url: Some(url),
        wait: Duration::from_secs(wait),
    }
}

fn by_id<'a>(findings: &'a [Finding], id: &str) -> &'a Finding {
    findings
        .iter()
        .find(|f| f.check.id == id)
        .unwrap_or_else(|| panic!("no finding {id} in {findings:#?}"))
}

#[tokio::test]
async fn a_settled_payment_passes_the_three_checks() {
    let nonce = B256::repeat_byte(0x74);
    let url = spawn(
        84532,
        vec![(TX, receipt(1, &[transfer(PAYER, PAY_TO, 10_000), used(nonce)]))],
    )
    .await;
    let findings = verify(
        &expected(Some(nonce)),
        TX,
        Some("eip155:84532"),
        Some(&options(url, 5)),
        &[3],
    )
    .await
    .findings;
    for id in ["LEDGER-TX", "EXACT-017", "EVM-006"] {
        let f = by_id(&findings, id);
        assert_eq!(f.verdict, Verdict::Pass, "{id}: {}", f.detail);
        assert_eq!(f.evidence, vec![3]);
    }
    assert!(by_id(&findings, "LEDGER-TX").detail.contains("block 47126927"));
    assert!(by_id(&findings, "EVM-006").detail.contains("in this transaction"));
}

#[tokio::test]
async fn incidental_transfers_do_not_disqualify_the_payment() {
    let fee_collector = Address::repeat_byte(0xfe);
    let url = spawn(
        84532,
        vec![(
            TX,
            receipt(
                1,
                &[transfer(PAYER, PAY_TO, 10_000), transfer(PAYER, fee_collector, 3)],
            ),
        )],
    )
    .await;
    let findings = verify(&expected(None), TX, None, Some(&options(url, 5)), &[])
        .await
        .findings;
    let f = by_id(&findings, "EXACT-017");
    assert_eq!(f.verdict, Verdict::Pass, "{}", f.detail);
    assert!(f.detail.contains("among 2 Transfer events"), "{}", f.detail);
    assert_eq!(by_id(&findings, "EVM-006").verdict, Verdict::Skip);
}

#[tokio::test]
async fn a_batch_of_identical_transfers_is_not_decidable() {
    let url = spawn(
        84532,
        vec![(
            TX,
            receipt(
                1,
                &[transfer(PAYER, PAY_TO, 10_000), transfer(PAYER, PAY_TO, 10_000)],
            ),
        )],
    )
    .await;
    let findings = verify(&expected(None), TX, None, Some(&options(url, 5)), &[])
        .await
        .findings;
    let f = by_id(&findings, "EXACT-017");
    assert_eq!(f.verdict, Verdict::CannotAssess, "{}", f.detail);
    assert!(f.detail.contains("2 identical transfers"));
}

#[tokio::test]
async fn a_transfer_of_another_amount_contradicts_the_receipt_without_blaming_the_server() {
    let nonce = B256::repeat_byte(1);
    let other_nonce = B256::repeat_byte(2);
    let url = spawn(
        84532,
        vec![(
            TX,
            receipt(1, &[transfer(PAYER, PAY_TO, 9_999), used(other_nonce)]),
        )],
    )
    .await;
    let findings = verify(&expected(Some(nonce)), TX, None, Some(&options(url, 5)), &[])
        .await
        .findings;
    for id in ["EXACT-017", "EVM-006"] {
        let f = by_id(&findings, id);
        assert_eq!(f.verdict, Verdict::Fail, "{id}: {}", f.detail);
        assert_eq!(f.attribution, Some(Attribution::Unknown));
        assert!(!f.counts_against_target());
    }
    assert!(by_id(&findings, "EXACT-017").detail.contains("9999"));
}

#[tokio::test]
async fn an_asset_without_the_eip3009_event_leaves_the_binding_open() {
    let url = spawn(84532, vec![(TX, receipt(1, &[transfer(PAYER, PAY_TO, 10_000)]))]).await;
    let findings = verify(
        &expected(Some(B256::repeat_byte(1))),
        TX,
        None,
        Some(&options(url, 5)),
        &[],
    )
    .await
    .findings;
    assert_eq!(by_id(&findings, "EXACT-017").verdict, Verdict::Pass);
    let f = by_id(&findings, "EVM-006");
    assert_eq!(f.verdict, Verdict::CannotAssess, "{}", f.detail);
}

#[tokio::test]
async fn a_reverted_transaction_contradicts_the_success_receipt() {
    let url = spawn(84532, vec![(TX, receipt(0, &[]))]).await;
    let findings = verify(&expected(None), TX, None, Some(&options(url, 5)), &[])
        .await
        .findings;
    let f = by_id(&findings, "LEDGER-TX");
    assert_eq!(f.verdict, Verdict::Fail);
    assert_eq!(f.attribution, Some(Attribution::Unknown));
    assert!(f.detail.contains("reverted"));
    assert_eq!(by_id(&findings, "EXACT-017").verdict, Verdict::CannotAssess);
}

#[tokio::test]
async fn an_unknown_transaction_is_reported_after_the_wait() {
    let url = spawn(84532, vec![]).await;
    let started = std::time::Instant::now();
    let findings = verify(&expected(None), TX, None, Some(&options(url, 1)), &[])
        .await
        .findings;
    assert!(started.elapsed() < Duration::from_secs(4), "the wait is bounded");
    let f = by_id(&findings, "LEDGER-TX");
    assert_eq!(f.verdict, Verdict::Fail);
    assert_eq!(f.attribution, Some(Attribution::Unknown));
    assert!(f.detail.contains("no inclusion receipt"), "{}", f.detail);
    assert_eq!(by_id(&findings, "EXACT-017").verdict, Verdict::CannotAssess);
}

#[tokio::test]
async fn a_node_of_another_chain_is_a_tool_misconfiguration() {
    let url = spawn(1, vec![]).await;
    let findings = verify(&expected(None), TX, None, Some(&options(url, 1)), &[])
        .await
        .findings;
    for id in ["LEDGER-TX", "EXACT-017", "EVM-006"] {
        let f = by_id(&findings, id);
        assert_eq!(f.attribution, Some(Attribution::Harness), "{id}: {}", f.detail);
        assert!(f.detail.contains("eip155:1"));
    }
}

#[tokio::test]
async fn an_unreachable_node_is_a_dependency() {
    let url: Url = "http://127.0.0.1:9/".parse().unwrap();
    let findings = verify(&expected(None), TX, None, Some(&options(url, 1)), &[])
        .await
        .findings;
    assert_eq!(
        by_id(&findings, "LEDGER-TX").attribution,
        Some(Attribution::Dependency)
    );
}

#[tokio::test]
async fn a_receipt_naming_another_network_is_not_looked_up() {
    // no node at all: the inconsistency is caught before any call
    let url: Url = "http://127.0.0.1:9/".parse().unwrap();
    let findings = verify(&expected(None), TX, Some("eip155:1"), Some(&options(url, 1)), &[])
        .await
        .findings;
    let f = by_id(&findings, "LEDGER-TX");
    assert_eq!(f.attribution, Some(Attribution::Unknown));
    assert!(f.detail.contains("eip155:1"));
    assert!(findings.iter().all(|f| f.check.id != "LEDGER-RPC"));
}

#[tokio::test]
async fn a_malformed_hash_and_a_disabled_ledger_are_explicit() {
    let url: Url = "http://127.0.0.1:9/".parse().unwrap();
    let findings = verify(&expected(None), "not-a-hash", None, Some(&options(url, 1)), &[])
        .await
        .findings;
    assert_eq!(
        by_id(&findings, "LEDGER-TX").attribution,
        Some(Attribution::Unknown)
    );
    let findings = verify(&expected(None), TX, None, None, &[]).await.findings;
    assert!(findings.iter().all(|f| f.verdict == Verdict::Skip));
    assert!(by_id(&findings, "EXACT-017").detail.contains("--no-ledger"));
}

#[tokio::test]
async fn a_preconfirmed_receipt_is_not_an_inclusion() {
    let zero = "0x0000000000000000000000000000000000000000000000000000000000000000";
    let url = spawn(
        84532,
        vec![(TX, sealed(zero, 1, &[transfer(PAYER, PAY_TO, 10_000)]))],
    )
    .await;
    let verified = verify(&expected(None), TX, None, Some(&options(url, 1)), &[]).await;
    for id in ["LEDGER-TX", "EXACT-017", "EVM-006"] {
        let f = by_id(&verified.findings, id);
        assert_eq!(f.verdict, Verdict::CannotAssess, "{id}: {}", f.detail);
    }
    assert!(
        by_id(&verified.findings, "LEDGER-TX")
            .detail
            .contains("preconfirmation")
    );
    assert_eq!(verified.snapshot.unwrap().state, "preconfirmed");
}

#[tokio::test]
async fn a_node_that_never_answers_in_time_is_a_dependency_not_an_absence() {
    let url = spawn_with_delay(84532, vec![], Duration::from_secs(3)).await;
    let verified = verify(&expected(None), TX, None, Some(&options(url, 1)), &[]).await;
    let f = by_id(&verified.findings, "LEDGER-TX");
    assert_eq!(f.attribution, Some(Attribution::Dependency), "{}", f.detail);
    assert!(f.detail.contains("deadline"), "{}", f.detail);
    assert!(verified.snapshot.is_none());
}

#[tokio::test]
async fn a_status_outside_zero_and_one_is_a_shape_error() {
    let url = spawn(84532, vec![(TX, receipt(2, &[]))]).await;
    let verified = verify(&expected(None), TX, None, Some(&options(url, 1)), &[]).await;
    let f = by_id(&verified.findings, "LEDGER-TX");
    assert_eq!(f.attribution, Some(Attribution::Dependency), "{}", f.detail);
    assert!(f.detail.contains("neither 0 nor 1"), "{}", f.detail);
}

#[tokio::test]
async fn the_snapshot_keeps_the_logs_the_findings_were_judged_on() {
    let nonce = B256::repeat_byte(0x74);
    let url = spawn(
        84532,
        vec![(TX, receipt(1, &[transfer(PAYER, PAY_TO, 10_000), used(nonce)]))],
    )
    .await;
    let verified = verify(&expected(Some(nonce)), TX, None, Some(&options(url, 5)), &[]).await;
    let snapshot = verified.snapshot.expect("a receipt was read");
    assert_eq!(snapshot.state, "sealed");
    assert_eq!(snapshot.chain_id, 84532);
    assert_eq!(snapshot.receipt.logs.len(), 2);
    assert_eq!(snapshot.receipt.logs[0].address, ASSET);
}

/// The standalone command: strict, so a transfer that is not demonstrated is an incomplete result.
async fn run_ledger_command(url: &Url, amount: &str, nonce: Option<B256>) -> (i32, String) {
    let url = url.to_string();
    let amount = amount.to_owned();
    let nonce = nonce.map(|n| n.to_string());
    tokio::task::spawn_blocking(move || {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_x402-checker"));
        command.args([
            "ledger",
            TX,
            "--asset",
            &ASSET.to_string(),
            "--pay-to",
            &PAY_TO.to_string(),
            "--amount",
            &amount,
            "--payer",
            &PAYER.to_string(),
            "--rpc-url",
            &url,
            "--ledger-wait",
            "2",
            "--color",
            "never",
        ]);
        if let Some(nonce) = &nonce {
            command.args(["--nonce", nonce]);
        }
        let output = command.output().expect("the binary runs");
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn the_ledger_command_is_strict() {
    let nonce = B256::repeat_byte(0x74);
    let url = spawn(
        84532,
        vec![(TX, receipt(1, &[transfer(PAYER, PAY_TO, 10_000), used(nonce)]))],
    )
    .await;
    let (code, out) = run_ledger_command(&url, "10000", Some(nonce)).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("CONFORMANT"), "{out}");
    // the wrong amount: not demonstrated, never conformant
    let (code, out) = run_ledger_command(&url, "9999", Some(nonce)).await;
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("EXACT-017"), "{out}");
    assert!(!out.contains("CONFORMANT"), "{out}");
    // without the nonce the binding is skipped, and the result says so
    let (code, out) = run_ledger_command(&url, "10000", None).await;
    assert_eq!(code, 2, "{out}");
    assert!(out.contains("nonce was not given"), "{out}");
}
