//! The suites against a small resource server written from the spec, wired to the crate's own doubles.
//!
//! The server is not a product: it is the smallest reading of the authorization flow (decode, match the offer,
//! `/verify`, call the backend, `/settle`, relay the receipt, refuse replays) that the suites should find
//! conformant. It also shows what a conformant server does with each facilitator outcome.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};
use x402_checker::check::{Level, Verdict};
use x402_checker::suites::probe;
use x402_checker::suites::scenarios::{self, MechanismKind, ScenarioOptions};
use x402_checker::target::{Context, Options, Target};
use x402_checker_testbed::{Facilitator, FacilitatorConfig, Recorder, Script, Witness, WitnessScript};
use x402_checker_types::{
    FacilitatorRequest, PaymentPayload, PaymentRequired, SettleResponse, VerifyResponse, codec, headers,
};

const NETWORK: &str = "eip155:84532";
const USDC: &str = "0x036CbD53842c5426634e7929541eC2318f3dCF7e";
const PAY_TO: &str = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";

#[derive(Clone)]
struct ServerState {
    facilitator_url: String,
    backend_url: Option<String>,
    public_url: Arc<Mutex<String>>,
    settled: Arc<Mutex<HashSet<String>>>,
    receipts: Arc<Mutex<Vec<(String, String)>>>,
    http: reqwest::Client,
}

fn offer(url: &str) -> PaymentRequired {
    serde_json::from_value(json!({
        "x402Version": 2,
        "error": "PAYMENT-SIGNATURE header is required",
        "resource": { "url": url, "description": "reference resource", "mimeType": "application/json" },
        "accepts": [{
            "scheme": "exact", "network": NETWORK, "amount": "10000", "asset": USDC, "payTo": PAY_TO,
            "maxTimeoutSeconds": 60, "extra": { "name": "USDC", "version": "2" }
        }],
        "extensions": {}
    }))
    .unwrap()
}

fn challenge(url: &str, error: Option<&str>) -> Response {
    let mut required = offer(url);
    if let Some(error) = error {
        required.error = Some(error.to_owned());
    }
    let header = codec::encode_header(&required).unwrap();
    let mut response = (
        StatusCode::PAYMENT_REQUIRED,
        axum::Json(json!({ "error": error.unwrap_or("payment required") })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(headers::PAYMENT_REQUIRED, HeaderValue::from_str(&header).unwrap());
    response
}

fn bad_request(reason: &str) -> Response {
    (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": reason }))).into_response()
}

fn with_receipt(mut response: Response, receipt: &SettleResponse) -> Response {
    let header = codec::encode_header(receipt).unwrap();
    response
        .headers_mut()
        .insert(headers::PAYMENT_RESPONSE, HeaderValue::from_str(&header).unwrap());
    response
}

async fn paid(State(state): State<ServerState>, request_headers: HeaderMap, _body: Bytes) -> Response {
    let url = state
        .public_url
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let Some(raw) = request_headers
        .get(headers::PAYMENT_SIGNATURE)
        .and_then(|v| v.to_str().ok())
    else {
        return challenge(&url, None);
    };
    let Ok(decoded) = codec::decode_header::<Value>(raw) else {
        return bad_request("invalid_payload");
    };
    let Ok(payload) = serde_json::from_value::<PaymentPayload>(decoded.value) else {
        return bad_request("invalid_payload");
    };
    if payload.x402_version != 2 {
        return bad_request("invalid_x402_version");
    }
    let requirements = offer(&url).accepts.remove(0);
    if payload.accepted != requirements {
        return bad_request("invalid_payment_requirements");
    }
    let nonce = payload
        .payload
        .pointer("/authorization/nonce")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    if let Some(receipt) = state.known_receipt(&nonce) {
        return with_receipt(
            (
                StatusCode::CONFLICT,
                axum::Json(json!({ "error": "payment_already_settled" })),
            )
                .into_response(),
            &receipt,
        );
    }
    let request = FacilitatorRequest {
        x402_version: 2,
        payment_payload: payload,
        payment_requirements: requirements,
    };
    if let Err(response) = state.verify(&request, &url).await {
        return *response;
    }
    let body = match state.resource().await {
        Ok(body) => body,
        Err(response) => return *response,
    };
    state.settle(&request, &nonce, body).await
}

impl ServerState {
    fn known_receipt(&self, nonce: &str) -> Option<SettleResponse> {
        let receipts = self.receipts.lock().unwrap_or_else(PoisonError::into_inner);
        let (_, receipt) = receipts.iter().find(|(n, _)| n == nonce)?;
        serde_json::from_str(receipt).ok()
    }

    /// `/verify`, then a 402 with the reason when the facilitator says no.
    async fn verify(&self, request: &FacilitatorRequest, url: &str) -> Result<(), Box<Response>> {
        let response = self
            .http
            .post(format!("{}/verify", self.facilitator_url))
            .json(request)
            .send()
            .await
            .map_err(|_| {
                Box::new((StatusCode::INTERNAL_SERVER_ERROR, "verify unreachable").into_response())
            })?;
        let verify: VerifyResponse = response.json().await.map_err(|_| {
            Box::new((StatusCode::INTERNAL_SERVER_ERROR, "verify unreadable").into_response())
        })?;
        if verify.is_valid {
            Ok(())
        } else {
            Err(Box::new(challenge(
                url,
                verify.invalid_reason.as_deref().or(Some("verification failed")),
            )))
        }
    }

    /// The protected resource: the witness when configured, a constant otherwise. A failure is not settled.
    async fn resource(&self) -> Result<String, Box<Response>> {
        let Some(backend) = &self.backend_url else {
            return Ok(json!({ "data": "premium" }).to_string());
        };
        match self.http.get(backend).send().await {
            Ok(r) if r.status().is_success() => Ok(r.text().await.unwrap_or_default()),
            Ok(r) => Err(Box::new(
                (
                    StatusCode::BAD_GATEWAY,
                    format!("backend answered {}", r.status()),
                )
                    .into_response(),
            )),
            Err(_) => Err(Box::new(
                (StatusCode::BAD_GATEWAY, "backend unreachable").into_response(),
            )),
        }
    }

    /// `/settle` once per nonce, then the receipt relayed with the status its outcome calls for.
    async fn settle(&self, request: &FacilitatorRequest, nonce: &str, body: String) -> Response {
        if !self
            .settled
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(nonce.to_owned())
        {
            return (
                StatusCode::CONFLICT,
                axum::Json(json!({ "error": "settlement_in_progress" })),
            )
                .into_response();
        }
        let unknown = || {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                axum::Json(json!({ "error": "settlement_unknown" })),
            )
                .into_response()
        };
        let Ok(response) = self
            .http
            .post(format!("{}/settle", self.facilitator_url))
            .json(request)
            .send()
            .await
        else {
            return unknown();
        };
        let Ok(receipt) = response.json::<SettleResponse>().await else {
            return unknown();
        };
        self.receipts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((nonce.to_owned(), serde_json::to_string(&receipt).unwrap()));
        if receipt.success || receipt.is_pending() {
            with_receipt((StatusCode::OK, body).into_response(), &receipt)
        } else {
            with_receipt(
                (
                    StatusCode::PAYMENT_REQUIRED,
                    axum::Json(json!({ "error": receipt.error_reason })),
                )
                    .into_response(),
                &receipt,
            )
        }
    }
}

async fn spawn_server(facilitator_url: String, backend_url: Option<String>) -> (String, ServerState) {
    let state = ServerState {
        facilitator_url,
        backend_url,
        public_url: Arc::new(Mutex::new(String::new())),
        settled: Arc::default(),
        receipts: Arc::default(),
        http: reqwest::Client::new(),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let url = format!("http://{}/paid", listener.local_addr().unwrap());
    state.public_url.lock().unwrap().clone_from(&url);
    let app = Router::new()
        .route("/paid", get(paid).post(paid))
        .with_state(state.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (url, state)
}

fn context(url: &str) -> Context {
    let target = Target {
        url: url.parse().unwrap(),
        method: reqwest::Method::GET,
        headers: vec![],
        body: None,
    };
    Context::new(
        target,
        Options {
            allow_mainnet: false,
            timeout: Duration::from_secs(10),
        },
    )
    .unwrap()
}

fn required_failures(findings: &[x402_checker::check::Finding]) -> Vec<String> {
    findings
        .iter()
        .filter(|f| f.check.level == Level::Required && f.counts_against_target())
        .map(|f| format!("{}: {}", f.check.id, f.detail))
        .collect()
}

#[tokio::test]
async fn the_reference_server_passes_probe() {
    let recorder = Recorder::new();
    let facilitator = Facilitator::spawn(
        "127.0.0.1:0".parse().unwrap(),
        FacilitatorConfig::exact_evm(NETWORK, PAY_TO),
        Script::default(),
        recorder,
    )
    .await
    .unwrap();
    let (url, _) = spawn_server(facilitator.url(), None).await;
    let mut ctx = context(&url);
    let result = probe::run(&mut ctx).await;
    assert_eq!(required_failures(&result.findings), Vec::<String>::new());
    let ids: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::Pass)
        .map(|f| f.check.id)
        .collect();
    for expected in [
        "HTTP-001",
        "HTTP-002",
        "HTTP-003",
        "CORE-002",
        "CORE-007",
        "CORE-008",
        "EVM-012",
        "HTTP-010",
        "HTTP-010s",
    ] {
        assert!(ids.contains(&expected), "{expected} should pass, got {ids:?}");
    }
    // the scripted facilitator accepts a zero signature, so the tool cannot tell who is at fault
    let zero = result
        .findings
        .iter()
        .find(|f| f.check.id == "CORE-054z")
        .unwrap();
    assert_eq!(zero.attribution, Some(x402_checker::check::Attribution::Unknown));
}

#[tokio::test]
async fn the_reference_server_passes_scenarios_with_a_witness() {
    let recorder = Recorder::new();
    let facilitator = Facilitator::spawn(
        "127.0.0.1:0".parse().unwrap(),
        FacilitatorConfig::exact_evm(NETWORK, PAY_TO),
        Script::default(),
        recorder.clone(),
    )
    .await
    .unwrap();
    let witness = Witness::spawn("127.0.0.1:0".parse().unwrap(), WitnessScript::default(), recorder)
        .await
        .unwrap();
    let (url, _) = spawn_server(facilitator.url(), Some(witness.url())).await;
    let mut ctx = context(&url);
    let options = ScenarioOptions {
        facilitator,
        witness: Some(witness),
        settle_wait: Duration::from_secs(2),
        mechanism: MechanismKind::default(),
    };
    let result = scenarios::run(&mut ctx, &options).await;
    assert_eq!(required_failures(&result.findings), Vec::<String>::new());
    let passed: Vec<_> = result
        .findings
        .iter()
        .filter(|f| f.verdict == Verdict::Pass)
        .map(|f| f.check.id)
        .collect();
    for expected in [
        "CORE-055",
        "CORE-059",
        "CORE-050a",
        "CORE-050",
        "CORE-030",
        "CORE-064",
        "CORE-054v",
        "CORE-054b",
        "HTTP-006",
        "CORE-038",
        "SCN-UNREADABLE",
        "CORE-051",
        "CORE-072s",
    ] {
        assert!(
            passed.contains(&expected),
            "{expected} should pass, got {passed:?}"
        );
    }
    assert!(
        result.findings.iter().all(|f| f.verdict != Verdict::Skip),
        "with a witness nothing is skipped: {:?}",
        result
            .findings
            .iter()
            .filter(|f| f.verdict == Verdict::Skip)
            .map(|f| f.check.id)
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn a_server_that_forwards_the_sidechannel_and_settles_before_the_backend_is_caught() {
    // a deliberately wrong server: settles first, forwards EXTENSION-RESPONSES, serves after an invalid verify
    #[derive(Clone)]
    struct Wrong {
        facilitator_url: String,
        http: reqwest::Client,
        url: Arc<Mutex<String>>,
    }
    async fn wrong(State(state): State<Wrong>, request_headers: HeaderMap) -> Response {
        let url = state.url.lock().unwrap().clone();
        let Some(raw) = request_headers
            .get(headers::PAYMENT_SIGNATURE)
            .and_then(|v| v.to_str().ok())
        else {
            return challenge(&url, None);
        };
        let payload: PaymentPayload = codec::decode_header::<PaymentPayload>(raw).unwrap().value;
        let request = FacilitatorRequest {
            x402_version: 2,
            payment_payload: payload,
            payment_requirements: offer(&url).accepts.remove(0),
        };
        let settle = state
            .http
            .post(format!("{}/settle", state.facilitator_url))
            .json(&request)
            .send()
            .await
            .unwrap();
        let side = settle.headers().get(headers::EXTENSION_RESPONSES).cloned();
        let receipt: SettleResponse = settle.json().await.unwrap_or(SettleResponse {
            success: true,
            error_reason: None,
            payer: None,
            transaction: "0x00".into(),
            network: NETWORK.into(),
            amount: None,
            extensions: None,
        });
        let _ = state
            .http
            .post(format!("{}/verify", state.facilitator_url))
            .json(&request)
            .send()
            .await;
        let mut response = with_receipt((StatusCode::OK, "served").into_response(), &receipt);
        if let Some(side) = side {
            response.headers_mut().insert(headers::EXTENSION_RESPONSES, side);
        }
        response
    }
    let recorder = Recorder::new();
    let facilitator = Facilitator::spawn(
        "127.0.0.1:0".parse().unwrap(),
        FacilitatorConfig::exact_evm(NETWORK, PAY_TO),
        Script::default(),
        recorder,
    )
    .await
    .unwrap();
    let state = Wrong {
        facilitator_url: facilitator.url(),
        http: reqwest::Client::new(),
        url: Arc::new(Mutex::new(String::new())),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap())
        .await
        .unwrap();
    let url = format!("http://{}/paid", listener.local_addr().unwrap());
    *state.url.lock().unwrap() = url.clone();
    let app = Router::new().route("/paid", get(wrong)).with_state(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let mut ctx = context(&url);
    let options = ScenarioOptions {
        facilitator,
        witness: None,
        settle_wait: Duration::from_secs(2),
        mechanism: MechanismKind::default(),
    };
    let result = scenarios::run(&mut ctx, &options).await;
    let failed: Vec<_> = required_failures(&result.findings)
        .into_iter()
        .map(|f| f.split(':').next().unwrap().to_owned())
        .collect();
    for expected in ["CORE-050a", "CORE-064", "CORE-054v"] {
        assert!(
            failed.contains(&expected.to_owned()),
            "{expected} should fail, failures: {failed:?}"
        );
    }
}
