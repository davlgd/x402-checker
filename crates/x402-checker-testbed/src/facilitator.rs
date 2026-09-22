//! A scripted facilitator (core spec, section 7).
//!
//! It answers `GET /supported` from its configuration and `POST /verify` / `POST /settle` from the current
//! [`Script`]. It never touches a chain and validates no cryptography: the point is to make the resource server
//! under test face every outcome the spec allows a facilitator to produce, on demand, and to record what the
//! server sent. Its one piece of state is the set of authorizations already settled, so that a replay meets a
//! consumed replay primitive as it would on a real network.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine as _;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use x402_checker_types::{X402_VERSION, headers as x402_headers};

use crate::recorder::{Endpoint, Recorder, header_map};

/// What `GET /supported` advertises (core spec, section 7.3.1).
#[derive(Debug, Clone, PartialEq)]
pub struct FacilitatorConfig {
    /// `(scheme, network)` pairs, all at protocol version 2.
    pub kinds: Vec<(String, String)>,
    /// Extension identifiers the facilitator claims to implement.
    pub extensions: Vec<String>,
    /// CAIP-2 patterns to signer addresses.
    pub signers: Map<String, Value>,
    /// The sponsor this facilitator advertises as `extra.feePayer` for `solana:*` kinds (exact on SVM); also its
    /// signer for those networks.
    pub svm_fee_payer: String,
}

/// The fee payer of the SVM scheme's own example, used when none is configured.
pub const DEFAULT_SVM_FEE_PAYER: &str = "EwWqGE4ZFKLofuestmU4LDdK7XM1N4ALgdZccwYugwGd";

/// The wallet this facilitator names as payer of every Solana payment it validates; the transaction is never read.
pub const SVM_PAYER: &str = "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin";

fn is_svm(network: &str) -> bool {
    network.starts_with("solana:")
}

impl FacilitatorConfig {
    /// Exact scheme on one EVM network, one signer, no extension: the common case.
    pub fn exact_evm(network: &str, signer: &str) -> Self {
        Self::exact(&[network.to_owned()], signer, DEFAULT_SVM_FEE_PAYER)
    }

    /// Exact scheme on the given networks: `signer` for the EVM ones, `svm_fee_payer` for the Solana ones.
    pub fn exact(networks: &[String], signer: &str, svm_fee_payer: &str) -> Self {
        let mut signers = Map::new();
        if networks.iter().any(|n| !is_svm(n)) {
            signers.insert("eip155:*".into(), json!([signer]));
        }
        if networks.iter().any(|n| is_svm(n)) {
            signers.insert("solana:*".into(), json!([svm_fee_payer]));
        }
        Self {
            kinds: networks.iter().map(|n| ("exact".to_owned(), n.clone())).collect(),
            extensions: vec![],
            signers,
            svm_fee_payer: svm_fee_payer.to_owned(),
        }
    }

    fn supported_response(&self) -> Value {
        json!({
            "kinds": self.kinds.iter().map(|(scheme, network)| {
                let mut kind = json!({ "x402Version": X402_VERSION, "scheme": scheme, "network": network });
                if is_svm(network) {
                    kind["extra"] = json!({ "feePayer": self.svm_fee_payer });
                }
                kind
            }).collect::<Vec<_>>(),
            "extensions": self.extensions,
            "signers": self.signers,
        })
    }
}

/// What `POST /verify` answers.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifyOutcome {
    /// `{"isValid": true, "payer": ...}`; the payer is `authorization.from` of the request when present.
    Valid,
    /// `{"isValid": false, "invalidReason": reason}`.
    Invalid {
        /// The reason, usually one of the section 9 codes.
        reason: String,
    },
    /// An arbitrary HTTP answer: status, content type and body, for unreadable or unexpected replies.
    Raw {
        /// HTTP status.
        status: u16,
        /// `Content-Type` value.
        content_type: String,
        /// Body text.
        body: String,
    },
}

/// What `POST /settle` answers.
#[derive(Debug, Clone, PartialEq)]
pub enum SettleOutcome {
    /// `{"success": true, "transaction": hash, "network": ..., "payer": ...}`.
    Settled {
        /// Transaction hash to report.
        transaction: String,
    },
    /// `{"success": false, "errorReason": reason, "transaction": transaction, "network": ...}`.
    Rejected {
        /// The reason, usually one of the section 9 codes.
        reason: String,
        /// Transaction to report: empty when nothing was broadcast (core spec, section 5.3.2).
        transaction: String,
    },
    /// `{"success": false, "errorReason": "settlement_pending", "transaction": hash, "network": ...}`.
    Pending {
        /// Broadcast hash, which the spec requires to be non-empty.
        transaction: String,
    },
    /// An arbitrary HTTP answer.
    Raw {
        /// HTTP status.
        status: u16,
        /// `Content-Type` value.
        content_type: String,
        /// Body text.
        body: String,
    },
    /// No answer before `after`, then `then`. Used to exceed the server's client timeout.
    Hang {
        /// How long to stay silent.
        after: Duration,
        /// What to answer afterwards, if the connection is still open.
        then: Box<SettleOutcome>,
    },
}

impl SettleOutcome {
    /// The total silence before the answer and the answer itself, with nested `Hang`s flattened.
    fn resolve(self) -> (Duration, Self) {
        match self {
            Self::Hang { after, then } => {
                let (inner, outcome) = then.resolve();
                (after + inner, outcome)
            }
            other => (Duration::ZERO, other),
        }
    }
}

/// The behaviour of the facilitator for the current scenario.
#[derive(Debug, Clone, PartialEq)]
pub struct Script {
    /// Answer to `/verify`.
    pub verify: VerifyOutcome,
    /// Answer to `/settle`.
    pub settle: SettleOutcome,
    /// When set, sent base64-encoded in the `EXTENSION-RESPONSES` header of verify and settle answers
    /// (core spec, section 7.2.1).
    pub extension_responses: Option<Value>,
    /// When true, a second `/settle` for an authorization already settled (same network, asset, payer and
    /// nonce) answers a rejection with `invalid_transaction_state`, like a network whose replay primitive was
    /// consumed.
    pub reject_consumed_nonces: bool,
    /// Response delay applied to every answer, to simulate a slow facilitator.
    pub latency: Duration,
}

impl Default for Script {
    /// A facilitator that accepts and settles everything, with a fixed transaction hash.
    fn default() -> Self {
        Self {
            verify: VerifyOutcome::Valid,
            settle: SettleOutcome::Settled {
                transaction: format!("0x{}", "ab".repeat(32)),
            },
            extension_responses: None,
            reject_consumed_nonces: true,
            latency: Duration::ZERO,
        }
    }
}

/// Script and settled authorizations, changed together under one lock.
#[derive(Debug)]
struct Scenario {
    script: Script,
    settled: HashSet<String>,
}

#[derive(Clone)]
struct AppState {
    config: Arc<FacilitatorConfig>,
    scenario: Arc<Mutex<Scenario>>,
    recorder: Recorder,
}

/// A running scripted facilitator.
#[derive(Debug)]
pub struct Facilitator {
    addr: SocketAddr,
    scenario: Arc<Mutex<Scenario>>,
    recorder: Recorder,
    task: JoinHandle<()>,
}

impl Facilitator {
    /// Binds `listen` (port 0 picks a free port) and serves in a background task until dropped.
    pub async fn spawn(
        listen: SocketAddr,
        config: FacilitatorConfig,
        script: Script,
        recorder: Recorder,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::bind(listen).await?;
        let addr = listener.local_addr()?;
        let scenario = Arc::new(Mutex::new(Scenario {
            script,
            settled: HashSet::new(),
        }));
        let state = AppState {
            config: Arc::new(config),
            scenario: Arc::clone(&scenario),
            recorder: recorder.clone(),
        };
        let app = Router::new()
            .route("/supported", get(supported))
            .route("/verify", post(verify))
            .route("/settle", post(settle))
            .fallback(unknown)
            .with_state(state);
        let task = tokio::spawn(async move {
            if let Err(error) = axum::serve(listener, app).await {
                tracing::error!(%error, "scripted facilitator stopped");
            }
        });
        Ok(Self {
            addr,
            scenario,
            recorder,
            task,
        })
    }

    /// Where it listens.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Base URL, for a resource server's facilitator setting.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Replaces the script for the next scenario. Settled authorizations are kept, so that a replay across scenarios
    /// still meets a consumed nonce; [`Self::reset`] forgets them. A call already in flight keeps the script it
    /// started with; wait for [`Recorder::has_in_flight`] to be false first.
    pub fn set_script(&self, script: Script) {
        self.scenario
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .script = script;
    }

    /// Forgets every settled authorization, for a fresh session.
    pub fn reset(&self) {
        self.scenario
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .settled
            .clear();
    }

    /// The shared recorder.
    pub fn recorder(&self) -> &Recorder {
        &self.recorder
    }
}

impl Drop for Facilitator {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn supported(State(state): State<AppState>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    let seq = state.recorder.start(
        Endpoint::Supported,
        method.as_str(),
        &uri.to_string(),
        header_map(&headers),
        &[],
    );
    let latency = state
        .scenario
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .script
        .latency;
    tokio::time::sleep(latency).await;
    let response = json_response(StatusCode::OK, &state.config.supported_response(), None);
    state.recorder.finish(seq, response.status().as_u16());
    response
}

async fn verify(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let seq = state.recorder.start(
        Endpoint::Verify,
        method.as_str(),
        &uri.to_string(),
        header_map(&headers),
        &body,
    );
    let script = state
        .scenario
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .script
        .clone();
    tokio::time::sleep(script.latency).await;
    let side = extension_header(script.extension_responses.as_ref());
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let response = match script.verify {
        VerifyOutcome::Valid => json_response(
            StatusCode::OK,
            &with_optional(json!({ "isValid": true }), "payer", payer_of(&request)),
            side,
        ),
        VerifyOutcome::Invalid { reason } => json_response(
            StatusCode::OK,
            &with_optional(
                json!({ "isValid": false, "invalidReason": reason }),
                "payer",
                payer_of(&request),
            ),
            side,
        ),
        VerifyOutcome::Raw {
            status,
            content_type,
            body,
        } => raw_response(status, &content_type, body, side),
    };
    state.recorder.finish(seq, response.status().as_u16());
    response
}

async fn settle(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let seq = state.recorder.start(
        Endpoint::Settle,
        method.as_str(),
        &uri.to_string(),
        header_map(&headers),
        &body,
    );
    let request: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    let (script, consumed) = {
        let mut scenario = state.scenario.lock().unwrap_or_else(PoisonError::into_inner);
        let script = scenario.script.clone();
        // the consumption decision looks at the effective outcome, even behind a Hang
        let (_, effective) = script.settle.clone().resolve();
        let consumed = script.reject_consumed_nonces
            && authorization_key(&request).is_some_and(|key| {
                if scenario.settled.contains(&key) {
                    true
                } else {
                    if matches!(effective, SettleOutcome::Settled { .. }) {
                        scenario.settled.insert(key);
                    }
                    false
                }
            });
        (script, consumed)
    };
    let side = extension_header(script.extension_responses.as_ref());
    let outcome = if consumed {
        SettleOutcome::Rejected {
            reason: "invalid_transaction_state".into(),
            transaction: String::new(),
        }
    } else {
        script.settle
    };
    let (silence, outcome) = outcome.resolve();
    tokio::time::sleep(script.latency + silence).await;
    let payer = settle_payer_of(&request, &state.config);
    let network = request
        .pointer("/paymentRequirements/network")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| state.config.kinds.first().map(|(_, network)| network.clone()))
        .unwrap_or_default();
    let response = match outcome {
        SettleOutcome::Settled { transaction } => json_response(
            StatusCode::OK,
            &settle_body(true, None, &transaction, &network, payer),
            side,
        ),
        SettleOutcome::Rejected { reason, transaction } => json_response(
            StatusCode::OK,
            &settle_body(false, Some(reason), &transaction, &network, payer),
            side,
        ),
        SettleOutcome::Pending { transaction } => json_response(
            StatusCode::OK,
            &settle_body(
                false,
                Some("settlement_pending".into()),
                &transaction,
                &network,
                payer,
            ),
            side,
        ),
        SettleOutcome::Raw {
            status,
            content_type,
            body,
        } => raw_response(status, &content_type, body, side),
        SettleOutcome::Hang { .. } => unreachable!("flattened by resolve"),
    };
    state.recorder.finish(seq, response.status().as_u16());
    response
}

async fn unknown(
    State(state): State<AppState>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let seq = state.recorder.start(
        Endpoint::Unknown,
        method.as_str(),
        &uri.to_string(),
        header_map(&headers),
        &body,
    );
    state.recorder.finish(seq, 404);
    (
        StatusCode::NOT_FOUND,
        "the scripted facilitator serves /supported, /verify and /settle only",
    )
        .into_response()
}

/// The `SettleResponse` body. `network` is Required by the spec; when the request did not name one, the double
/// answers with the first network of its configuration, which is what a facilitator of that network would say.
fn settle_body(
    success: bool,
    reason: Option<String>,
    transaction: &str,
    network: &str,
    payer: Option<String>,
) -> Value {
    let mut body = json!({ "success": success, "transaction": transaction, "network": network });
    body = with_optional(body, "errorReason", reason);
    with_optional(body, "payer", payer)
}

fn with_optional(mut body: Value, key: &str, value: Option<String>) -> Value {
    if let (Some(object), Some(value)) = (body.as_object_mut(), value) {
        object.insert(key.to_owned(), Value::String(value));
    }
    body
}

fn network_of(request: &Value) -> &str {
    request
        .pointer("/paymentRequirements/network")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// The payer `/verify` names: `authorization.from` on EVM, a fixed wallet on Solana (the double reads no
/// transaction).
fn payer_of(request: &Value) -> Option<String> {
    if is_svm(network_of(request)) {
        return Some(SVM_PAYER.to_owned());
    }
    request
        .pointer("/paymentPayload/payload/authorization/from")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// The payer `/settle` names. On Solana the scheme defines it as the fee payer, the account that signed for the
/// fees, not the client's wallet.
fn settle_payer_of(request: &Value, config: &FacilitatorConfig) -> Option<String> {
    if is_svm(network_of(request)) {
        return Some(config.svm_fee_payer.clone());
    }
    payer_of(request)
}

/// The identity a network would refuse twice. EVM: the EIP-3009 authorization (network, asset, payer, nonce).
/// Solana: the serialized transaction itself, decoded so that its base64 spelling does not matter.
fn authorization_key(request: &Value) -> Option<String> {
    let field = |pointer: &str| request.pointer(pointer).and_then(Value::as_str);
    if is_svm(network_of(request)) {
        let transaction = field("/paymentPayload/payload/transaction")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(transaction.trim())
            .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(transaction.trim()))
            .ok()?;
        return Some(format!(
            "{}|{}|{}",
            field("/paymentRequirements/network")?,
            field("/paymentRequirements/asset")?,
            base64::engine::general_purpose::STANDARD.encode(bytes)
        ));
    }
    Some(format!(
        "{}|{}|{}|{}",
        field("/paymentRequirements/network")?,
        field("/paymentRequirements/asset")?.to_ascii_lowercase(),
        field("/paymentPayload/payload/authorization/from")?.to_ascii_lowercase(),
        field("/paymentPayload/payload/authorization/nonce")?.to_ascii_lowercase(),
    ))
}

fn extension_header(value: Option<&Value>) -> Option<HeaderValue> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(value?).ok()?);
    HeaderValue::from_str(&encoded).ok()
}

fn json_response(status: StatusCode, body: &Value, side: Option<HeaderValue>) -> Response {
    let mut response = (status, axum::Json(body.clone())).into_response();
    if let Some(side) = side {
        response
            .headers_mut()
            .insert(x402_headers::EXTENSION_RESPONSES, side);
    }
    response
}

fn raw_response(status: u16, content_type: &str, body: String, side: Option<HeaderValue>) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (status, body).into_response();
    if let Ok(value) = HeaderValue::from_str(content_type) {
        response.headers_mut().insert(header::CONTENT_TYPE, value);
    }
    if let Some(side) = side {
        response
            .headers_mut()
            .insert(x402_headers::EXTENSION_RESPONSES, side);
    }
    response
}
