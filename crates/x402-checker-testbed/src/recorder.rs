//! Shared record of every call received by the doubles.
//!
//! A call is recorded twice: when it arrives and when its answer is prepared (handed to the HTTP layer). Sequence claims ("verify finished
//! before the backend was called", "settle started after the backend answered") must be made on `finished_at`,
//! never on arrival order alone: a server that fires three requests without waiting produces the same arrival
//! order as a conformant one.
//!
//! Normalisation, stated once: header names are lower-cased and repeated values joined with `, `; the body is
//! kept as lossy UTF-8 text in `body_text` and, when it parses, as JSON in `body_json`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Which double, and which of its endpoints, received a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Endpoint {
    /// Facilitator `GET /supported`.
    Supported,
    /// Facilitator `POST /verify`.
    Verify,
    /// Facilitator `POST /settle`.
    Settle,
    /// Any request to the witness backend.
    Backend,
    /// A request to the facilitator on a path it does not serve.
    Unknown,
}

/// One received call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Call {
    /// Position in arrival order across both doubles, never reused, even after [`Recorder::clear`].
    pub seq: u64,
    /// Arrival time.
    pub started_at: Timestamp,
    /// When the answer was prepared, `None` while the call is in flight.
    pub finished_at: Option<Timestamp>,
    /// The status the double answered with, `None` while in flight.
    pub answered_status: Option<u16>,
    /// Which endpoint.
    pub endpoint: Endpoint,
    /// HTTP method.
    pub method: String,
    /// Path and query as received.
    pub path: String,
    /// Request headers, lower-cased names, repeated values joined with `, `.
    pub headers: BTreeMap<String, String>,
    /// Request body as lossy UTF-8 text, empty when there was none.
    pub body_text: String,
    /// The body parsed as JSON, when it parses.
    pub body_json: Option<Value>,
}

impl Call {
    /// Whether the double has answered.
    pub fn is_finished(&self) -> bool {
        self.finished_at.is_some()
    }
}

#[derive(Debug, Default)]
struct Inner {
    calls: Vec<Call>,
    next_seq: u64,
}

/// Thread-safe, append-only list of calls shared by the doubles and the test.
#[derive(Debug, Clone, Default)]
pub struct Recorder {
    inner: Arc<Mutex<Inner>>,
}

impl Recorder {
    /// An empty recorder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an arrival and returns its sequence number.
    pub(crate) fn start(
        &self,
        endpoint: Endpoint,
        method: &str,
        path: &str,
        headers: BTreeMap<String, String>,
        body: &[u8],
    ) -> u64 {
        let body_text = String::from_utf8_lossy(body).into_owned();
        let body_json = if body.is_empty() {
            None
        } else {
            serde_json::from_slice(body).ok()
        };
        // sequence number and insertion under the same lock, so that seq order is arrival order
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        inner.next_seq += 1;
        let seq = inner.next_seq;
        inner.calls.push(Call {
            seq,
            started_at: Timestamp::now(),
            finished_at: None,
            answered_status: None,
            endpoint,
            method: method.to_owned(),
            path: path.to_owned(),
            headers,
            body_text,
            body_json,
        });
        seq
    }

    /// Records that the handler of call `seq` produced its answer with `status`. This is the moment the double
    /// hands the response to the HTTP layer, not proof that the bytes reached the peer; it is enough to order the
    /// server's calls locally.
    pub(crate) fn finish(&self, seq: u64, status: u16) {
        let mut inner = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(call) = inner.calls.iter_mut().find(|c| c.seq == seq) {
            call.finished_at = Some(Timestamp::now());
            call.answered_status = Some(status);
        }
    }

    /// A snapshot of every call so far, in arrival order.
    pub fn calls(&self) -> Vec<Call> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .clone()
    }

    /// The calls to one endpoint, in arrival order.
    pub fn calls_to(&self, endpoint: Endpoint) -> Vec<Call> {
        self.calls()
            .into_iter()
            .filter(|c| c.endpoint == endpoint)
            .collect()
    }

    /// Whether some call has not been answered yet. A test waits for this to be false before changing scripts.
    pub fn has_in_flight(&self) -> bool {
        self.calls().iter().any(|c| !c.is_finished())
    }

    /// Forgets every finished call. Calls still in flight are kept so that their end is not lost and
    /// [`Self::has_in_flight`] stays true; sequence numbers keep increasing, so a late call from an earlier
    /// scenario cannot be mistaken for a new one.
    pub fn clear(&self) {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .calls
            .retain(|c| !c.is_finished());
    }
}

/// Lower-cases header names and joins repeated values, for recording.
pub(crate) fn header_map(headers: &axum::http::HeaderMap) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers {
        let value = redact(name.as_str(), value.to_str().unwrap_or("<non-ascii>"));
        out.entry(name.as_str().to_owned())
            .and_modify(|v| *v = format!("{v}, {value}"))
            .or_insert(value);
    }
    out
}

/// Credentials never reach a trace, hence a report: see [`x402_checker_types::headers::redact`].
fn redact(name: &str, value: &str) -> String {
    x402_checker_types::headers::redact(name, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_are_redacted_and_a_jwt_keeps_only_its_descriptive_parts() {
        use base64::Engine as _;
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let header = engine.encode(r#"{"alg":"EdDSA","kid":"k","typ":"JWT","nonce":"n"}"#);
        let claims =
            engine.encode(r#"{"sub":"k","iss":"cdp","uris":["POST h/p"],"exp":2,"nbf":1,"email":"x@y"}"#);
        let kept = redact("authorization", &format!("Bearer {header}.{claims}.sig"));
        assert!(kept.starts_with("Bearer "));
        assert!(kept.ends_with(".<signature redacted>"));
        let parts: Vec<&str> = kept.trim_start_matches("Bearer ").split('.').collect();
        let claims_kept: Value = serde_json::from_slice(&engine.decode(parts[1]).unwrap()).unwrap();
        assert!(
            claims_kept.get("uris").is_some()
                && claims_kept.get("email").is_none()
                && claims_kept.get("sub").is_none()
        );
        let header_kept: Value = serde_json::from_slice(&engine.decode(parts[0]).unwrap()).unwrap();
        assert!(header_kept.get("alg").is_some() && header_kept.get("nonce").is_none());
        assert_eq!(redact("Authorization", "Bearer opaque"), "Bearer <redacted>");
        assert_eq!(redact("authorization", "raw-token-without-scheme"), "<redacted>");
        assert_eq!(redact("x-api-key", "k-123"), "<redacted>");
        assert_eq!(redact("cookie", "session=abc; other=1"), "<redacted>");
        assert_eq!(redact("content-type", "application/json"), "application/json");
    }
}
