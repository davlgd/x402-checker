//! An HTTP client that keeps every exchange as evidence.
//!
//! Each request sent to the target is recorded with its headers and a bounded copy of its body, then the response
//! status and headers as soon as they arrive, a bounded copy of the response body, and the x402 headers decoded
//! as raw JSON. A body that cannot be read still leaves an exchange with its status and headers: the state of a
//! payment (in the headers) and the delivery of the resource (the body) are two different facts.

use std::collections::BTreeMap;
use std::time::Instant;

use reqwest::header::HeaderMap;
use reqwest::{Method, Request, Url};
use serde::Serialize;
use serde_json::Value;
use x402_checker_types::codec::{Base64Variant, decode_header};
use x402_checker_types::{PaymentRequired, SettleResponse, headers};

/// Bodies are kept up to this many bytes in the report.
pub const BODY_CAP: usize = 8 * 1024;

/// One of the x402 headers, decoded as far as it goes.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DecodedHeader {
    /// The raw header value.
    pub raw: String,
    /// The base64 variant found, when the value was base64 at all.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<Base64Variant>,
    /// The decoded JSON exactly as sent (numbers, nulls and unknown members kept), when it parsed as JSON.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<Value>,
    /// Why base64 or JSON decoding failed, otherwise.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl DecodedHeader {
    fn decode(raw: &str) -> Self {
        match decode_header::<Value>(raw) {
            Ok(decoded) => Self {
                raw: raw.to_owned(),
                variant: Some(decoded.variant),
                json: Some(decoded.value),
                error: None,
            },
            Err(error) => Self {
                raw: raw.to_owned(),
                variant: None,
                json: None,
                error: Some(error.to_string()),
            },
        }
    }

    /// The JSON converted to a wire type, when its shape allows it.
    pub fn typed<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        serde_json::from_value(self.json.clone()?).ok()
    }
}

/// A bounded copy of a body.
#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub struct Body {
    /// Lossy UTF-8 text of the first [`BODY_CAP`] bytes.
    pub text: String,
    /// Whether the body was cut at the cap.
    pub truncated: bool,
    /// Why the body could not be read to the end, when it could not.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// One request and its response.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Exchange {
    /// Position in the run, starting at 1.
    pub seq: usize,
    /// Why this request was sent.
    pub label: String,
    /// HTTP method.
    pub method: String,
    /// Request URL.
    pub url: String,
    /// Request headers, lower-cased names.
    pub request_headers: BTreeMap<String, String>,
    /// Request body, bounded.
    pub request_body: Body,
    /// Response status.
    pub status: u16,
    /// Response headers, lower-cased names, repeated values joined with `, `.
    pub response_headers: BTreeMap<String, String>,
    /// Response body, bounded.
    pub body: Body,
    /// Time from sending to the end of the body read.
    pub elapsed_ms: u128,
    /// `PAYMENT-REQUIRED` decoded, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_required: Option<DecodedHeader>,
    /// `PAYMENT-RESPONSE` decoded, when present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payment_response: Option<DecodedHeader>,
}

impl Exchange {
    /// A response header by case-insensitive name.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.response_headers
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// The `PaymentRequired` object, when the header was present and its JSON has the expected shape.
    pub fn payment_required(&self) -> Option<PaymentRequired> {
        self.payment_required.as_ref()?.typed()
    }

    /// The raw JSON of `PAYMENT-REQUIRED`, when it decoded.
    pub fn payment_required_json(&self) -> Option<&Value> {
        self.payment_required.as_ref()?.json.as_ref()
    }

    /// The `SettleResponse` object, when the header was present and its JSON has the expected shape.
    pub fn payment_response(&self) -> Option<SettleResponse> {
        self.payment_response.as_ref()?.typed()
    }

    /// The response body parsed as JSON, when it is JSON.
    pub fn body_json(&self) -> Option<Value> {
        serde_json::from_str(&self.body.text).ok()
    }

    /// Whether the status is 2xx.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// Why a request could not complete at all (no status received).
#[derive(Debug, thiserror::Error)]
#[error("{label}: {source}")]
pub struct HttpError {
    /// The exchange label.
    pub label: String,
    /// The underlying error.
    #[source]
    pub source: reqwest::Error,
}

/// The recording client.
#[derive(Debug)]
pub struct Client {
    http: reqwest::Client,
    exchanges: Vec<Exchange>,
}

impl Client {
    /// A client with the given per-request timeout, no redirects (a 3xx is an answer worth seeing), rustls.
    pub fn new(timeout: std::time::Duration) -> Result<Self, reqwest::Error> {
        let http = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("x402-checker/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            exchanges: Vec::new(),
        })
    }

    /// A request builder for `method` on `url`.
    pub fn request(&self, method: Method, url: Url) -> reqwest::RequestBuilder {
        self.http.request(method, url)
    }

    /// Sends `request`, records the exchange under `label`, returns its index. A body that cannot be read to the
    /// end is still an exchange, with the error noted in `body.error`.
    pub async fn send(&mut self, label: impl Into<String>, request: Request) -> Result<usize, HttpError> {
        let label = label.into();
        let method = request.method().to_string();
        let url = request.url().to_string();
        let request_headers = header_map(request.headers());
        let request_body = request
            .body()
            .and_then(|b| b.as_bytes())
            .map(bounded)
            .unwrap_or_default();
        let started = Instant::now();
        let mut response = self.http.execute(request).await.map_err(|source| HttpError {
            label: label.clone(),
            source,
        })?;
        let status = response.status().as_u16();
        let response_headers = header_map(response.headers());
        let mut bytes = Vec::new();
        let mut body = Body::default();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let room = BODY_CAP.saturating_sub(bytes.len());
                    if chunk.len() > room {
                        body.truncated = true;
                    }
                    bytes.extend_from_slice(&chunk[..chunk.len().min(room)]);
                }
                Ok(None) => break,
                Err(error) => {
                    body.error = Some(error.to_string());
                    break;
                }
            }
        }
        body.text = String::from_utf8_lossy(&bytes).into_owned();
        let elapsed_ms = started.elapsed().as_millis();
        let payment_required = response_headers
            .get(&headers::PAYMENT_REQUIRED.to_ascii_lowercase())
            .map(|v| DecodedHeader::decode(v));
        let payment_response = response_headers
            .get(&headers::PAYMENT_RESPONSE.to_ascii_lowercase())
            .map(|v| DecodedHeader::decode(v));
        self.exchanges.push(Exchange {
            seq: self.exchanges.len() + 1,
            label,
            method,
            url,
            request_headers,
            request_body,
            status,
            response_headers,
            body,
            elapsed_ms,
            payment_required,
            payment_response,
        });
        Ok(self.exchanges.len() - 1)
    }

    /// An exchange by index.
    pub fn exchange(&self, index: usize) -> &Exchange {
        &self.exchanges[index]
    }

    /// Every exchange so far.
    pub fn exchanges(&self) -> &[Exchange] {
        &self.exchanges
    }

    /// Hands the exchanges over to the report.
    pub fn into_exchanges(self) -> Vec<Exchange> {
        self.exchanges
    }
}

fn bounded(bytes: &[u8]) -> Body {
    Body {
        text: String::from_utf8_lossy(&bytes[..bytes.len().min(BODY_CAP)]).into_owned(),
        truncated: bytes.len() > BODY_CAP,
        error: None,
    }
}

/// Headers as the report keeps them: credentials redacted (an `Authorization` given with `-H` never lands in a
/// report), the x402 headers untouched since they are what the checks read.
fn header_map(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (name, value) in headers {
        let value = headers::redact(name.as_str(), value.to_str().unwrap_or("<non-ascii>"));
        out.entry(name.as_str().to_owned())
            .and_modify(|v| *v = format!("{v}, {value}"))
            .or_insert(value);
    }
    out
}
