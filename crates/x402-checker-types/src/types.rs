//! The core data structures (core spec, section 5 and 7.3).
//!
//! These structs are for *building* and *consuming* messages (a client signing for an offer, a facilitator double
//! answering a request). They are not the conformance oracle: a conformance check works on the raw JSON value,
//! where presence, `null` and the exact number representation are visible, and only then converts. Accordingly
//! the structs are permissive where it costs nothing (an absent optional and `null` both read as `None`, unknown
//! members are ignored) and keep the representation where it matters (`maxTimeoutSeconds` stays a JSON number).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The protocol version this crate implements (`x402Version`).
pub const X402_VERSION: u64 = 2;

/// Extension data as it travels in `PaymentRequired`, `PaymentPayload` and responses: a map from extension
/// identifier to that extension's object (core spec, section 5.1.2: `info` and `schema` when advertised by a
/// server; free-form elsewhere).
pub type Extensions = Map<String, Value>;

/// Section 5.1: what a resource server sends when payment is required.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequired {
    /// Protocol version identifier; the spec says it must be 2.
    pub x402_version: u64,
    /// Human-readable reason, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The protected resource.
    pub resource: ResourceInfo,
    /// Acceptable payment methods.
    pub accepts: Vec<PaymentRequirements>,
    /// Extensions advertised by the server, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
}

/// Section 5.1.2: one acceptable payment method.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentRequirements {
    /// Payment scheme identifier, for example `exact`.
    pub scheme: String,
    /// Network identifier in CAIP-2 format. Kept as a string so that an invalid value can be reported.
    pub network: String,
    /// Required amount in atomic units, as a string.
    pub amount: String,
    /// Token contract address, or ISO 4217 code for fiat.
    pub asset: String,
    /// Recipient address or role constant.
    pub pay_to: String,
    /// Maximum time allowed for payment completion. Kept as a JSON number so that `60` and `60.0` round-trip as sent.
    pub max_timeout_seconds: serde_json::Number,
    /// Scheme-specific data plus the reserved keys `assetTransferMethod` and `paymentFlow` (section 6.1).
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub extra: Map<String, Value>,
}

impl PaymentRequirements {
    /// The reserved `extra.assetTransferMethod`: `Ok(None)` when absent (mechanism default), `Ok(Some)` when a
    /// string, `Err` with the offending value when present with another type.
    pub fn asset_transfer_method(&self) -> Result<Option<&str>, &Value> {
        reserved_string(&self.extra, "assetTransferMethod")
    }

    /// The reserved `extra.paymentFlow`: `Ok(None)` when absent (the mechanism default, `authorization` for
    /// `exact`), `Ok(Some)` when a string, `Err` with the offending value when present with another type.
    pub fn payment_flow(&self) -> Result<Option<&str>, &Value> {
        reserved_string(&self.extra, "paymentFlow")
    }
}

fn reserved_string<'a>(extra: &'a Map<String, Value>, key: &str) -> Result<Option<&'a str>, &'a Value> {
    match extra.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(other) => Err(other),
    }
}

/// Section 5.1.2: description of the protected resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceInfo {
    /// URL of the protected resource.
    pub url: String,
    /// Human-readable description, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// MIME type of the expected response, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    /// Service name: printable ASCII, at most 32 characters, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_name: Option<String>,
    /// Discovery tags: at most 5, each printable ASCII of at most 32 characters, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Absolute http(s) icon URL of at most 2048 characters, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_url: Option<String>,
}

/// Section 5.2: what a client sends back with its payment authorization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentPayload {
    /// Protocol version identifier.
    pub x402_version: u64,
    /// The resource being accessed, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceInfo>,
    /// The `accepts[]` entry the client chose.
    pub accepted: PaymentRequirements,
    /// Scheme-specific payment data (for exact EVM: `signature` and `authorization`).
    pub payload: Value,
    /// Extensions echoed by the client, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
}

/// Section 5.3: outcome of a settlement, from the facilitator to the server and on to the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettleResponse {
    /// Whether the settlement succeeded.
    pub success: bool,
    /// Error reason when it failed; omitted on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_reason: Option<String>,
    /// Payer address, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// Transaction hash; empty string when nothing was broadcast; non-empty when `errorReason` is
    /// `settlement_pending`.
    pub transaction: String,
    /// Network identifier in CAIP-2 format.
    pub network: String,
    /// Amount actually settled in atomic units, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// Extension data, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
}

impl SettleResponse {
    /// Whether this is the non-terminal `settlement_pending` outcome (section 9).
    pub fn is_pending(&self) -> bool {
        !self.success && self.error_reason.as_deref() == Some(crate::error_codes::SETTLEMENT_PENDING)
    }
}

/// Section 5.4: outcome of a verification, from the facilitator to the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerifyResponse {
    /// Whether the authorization is valid.
    pub is_valid: bool,
    /// Reason when invalid; omitted when valid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invalid_reason: Option<String>,
    /// Payer address, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payer: Option<String>,
    /// Extension data, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    /// Scheme-specific additional data, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Map<String, Value>>,
}

/// Section 7.1 and 7.2: request body of `POST /verify` and `POST /settle`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FacilitatorRequest {
    /// Protocol version identifier.
    pub x402_version: u64,
    /// The client's payload.
    pub payment_payload: PaymentPayload,
    /// The server's requirements for this payment.
    pub payment_requirements: PaymentRequirements,
}

/// Section 7.3: what `GET /supported` returns.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedResponse {
    /// Supported (version, scheme, network) triples.
    pub kinds: Vec<SupportedKind>,
    /// Extension identifiers the facilitator implements.
    pub extensions: Vec<String>,
    /// CAIP-2 patterns to public signer addresses.
    pub signers: Map<String, Value>,
}

/// Section 7.3.1: one supported payment kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    /// Protocol version supported.
    pub x402_version: u64,
    /// Payment scheme identifier.
    pub scheme: String,
    /// Network identifier in CAIP-2 format.
    pub network: String,
    /// Scheme-specific configuration, optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<Map<String, Value>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Section 5.1.1 example, verbatim.
    const SPEC_PAYMENT_REQUIRED: &str = r#"{
      "x402Version": 2,
      "error": "PAYMENT-SIGNATURE header is required",
      "resource": {
        "url": "https://api.example.com/premium-data",
        "description": "Access to premium market data",
        "mimeType": "application/json",
        "serviceName": "Example Market Data",
        "tags": ["market-data", "finance"],
        "iconUrl": "https://api.example.com/icon.png"
      },
      "accepts": [
        {
          "scheme": "exact",
          "network": "eip155:84532",
          "amount": "10000",
          "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
          "maxTimeoutSeconds": 60,
          "extra": { "name": "USDC", "version": "2" }
        }
      ],
      "extensions": {}
    }"#;

    /// Section 7.3 example, verbatim.
    const SPEC_SUPPORTED: &str = r#"{
      "kinds": [
        { "x402Version": 2, "scheme": "exact", "network": "eip155:84532" },
        { "x402Version": 2, "scheme": "exact", "network": "eip155:8453" }
      ],
      "extensions": [],
      "signers": {
        "eip155:*": ["0x1234567890abcdef1234567890abcdef12345678"],
        "solana:*": ["CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5"]
      }
    }"#;

    #[test]
    fn parses_the_full_payment_required_example() {
        let required: PaymentRequired = serde_json::from_str(SPEC_PAYMENT_REQUIRED).unwrap();
        let resource = &required.resource;
        assert_eq!(resource.service_name.as_deref(), Some("Example Market Data"));
        assert_eq!(
            resource.tags.as_deref(),
            Some(&["market-data".to_owned(), "finance".to_owned()][..])
        );
        assert_eq!(
            resource.icon_url.as_deref(),
            Some("https://api.example.com/icon.png")
        );
        assert_eq!(required.extensions, Some(Map::new()));
        let offer = &required.accepts[0];
        assert_eq!(
            offer.payment_flow(),
            Ok(None),
            "absent means the mechanism default"
        );
        assert_eq!(offer.asset_transfer_method(), Ok(None));
    }

    #[test]
    fn serialisation_keeps_the_spec_field_names_and_omits_absent_options() {
        let required: PaymentRequired = serde_json::from_str(SPEC_PAYMENT_REQUIRED).unwrap();
        let json = serde_json::to_value(&required).unwrap();
        assert_eq!(json["x402Version"], 2);
        assert_eq!(
            json["accepts"][0]["payTo"],
            "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
        );
        assert_eq!(json["accepts"][0]["maxTimeoutSeconds"], 60);
        assert_eq!(json["resource"]["mimeType"], "application/json");

        let minimal = PaymentRequired {
            x402_version: 2,
            error: None,
            resource: ResourceInfo {
                url: "https://example.com/r".into(),
                description: None,
                mime_type: None,
                service_name: None,
                tags: None,
                icon_url: None,
            },
            accepts: vec![],
            extensions: None,
        };
        let json = serde_json::to_value(&minimal).unwrap();
        assert_eq!(
            json.as_object().unwrap().keys().collect::<Vec<_>>(),
            ["x402Version", "resource", "accepts"]
        );
        assert_eq!(json["resource"].as_object().unwrap().len(), 1);
    }

    #[test]
    fn parses_the_supported_example() {
        let supported: SupportedResponse = serde_json::from_str(SPEC_SUPPORTED).unwrap();
        assert_eq!(supported.kinds.len(), 2);
        assert!(supported.signers.contains_key("eip155:*"));
    }

    #[test]
    fn a_malformed_object_is_still_reported_as_a_decode_error_not_a_panic() {
        let missing_accepts = r#"{"x402Version":2,"resource":{"url":"u"}}"#;
        let err = serde_json::from_str::<PaymentRequired>(missing_accepts).unwrap_err();
        assert!(err.to_string().contains("accepts"));
    }

    #[test]
    fn settlement_pending_is_recognised() {
        let pending = SettleResponse {
            success: false,
            error_reason: Some("settlement_pending".into()),
            payer: None,
            transaction: "0xabc".into(),
            network: "eip155:84532".into(),
            amount: None,
            extensions: None,
        };
        assert!(pending.is_pending());
    }
}
