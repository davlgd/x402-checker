//! Base64 codec of the x402 HTTP headers.
//!
//! The transport spec says "base64-encoded JSON" and never names the alphabet or the padding rule; its examples
//! use the standard alphabet with `=` padding. Decoding therefore accepts the four usual variants and reports
//! which one was found, so a conformance report can state the fact without inventing a rule. Encoding always
//! produces the variant of the examples.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// The base64 alphabet found in a header value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Alphabet {
    /// RFC 4648 section 4 (`+` and `/`): the alphabet of the spec examples.
    Standard,
    /// RFC 4648 section 5 (`-` and `_`).
    UrlSafe,
    /// The value contains none of the four distinguishing characters, so both alphabets decode it identically.
    Indistinct,
}

/// Whether a header value carried `=` padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Padding {
    /// Trailing `=` present, as in the spec examples.
    Present,
    /// Padding would have been needed and was omitted.
    Omitted,
    /// The encoded length is a multiple of four, so padding was not needed and nothing can be said.
    NotNeeded,
}

/// How a header value was base64-encoded, as far as the bytes allow to tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Base64Variant {
    /// The alphabet used.
    pub alphabet: Alphabet,
    /// The padding observed.
    pub padding: Padding,
}

impl Base64Variant {
    /// Whether the value could have been produced by an encoder following the spec examples (standard alphabet,
    /// padded). `Indistinct` and `NotNeeded` count as compatible.
    pub fn is_compatible_with_spec_examples(self) -> bool {
        self.alphabet != Alphabet::UrlSafe && self.padding != Padding::Omitted
    }
}

/// Why a header value could not be turned into the expected object.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    /// The value is not base64 in any of the four accepted variants.
    #[error("value is not base64 (tried standard and URL-safe alphabets, padded and unpadded)")]
    NotBase64,
    /// The decoded bytes are not UTF-8 text.
    #[error("decoded bytes are not UTF-8: {0}")]
    NotUtf8(#[from] std::string::FromUtf8Error),
    /// The decoded text is not the expected JSON object.
    #[error("decoded text is not the expected JSON object: {0}")]
    NotJson(#[from] serde_json::Error),
}

/// A successfully decoded header: the object, the variant it was encoded with and the JSON text as received.
#[derive(Debug, Clone)]
pub struct Decoded<T> {
    /// The parsed object.
    pub value: T,
    /// The base64 variant the sender used.
    pub variant: Base64Variant,
    /// The JSON text exactly as decoded, useful as evidence.
    pub json: String,
}

/// Decodes a header value into `T`, accepting any of the four base64 variants.
///
/// Surrounding ASCII whitespace is ignored, as HTTP allows it around field values.
pub fn decode_header<T: DeserializeOwned>(value: &str) -> Result<Decoded<T>, DecodeError> {
    let value = value.trim_ascii();
    let (bytes, variant) = decode_bytes(value).ok_or(DecodeError::NotBase64)?;
    let json = String::from_utf8(bytes)?;
    let value = serde_json::from_str(&json)?;
    Ok(Decoded { value, variant, json })
}

/// Encodes an object the way the specification examples do: compact JSON, standard alphabet, padded.
pub fn encode_header<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    Ok(STANDARD.encode(serde_json::to_vec(value)?))
}

fn decode_bytes(value: &str) -> Option<(Vec<u8>, Base64Variant)> {
    let alphabet = if value.contains(['-', '_']) {
        Alphabet::UrlSafe
    } else if value.contains(['+', '/']) {
        Alphabet::Standard
    } else {
        Alphabet::Indistinct
    };
    let padding = if value.ends_with('=') {
        Padding::Present
    } else if value.len().is_multiple_of(4) {
        Padding::NotNeeded
    } else {
        Padding::Omitted
    };
    let engine = match (alphabet, padding) {
        (Alphabet::UrlSafe, Padding::Omitted) => URL_SAFE_NO_PAD,
        (Alphabet::UrlSafe, _) => URL_SAFE,
        (_, Padding::Omitted) => STANDARD_NO_PAD,
        _ => STANDARD,
    };
    let bytes = engine.decode(value).ok()?;
    Some((bytes, Base64Variant { alphabet, padding }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{PaymentPayload, PaymentRequired, SettleResponse};

    /// `PAYMENT-REQUIRED` value of the HTTP transport spec, "Payment Required Signaling" example.
    const SPEC_PAYMENT_REQUIRED: &str = "eyJ4NDAyVmVyc2lvbiI6MiwiZXJyb3IiOiJQQVlNRU5ULVNJR05BVFVSRSBoZWFkZXIgaXMgcmVxdWlyZWQiLCJyZXNvdXJjZSI6eyJ1cmwiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbS9wcmVtaXVtLWRhdGEiLCJkZXNjcmlwdGlvbiI6IkFjY2VzcyB0byBwcmVtaXVtIG1hcmtldCBkYXRhIiwibWltZVR5cGUiOiJhcHBsaWNhdGlvbi9qc29uIn0sImFjY2VwdHMiOlt7InNjaGVtZSI6ImV4YWN0IiwibmV0d29yayI6ImVpcDE1NTo4NDUzMiIsImFtb3VudCI6IjEwMDAwIiwiYXNzZXQiOiIweDAzNkNiRDUzODQyYzU0MjY2MzRlNzkyOTU0MWVDMjMxOGYzZENGN2UiLCJwYXlUbyI6IjB4MjA5NjkzQmM2YWZjMEM1MzI4YkEzNkZhRjAzQzUxNEVGMzEyMjg3QyIsIm1heFRpbWVvdXRTZWNvbmRzIjo2MCwiZXh0cmEiOnsibmFtZSI6IlVTREMiLCJ2ZXJzaW9uIjoiMiJ9fV19";

    /// `PAYMENT-SIGNATURE` value of the HTTP transport spec, "Payment Payload Transmission" example.
    const SPEC_PAYMENT_SIGNATURE: &str = "eyJ4NDAyVmVyc2lvbiI6MiwicmVzb3VyY2UiOnsidXJsIjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20vcHJlbWl1bS1kYXRhIiwiZGVzY3JpcHRpb24iOiJBY2Nlc3MgdG8gcHJlbWl1bSBtYXJrZXQgZGF0YSIsIm1pbWVUeXBlIjoiYXBwbGljYXRpb24vanNvbiJ9LCJhY2NlcHRlZCI6eyJzY2hlbWUiOiJleGFjdCIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1MzIiLCJhbW91bnQiOiIxMDAwMCIsImFzc2V0IjoiMHgwMzZDYkQ1Mzg0MmM1NDI2NjM0ZTc5Mjk1NDFlQzIzMThmM2RDRjdlIiwicGF5VG8iOiIweDIwOTY5M0JjNmFmYzBDNTMyOGJBMzZGYUYwM0M1MTRFRjMxMjI4N0MiLCJtYXhUaW1lb3V0U2Vjb25kcyI6NjAsImV4dHJhIjp7Im5hbWUiOiJVU0RDIiwidmVyc2lvbiI6IjIifX0sInBheWxvYWQiOnsic2lnbmF0dXJlIjoiMHgyZDZhNzU4OGQ2YWNjYTUwNWNiZjBkOWE0YTIyN2UwYzUyYzZjMzQwMDhjOGU4OTg2YTEyODMyNTk3NjQxNzM2MDhhMmNlNjQ5NjY0MmUzNzdkNmRhOGRiYmY1ODM2ZTliZDE1MDkyZjllY2FiMDVkZWQzZDYyOTNhZjE0OGI1NzFjIiwiYXV0aG9yaXphdGlvbiI6eyJmcm9tIjoiMHg4NTdiMDY1MTlFOTFlM0E1NDUzODc5MWJEYmIwRTIyMzczZTM2YjY2IiwidG8iOiIweDIwOTY5M0JjNmFmYzBDNTMyOGJBMzZGYUYwM0M1MTRFRjMxMjI4N0MiLCJ2YWx1ZSI6IjEwMDAwIiwidmFsaWRBZnRlciI6IjE3NDA2NzIwODkiLCJ2YWxpZEJlZm9yZSI6IjE3NDA2NzIxNTQiLCJub25jZSI6IjB4ZjM3NDY2MTNjMmQ5MjBiNWZkYWJjMDg1NmYyYWViMmQ0Zjg4ZWU2MDM3YjhjYzVkMDRhNzFhNDQ2MmYxMzQ4MCJ9fX0=";

    /// `PAYMENT-RESPONSE` values of the HTTP transport spec, success and failure examples.
    const SPEC_PAYMENT_RESPONSE_OK: &str = "eyJzdWNjZXNzIjp0cnVlLCJ0cmFuc2FjdGlvbiI6IjB4MTIzNDU2Nzg5MGFiY2RlZjEyMzQ1Njc4OTBhYmNkZWYxMjM0NTY3ODkwYWJjZGVmMTIzNDU2Nzg5MGFiY2RlZiIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1MzIiLCJwYXllciI6IjB4ODU3YjA2NTE5RTkxZTNBNTQ1Mzg3OTFiRGJiMEUyMjM3M2UzNmI2NiJ9";
    const SPEC_PAYMENT_RESPONSE_FAILED: &str = "eyJzdWNjZXNzIjpmYWxzZSwiZXJyb3JSZWFzb24iOiJpbnN1ZmZpY2llbnRfZnVuZHMiLCJ0cmFuc2FjdGlvbiI6IiIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1MzIiLCJwYXllciI6IjB4ODU3YjA2NTE5RTkxZTNBNTQ1Mzg3OTFiRGJiMEUyMjM3M2UzNmI2NiJ9";

    #[test]
    fn decodes_the_spec_payment_required_example() {
        let decoded = decode_header::<PaymentRequired>(SPEC_PAYMENT_REQUIRED).unwrap();
        assert_eq!(
            decoded.variant.alphabet,
            Alphabet::Indistinct,
            "the example uses none of + / - _"
        );
        assert_eq!(
            decoded.variant.padding,
            Padding::NotNeeded,
            "the example happens to need no padding"
        );
        let required = decoded.value;
        assert_eq!(required.x402_version, 2);
        assert_eq!(
            required.error.as_deref(),
            Some("PAYMENT-SIGNATURE header is required")
        );
        assert_eq!(required.resource.url, "https://api.example.com/premium-data");
        assert_eq!(required.accepts.len(), 1);
        let offer = &required.accepts[0];
        assert_eq!(offer.scheme, "exact");
        assert_eq!(offer.network, "eip155:84532");
        assert_eq!(offer.amount, "10000");
        assert_eq!(offer.max_timeout_seconds.as_u64(), Some(60));
        assert_eq!(offer.extra["name"], "USDC");
    }

    #[test]
    fn decodes_the_spec_payment_signature_example() {
        let decoded = decode_header::<PaymentPayload>(SPEC_PAYMENT_SIGNATURE).unwrap();
        assert_eq!(
            decoded.variant,
            Base64Variant {
                alphabet: Alphabet::Indistinct,
                padding: Padding::Present
            }
        );
        let payload = decoded.value;
        assert_eq!(
            payload.accepted.pay_to,
            "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
        );
        assert_eq!(payload.payload["authorization"]["value"], "10000");
        assert_eq!(
            payload.payload["authorization"]["nonce"].as_str().unwrap().len(),
            66
        );
    }

    #[test]
    fn decodes_both_spec_payment_response_examples() {
        let ok = decode_header::<SettleResponse>(SPEC_PAYMENT_RESPONSE_OK)
            .unwrap()
            .value;
        assert!(ok.success);
        assert_eq!(ok.transaction.len(), 66);
        assert!(ok.error_reason.is_none());

        let failed = decode_header::<SettleResponse>(SPEC_PAYMENT_RESPONSE_FAILED)
            .unwrap()
            .value;
        assert!(!failed.success);
        assert_eq!(failed.error_reason.as_deref(), Some("insufficient_funds"));
        assert_eq!(
            failed.transaction, "",
            "no transaction broadcast means an empty string"
        );
    }

    #[test]
    fn round_trips_through_the_example_variant() {
        let required = decode_header::<PaymentRequired>(SPEC_PAYMENT_REQUIRED)
            .unwrap()
            .value;
        let encoded = encode_header(&required).unwrap();
        let again = decode_header::<PaymentRequired>(&encoded).unwrap();
        assert_eq!(again.value, required);
        assert!(again.variant.is_compatible_with_spec_examples());
    }

    #[test]
    fn accepts_url_safe_and_unpadded_input_and_reports_it() {
        // "~~~" encodes to "fn5+" in the standard alphabet and "fn5-" in the URL-safe one, so the two can be told apart.
        let mut required = decode_header::<PaymentRequired>(SPEC_PAYMENT_REQUIRED)
            .unwrap()
            .value;
        required.error = Some("~~~".into());
        let json = serde_json::to_vec(&required).unwrap();
        let url_safe = URL_SAFE_NO_PAD.encode(&json);
        let decoded = decode_header::<PaymentRequired>(&url_safe).unwrap();
        assert_eq!(decoded.value, required);
        assert_eq!(decoded.variant.alphabet, Alphabet::UrlSafe);
        assert!(!decoded.variant.is_compatible_with_spec_examples());
    }

    #[test]
    fn tells_the_alphabets_apart_when_the_bytes_allow_it() {
        let bytes = [0xfb, 0xff, 0xbf];
        let (_, standard) = decode_bytes(&STANDARD.encode(bytes)).unwrap();
        assert_eq!(
            standard,
            Base64Variant {
                alphabet: Alphabet::Standard,
                padding: Padding::NotNeeded
            }
        );
        let (_, url_safe) = decode_bytes(&URL_SAFE.encode(bytes)).unwrap();
        assert_eq!(
            url_safe,
            Base64Variant {
                alphabet: Alphabet::UrlSafe,
                padding: Padding::NotNeeded
            }
        );
        assert!(!url_safe.is_compatible_with_spec_examples());
        let (_, unpadded) = decode_bytes(&STANDARD_NO_PAD.encode([0xfb, 0xff])).unwrap();
        assert_eq!(unpadded.padding, Padding::Omitted);
    }

    #[test]
    fn names_each_failure_mode() {
        assert!(matches!(
            decode_header::<PaymentRequired>("not base64!"),
            Err(DecodeError::NotBase64)
        ));
        let not_json = STANDARD.encode(b"plain text");
        assert!(matches!(
            decode_header::<PaymentRequired>(&not_json),
            Err(DecodeError::NotJson(_))
        ));
        let wrong_shape = STANDARD.encode(b"{\"x402Version\":2}");
        assert!(matches!(
            decode_header::<PaymentRequired>(&wrong_shape),
            Err(DecodeError::NotJson(_))
        ));
    }
}
