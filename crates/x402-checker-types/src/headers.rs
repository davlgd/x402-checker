//! Header names of the HTTP transport (`spec/transports-v2_http.md`, "Header Summary") and of the facilitator
//! sidechannel (core spec, section 7.2.1).
//!
//! HTTP header names are case-insensitive; the spec writes them in upper case and so do we. Compare with
//! `eq_ignore_ascii_case` or through an HTTP library that normalises names.

/// Server to client: base64-encoded `PaymentRequired` object, on a 402 response.
pub const PAYMENT_REQUIRED: &str = "PAYMENT-REQUIRED";

/// Client to server: base64-encoded `PaymentPayload` object.
pub const PAYMENT_SIGNATURE: &str = "PAYMENT-SIGNATURE";

/// Server to client: base64-encoded `SettleResponse` object, after a settlement attempt.
pub const PAYMENT_RESPONSE: &str = "PAYMENT-RESPONSE";

/// Facilitator to resource server only: base64-encoded JSON object keyed by extension name. Never forwarded to
/// the client (core spec, section 7.2.1).
pub const EXTENSION_RESPONSES: &str = "EXTENSION-RESPONSES";

/// The three headers that carry protocol data between a client and a resource server.
pub const CLIENT_FACING: [&str; 3] = [PAYMENT_REQUIRED, PAYMENT_SIGNATURE, PAYMENT_RESPONSE];

/// Request or response headers whose value is a credential, hence never kept in a report.
pub const SECRET_HEADERS: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "x-secret-key",
    "x-auth-token",
];

/// JWT members a report may keep: what describes a token, never what it carries about anyone.
const JWT_HEADER_KEPT: [&str; 3] = ["alg", "kid", "typ"];
const JWT_CLAIMS_KEPT: [&str; 4] = ["iss", "uris", "exp", "nbf"];

/// The value of a header as a report may keep it. Names outside [`SECRET_HEADERS`] pass unchanged. An
/// `Authorization` (or proxy) value keeps its scheme when it has one; a Bearer JWT additionally keeps a filtered copy
/// of its header and claims (algorithm, key id, issuer, `uris`, validity), re-encoded, with no signature. Every other
/// secret header is replaced entirely.
pub fn redact(name: &str, value: &str) -> String {
    let name = name.to_ascii_lowercase();
    if !SECRET_HEADERS.contains(&name.as_str()) {
        return value.to_owned();
    }
    if name != "authorization" && name != "proxy-authorization" {
        return "<redacted>".to_owned();
    }
    let mut words = value.splitn(2, ' ');
    let scheme = words.next().unwrap_or_default();
    let token = words.next().unwrap_or_default();
    let has_scheme =
        !scheme.is_empty() && !token.is_empty() && scheme.bytes().all(|b| b.is_ascii_alphabetic());
    if !has_scheme {
        return "<redacted>".to_owned();
    }
    if scheme.eq_ignore_ascii_case("bearer")
        && let Some(summary) = jwt_summary(token)
    {
        return format!("{scheme} {summary}");
    }
    format!("{scheme} <redacted>")
}

/// `header.claims.<signature redacted>` with only the kept members, or `None` when the token is not a JWS.
fn jwt_summary(token: &str) -> Option<String> {
    use base64::Engine as _;
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let filtered = |part: &str, kept: &[&str]| -> Option<String> {
        let json: serde_json::Value = serde_json::from_slice(&engine.decode(part).ok()?).ok()?;
        let object = json.as_object()?;
        let kept: serde_json::Map<String, serde_json::Value> = object
            .iter()
            .filter(|(k, _)| kept.contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        Some(engine.encode(serde_json::to_vec(&serde_json::Value::Object(kept)).ok()?))
    };
    Some(format!(
        "{}.{}.<signature redacted>",
        filtered(parts[0], &JWT_HEADER_KEPT)?,
        filtered(parts[1], &JWT_CLAIMS_KEPT)?
    ))
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
        assert!(kept.starts_with("Bearer ") && kept.ends_with(".<signature redacted>"));
        let parts: Vec<&str> = kept.trim_start_matches("Bearer ").split('.').collect();
        let claims_kept: serde_json::Value =
            serde_json::from_slice(&engine.decode(parts[1]).unwrap()).unwrap();
        assert!(
            claims_kept.get("uris").is_some()
                && claims_kept.get("email").is_none()
                && claims_kept.get("sub").is_none()
        );
        let header_kept: serde_json::Value =
            serde_json::from_slice(&engine.decode(parts[0]).unwrap()).unwrap();
        assert!(header_kept.get("alg").is_some() && header_kept.get("nonce").is_none());
        assert_eq!(redact("Authorization", "Bearer opaque"), "Bearer <redacted>");
        assert_eq!(redact("authorization", "raw-token-without-scheme"), "<redacted>");
        assert_eq!(redact("x-api-key", "k-123"), "<redacted>");
        assert_eq!(redact("Set-Cookie", "session=abc"), "<redacted>");
        assert_eq!(redact("content-type", "application/json"), "application/json");
        assert_eq!(redact("PAYMENT-SIGNATURE", "eyJ4"), "eyJ4");
    }
}
