//! `probe`: what can be said about a resource server without funds and without its cooperation.
//!
//! One unpaid request, then a series of deliberately unusable `PAYMENT-SIGNATURE` values. Nothing here can move
//! money: the only structurally valid payment sent carries a signature of 65 zero bytes.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};
use x402_checker_evm::{AuthorizationParams, Eip3009Offer, Payer};
use x402_checker_types::codec::decode_header;
use x402_checker_types::{Caip2, PaymentRequirements, error_codes, headers};

use super::{decimal_integer, extensions, member, printable_ascii, short};
use crate::check::{Attribution, Check, Finding, Level, Source, SuiteResult, judge};
use crate::http::Exchange;
use crate::target::Context;

mod offers;

use offers::{json_kind, offer_checks, resource_bounds};

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

const HTTP_01: Check = check(
    "HTTP-001",
    "an unpaid request is answered with status 402",
    Level::Required,
    Source::Prose,
    "transports-v2/http.md, Payment Required Signaling: \"The server indicates payment is required using the HTTP 402\"",
);

const HTTP_02: Check = check(
    "HTTP-002",
    "the 402 carries a PAYMENT-REQUIRED header",
    Level::Required,
    Source::Prose,
    "transports-v2/http.md: \"HTTP 402 status code with PAYMENT-REQUIRED header\", \"the canonical HTTP transport location\"",
);

const HTTP_03: Check = with_note(
    check(
        "HTTP-003",
        "PAYMENT-REQUIRED is base64 of a JSON object",
        Level::Required,
        Source::Prose,
        "transports-v2/http.md: \"Base64-encoded PaymentRequired schema in header\"",
    ),
    "the spec never names the base64 alphabet or padding; the tool accepts standard and URL-safe, padded or not",
);

const HTTP_03_VARIANT: Check = check(
    "HTTP-003v",
    "the base64 variant matches the spec examples (standard alphabet, padded)",
    Level::Optional,
    Source::Example,
    "transports-v2/http.md examples use the standard alphabet with = padding",
);

const CORE_5_1_02: Check = check(
    "CORE-002",
    "PaymentRequired.x402Version is the number 2",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.1.2: x402Version, number, Required, \"must be 2\"",
);

const CORE_5_1_03: Check = check(
    "CORE-003",
    "PaymentRequired.error, when present, is a string",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.1.2: error, string, Optional",
);

const CORE_5_1_04: Check = check(
    "CORE-004",
    "PaymentRequired.resource is an object with a string url",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.1.2: resource, object, Required; ResourceInfo.url, string, Required",
);

const CORE_5_1_14: Check = with_note(
    check(
        "CORE-014",
        "resource.url designates the requested resource",
        Level::Optional,
        Source::Prose,
        "x402-specification-v2.md 5.1.2: url, \"URL of the protected resource\"",
    ),
    "the spec does not say whether url must equal the request URL byte for byte; the tool reports the relation",
);

const CORE_5_1_05: Check = check(
    "CORE-005",
    "PaymentRequired.accepts is an array",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.1.2: accepts, array, Required",
);

const CORE_5_1_05_EMPTY: Check = with_note(
    check(
        "CORE-005e",
        "accepts offers at least one payment method",
        Level::Recommended,
        Source::Prose,
        "x402-specification-v2.md 5.1.2: \"Array of payment requirement objects defining acceptable payment methods\"",
    ),
    "the text does not forbid an empty array; a 402 without any offer cannot be paid, so the tool warns",
);

const CORE_5_1_06: Check = check(
    "CORE-006",
    "PaymentRequired.extensions, when present, is an object",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.1.2: extensions, object, Optional",
);

const CORE_5_1_07: Check = check(
    "CORE-007",
    "every accepts[] entry has scheme, network, amount, asset, payTo (strings) and maxTimeoutSeconds (number)",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.1.2: PaymentRequirements table, all six Required; extra, object, Optional",
);

const CORE_5_1_08: Check = check(
    "CORE-008",
    "every accepts[].network is a CAIP-2 identifier",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.1.2: network, \"Blockchain network identifier in CAIP-2 format\"; 11.1 \"{namespace}:{reference}\"",
);

const CORE_5_1_09: Check = with_note(
    check(
        "CORE-009",
        "every accepts[].amount is a decimal integer string of atomic units",
        Level::Required,
        Source::FieldTable,
        "x402-specification-v2.md 5.1.2: amount, string, \"Required payment amount in atomic token units\"",
    ),
    "no grammar is given; a non-negative decimal integer is the only reading consistent with the examples",
);

const CORE_5_1_13: Check = check(
    "CORE-042",
    "reserved extra keys carry their section 6.1 meaning: paymentFlow is authorization, upfront or escrow; assetTransferMethod is a string",
    Level::Required,
    Source::ExplicitMust,
    "x402-specification-v2.md 6.1: \"clients and servers MUST interpret them as defined here\"; flow table",
);

const CORE_5_1_16: Check = check(
    "CORE-016",
    "ResourceInfo optional fields respect their bounds (serviceName, tags, iconUrl, description, mimeType)",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.1.2: serviceName printable ASCII max 32; tags max 5, each printable ASCII max 32; iconUrl absolute http(s) max 2048",
);

const CORE_5_1_19: Check = check(
    "CORE-019",
    "every advertised extension is an object with info and schema objects",
    Level::Required,
    Source::FieldTable,
    "x402-specification-v2.md 5.1.2: Extensions table, info object Required, schema object Required",
);

const EVM_EXTRA: Check = check(
    "EVM-012",
    "exact offers on eip155 networks carry extra.name and extra.version (EIP-712 domain of the token)",
    Level::Required,
    Source::Prose,
    "schemes/exact/scheme_exact_evm.md 1: \"extra.name (required)\", \"extra.version (required)\" for eip3009",
);

const EVM_ADDRESSES: Check = check(
    "CORE-010e",
    "exact offers on eip155 networks have 20-byte hex asset and payTo addresses",
    Level::Required,
    Source::Prose,
    "x402-specification-v2.md 5.1.2: asset \"Token contract address\", payTo \"Recipient wallet address\"; EVM binding uses them as contract and recipient",
);

const EVM_METHODS: Check = check(
    "EVM-004i",
    "asset transfer methods offered on eip155 networks",
    Level::Optional,
    Source::Prose,
    "schemes/exact/scheme_exact_evm.md: eip3009 (default), permit2, erc7710",
);

const SVM_FEE_PAYER: Check = check(
    "SVM-001",
    "exact offers on solana networks carry extra.feePayer, the sponsor's public key",
    Level::Required,
    Source::Prose,
    "schemes/exact/scheme_exact_svm.md, Protocol Flow 2: \"The extra field contains a feePayer, identifying the sponsor\"; PaymentRequirements: \"requires the following inside the extra field\"",
);

const SVM_ADDRESSES: Check = check(
    "SVM-004",
    "exact offers on solana networks have base58 32-byte asset (mint) and payTo (merchant) public keys",
    Level::Required,
    Source::Prose,
    "schemes/exact/scheme_exact_svm.md, PaymentRequirements: \"asset: The public key of the token mint\", \"payTo: The merchant's public key\"; external basis: Solana public keys and program-derived addresses are 32 bytes, written in base58",
);

const SVM_HINTS: Check = with_note(
    check(
        "SVM-002",
        "the optional extra hints of exact on solana are well formed when present: memo (UTF-8, 256 bytes max), recentBlockhash (base58 32 bytes), lastValidBlockHeight (decimal string)",
        Level::Recommended,
        Source::Prose,
        "schemes/exact/scheme_exact_svm.md, PaymentRequirements: memo \"Maximum 256 bytes\"; recentBlockhash \"A recent blockhash\"; lastValidBlockHeight \"as a decimal string\"",
    ),
    "the fields are optional and only their shape when present is looked at; the spec gives the client a fallback for a malformed blockhash and lets everyone ignore the height, so a bad hint is a warning, not a failure",
);

const SVM_FLOW: Check = check(
    "SVM-003",
    "payment flow offered on solana networks",
    Level::Optional,
    Source::Prose,
    "schemes/exact/scheme_exact_svm.md, Protocol Flow: \"Resource servers with long-running handlers SHOULD use payment flow upfront, because under authorization the handler must complete before the signed transaction's blockhash expires\"",
);

const HTTP_08: Check = check(
    "HTTP-009",
    "the 402 body (free for the server to choose)",
    Level::Optional,
    Source::Prose,
    "transports-v2/http.md, Response Body: \"Response bodies are a server implementation concern\"",
);

const STABLE_TERMS: Check = check(
    "PROBE-STABLE",
    "two consecutive unpaid requests receive the same accepts[]",
    Level::Optional,
    Source::Prose,
    "not a spec clause; a client that reads the terms then pays relies on it",
);

const HTTP_09_NOT_SERVED: Check = check(
    "HTTP-010",
    "a malformed PAYMENT-SIGNATURE never gets the resource (no 2xx) and is not a server error (no 5xx)",
    Level::Required,
    Source::FieldTable,
    "transports-v2/http.md, Error Handling: Invalid Payment 400 \"Malformed payment payload\"; Payment Failed 402; Server Error 500 \"during payment processing\"",
);

const HTTP_09_STATUS: Check = with_note(
    check(
        "HTTP-010s",
        "a malformed PAYMENT-SIGNATURE is answered with status 400",
        Level::Recommended,
        Source::FieldTable,
        "transports-v2/http.md, Error Handling: \"Invalid Payment | 400 | Malformed payment payload or requirements\"",
    ),
    "the same table maps Payment Failed to 402, so a 402 with a fresh challenge is defensible; the tool warns rather than fails",
);

const V1_PAYLOAD: Check = with_note(
    check(
        "PROBE-V1",
        "how a payload marked x402Version 1 is treated",
        Level::Optional,
        Source::Policy,
        "x402-specification-v2.md 5.2.2: x402Version Required; a v2 server may also keep accepting v1 payloads for compatibility, which the v2 text neither requires nor forbids",
    ),
    "not judged: the core text makes x402Version an identifier and invalid_x402_version a code for an unsupported version, without forbidding an endpoint that serves several versions; what happened is reported",
);

const CORE_6_1_09: Check = check(
    "CORE-054z",
    "a payment that cannot be valid (zero signature) never yields the resource",
    Level::Required,
    Source::ExplicitMust,
    "x402-specification-v2.md 6.1: \"at least one check ... MUST run before the resource executes. The resource never executes with nothing checked\"",
);

const CORE_9_01: Check = check(
    "CORE-070",
    "error reasons given on refusals",
    Level::Optional,
    Source::Prose,
    "x402-specification-v2.md 9: standard codes \"may be returned by facilitators or resource servers\"",
);

const CORS_EXPOSE: Check = check(
    "PROBE-CORS",
    "browser clients can read the x402 headers (Access-Control-Expose-Headers)",
    Level::Optional,
    Source::Prose,
    "not a spec clause; needed only by browser clients",
);

/// Runs the probe suite.
pub async fn run(ctx: &mut Context) -> SuiteResult {
    let mut findings = Vec::new();
    let Some((first, exchange, pr)) = payment_required_signal(ctx, &mut findings).await else {
        return SuiteResult::new("probe", findings);
    };
    let ev = [first];
    findings.extend(payment_required_checks(&pr, ctx.target.url.as_str(), &ev));

    let accepts = member(&pr, "accepts");
    findings.push(judge(
        &CORE_5_1_05,
        accepts.is_some_and(Value::is_array),
        format!("accepts is {}", accepts.map_or("absent", json_kind)),
        &ev,
    ));
    let offers: Vec<Value> = accepts.and_then(Value::as_array).cloned().unwrap_or_default();
    findings.push(judge(
        &CORE_5_1_05_EMPTY,
        !offers.is_empty(),
        format!("{} offer(s)", offers.len()),
        &ev,
    ));
    if !offers.is_empty() {
        findings.extend(offer_checks(&offers, &ev));
    }
    findings.push(Finding::info(&HTTP_08, body_description(&exchange), &ev));
    findings.push(Finding::info(&CORS_EXPOSE, cors_description(&exchange), &ev));
    if let Some(finding) = stable_terms(ctx, first, &offers).await {
        findings.push(finding);
    }

    // Malformed payment headers: nothing here can be settled.
    let typed_offers: Vec<PaymentRequirements> = offers
        .iter()
        .filter_map(|o| serde_json::from_value(o.clone()).ok())
        .collect();
    findings.extend(malformed_signature_checks(ctx, typed_offers.first()).await);
    if let Some(finding) = v1_payload_check(ctx, typed_offers.first()).await {
        findings.push(finding);
    }
    findings.push(zero_signature_check(ctx, &typed_offers).await);

    SuiteResult::new("probe", findings)
}

/// The unpaid request and the checks that gate everything else: no credential wall or redirect in the way, a v2
/// 402, a `PAYMENT-REQUIRED` header, a decodable header. Returns the exchange index, the exchange and the decoded
/// `PaymentRequired` as raw JSON, or `None` when there is nothing more to inspect.
async fn payment_required_signal(
    ctx: &mut Context,
    findings: &mut Vec<Finding>,
) -> Option<(usize, Exchange, Value)> {
    let first = match ctx.client.send("unpaid request", ctx.resource_request(&[])).await {
        Ok(index) => index,
        Err(error) => {
            findings.push(Finding::cannot_assess(
                &HTTP_01,
                format!("the target could not be reached: {error}"),
                &[],
            ));
            return None;
        }
    };
    let exchange = ctx.client.exchange(first).clone();
    let ev = [first];
    let raw = exchange.header(headers::PAYMENT_REQUIRED).map(str::to_owned);

    // out of scope before any verdict: a credential wall, a redirect, or a server that only speaks v1
    let body_version = exchange
        .body_json()
        .and_then(|b| member(&b, "x402Version").and_then(Value::as_f64));
    let out_of_scope = match exchange.status {
        401 | 403 => Some(format!("status {}: a credential wall; pass the credentials with --header", exchange.status)),
        300..=399 => Some(format!("status {} redirecting to {}: run the tool against the final URL", exchange.status, exchange.header("location").unwrap_or("an unknown location"))),
        402 if raw.is_none() && body_version == Some(1.0) => Some("402 without PAYMENT-REQUIRED and a body with x402Version 1: the target speaks x402 v1 only, which this tool does not judge".to_owned()),
        _ => None,
    };
    if let Some(why) = out_of_scope {
        findings.push(Finding::cannot_assess(&HTTP_01, why.clone(), &ev));
        findings.push(Finding::cannot_assess(&HTTP_02, why, &ev));
        return None;
    }

    findings.push(judge(
        &HTTP_01,
        exchange.status == 402,
        format!("status {}", exchange.status),
        &ev,
    ));
    let Some(raw) = raw else {
        if exchange.status == 402 {
            findings.push(Finding::fail(
                &HTTP_02,
                "402 without a PAYMENT-REQUIRED header",
                &ev,
            ));
        } else {
            findings.push(Finding::skip(&HTTP_02, "no 402 to inspect"));
        }
        findings.push(Finding::info(&HTTP_08, body_description(&exchange), &ev));
        return None;
    };
    findings.push(Finding::pass(&HTTP_02, "header present", &ev));

    let decoded = match decode_header::<Value>(&raw) {
        Ok(decoded) if decoded.value.is_object() => decoded,
        Ok(decoded) => {
            findings.push(Finding::fail(
                &HTTP_03,
                format!("decodes to JSON but not to an object: {}", short(&decoded.json)),
                &ev,
            ));
            return None;
        }
        Err(error) => {
            findings.push(Finding::fail(
                &HTTP_03,
                format!("{error}; value starts with {:?}", short(&raw)),
                &ev,
            ));
            return None;
        }
    };
    findings.push(Finding::pass(
        &HTTP_03,
        format!("{} bytes of JSON", decoded.json.len()),
        &ev,
    ));
    findings.push(judge(
        &HTTP_03_VARIANT,
        decoded.variant.is_compatible_with_spec_examples(),
        format!(
            "alphabet {:?}, padding {:?}",
            decoded.variant.alphabet, decoded.variant.padding
        ),
        &ev,
    ));
    Some((first, exchange, decoded.value))
}

/// The `PaymentRequired` object field by field, on the raw JSON so that one bad field hides no other.
fn payment_required_checks(pr: &Value, requested: &str, ev: &[usize]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.push(judge(
        &CORE_5_1_02,
        member(pr, "x402Version").is_some_and(|v| v.as_f64() == Some(2.0)),
        format!(
            "x402Version = {}",
            member(pr, "x402Version").map_or("absent".into(), Value::to_string)
        ),
        ev,
    ));
    if let Some(error) = member(pr, "error") {
        findings.push(judge(
            &CORE_5_1_03,
            error.is_string(),
            format!("error = {}", short(&error.to_string())),
            ev,
        ));
    }
    let resource = member(pr, "resource");
    let url = resource.and_then(|r| member(r, "url")).and_then(Value::as_str);
    findings.push(judge(
        &CORE_5_1_04,
        resource.is_some_and(Value::is_object) && url.is_some(),
        format!(
            "resource = {}",
            resource.map_or("absent".into(), |r| short(&r.to_string()))
        ),
        ev,
    ));
    if let Some(url) = url {
        let relation = if url == requested {
            "equals the request URL"
        } else if url.trim_end_matches('/') == requested.trim_end_matches('/') {
            "equals the request URL up to a trailing slash"
        } else if requested.starts_with(url) || url.starts_with(requested) {
            "is a prefix or an extension of the request URL"
        } else {
            "differs from the request URL"
        };
        findings.push(Finding::info(
            &CORE_5_1_14,
            format!("resource.url {relation}: {url}"),
            ev,
        ));
    }
    if let Some(resource) = resource.filter(|r| r.is_object()) {
        findings.push(resource_bounds(resource, ev));
    }
    if let Some(extensions) = member(pr, "extensions") {
        findings.push(judge(
            &CORE_5_1_06,
            extensions.is_object(),
            format!("extensions is {}", json_kind(extensions)),
            ev,
        ));
        if let Some(map) = extensions.as_object() {
            let bad: Vec<_> = map
                .iter()
                .filter(|(_, v)| {
                    !(member(v, "info").is_some_and(Value::is_object)
                        && member(v, "schema").is_some_and(Value::is_object))
                })
                .map(|(k, _)| k.clone())
                .collect();
            let names: Vec<_> = map.keys().cloned().collect();
            let detail = if names.is_empty() {
                "no extension advertised".to_owned()
            } else if bad.is_empty() {
                format!("advertised: {}", names.join(", "))
            } else {
                format!("missing info or schema object: {}", bad.join(", "))
            };
            findings.push(judge(&CORE_5_1_19, bad.is_empty(), detail, ev));
        }
        findings.extend(extensions::declaration_checks(extensions, resource, ev));
    }
    findings
}

fn cors_description(exchange: &Exchange) -> String {
    match exchange.header("access-control-expose-headers") {
        Some(v) if v.to_ascii_lowercase().contains("payment-required") => format!("exposed: {v}"),
        Some(v) => format!("header present but PAYMENT-REQUIRED not listed: {v}"),
        None => "no Access-Control-Expose-Headers on the 402 (only matters for browser clients)".to_owned(),
    }
}

/// A second unpaid request: are the terms stable?
async fn stable_terms(ctx: &mut Context, first: usize, offers: &[Value]) -> Option<Finding> {
    let second = ctx
        .client
        .send("unpaid request, again", ctx.resource_request(&[]))
        .await
        .ok()?;
    let again = ctx.client.exchange(second).payment_required().map(|p| p.accepts);
    let typed: Option<Vec<PaymentRequirements>> = serde_json::from_value(Value::Array(offers.to_vec())).ok();
    let detail = if again.is_some() && again == typed {
        "same accepts[] on both requests"
    } else {
        "accepts[] differ between two unpaid requests (dynamic pricing or per-request data)"
    };
    Some(Finding::info(&STABLE_TERMS, detail, &[first, second]))
}

/// The `PAYMENT-SIGNATURE` values a server must refuse without serving anything: not base64, not JSON, not the
/// object, an `accepted` matching no offer, an unknown scheme.
fn malformed_cases(offer: Option<&PaymentRequirements>) -> Vec<(&'static str, String)> {
    let mut cases: Vec<(&str, String)> = vec![
        ("not base64", "this is not base64!".to_owned()),
        ("base64 of plain text", STANDARD.encode("plain text")),
        ("base64 of an empty object", STANDARD.encode("{}")),
    ];
    if let Some(offer) = offer {
        let offer_json = serde_json::to_value(offer).unwrap_or_default();
        let payload = |accepted: Value, version: u64| {
            STANDARD.encode(json!({ "x402Version": version, "accepted": accepted, "payload": { "signature": "0x00", "authorization": {} } }).to_string())
        };
        let mut other_amount = offer_json.clone();
        if let Some(o) = other_amount.as_object_mut() {
            o.insert("amount".into(), json!(format!("{}1", offer.amount)));
        }
        cases.push((
            "accepted matching no offer (amount changed)",
            payload(other_amount, 2),
        ));
        let mut other_scheme = offer_json;
        if let Some(o) = other_scheme.as_object_mut() {
            o.insert("scheme".into(), json!("no-such-scheme"));
        }
        cases.push(("unknown scheme", payload(other_scheme, 2)));
    }
    cases
}

/// A structurally v2 payload marked `x402Version: 1` (with an unusable signature): what the server answers is
/// reported, nothing is judged (see `PROBE-V1`). The observation does not tell whether the server speaks v1 or
/// where it validates.
async fn v1_payload_check(ctx: &mut Context, offer: Option<&PaymentRequirements>) -> Option<Finding> {
    let offer = offer?;
    let header = STANDARD.encode(json!({ "x402Version": 1, "accepted": offer, "payload": { "signature": "0x00", "authorization": {} } }).to_string());
    let request = ctx.resource_request(&[(headers::PAYMENT_SIGNATURE, header.as_str())]);
    let what = match ctx.client.send("payload marked x402Version 1", request).await {
        Ok(index) => {
            let exchange = ctx.client.exchange(index);
            let text = if exchange.is_success() {
                format!(
                    "status {} for a payload marked version 1; version support and validation path not established from the HTTP exchange alone",
                    exchange.status
                )
            } else {
                format!(
                    "status {}{}",
                    exchange.status,
                    refusal_reason(exchange)
                        .map(|r| format!(", reason {r}"))
                        .unwrap_or_default()
                )
            };
            return Some(Finding::info(&V1_PAYLOAD, text, &[index]));
        }
        Err(error) => format!("not observed: {error}"),
    };
    Some(Finding::cannot_assess(&V1_PAYLOAD, what, &[]))
}

async fn malformed_signature_checks(ctx: &mut Context, offer: Option<&PaymentRequirements>) -> Vec<Finding> {
    let cases = malformed_cases(offer);
    let (mut served, mut served_ev) = (Vec::new(), Vec::new());
    let (mut not_400, mut not_400_ev) = (Vec::new(), Vec::new());
    let mut failed = Vec::new();
    let mut reasons = Vec::new();
    let mut completed = 0usize;
    for (name, value) in &cases {
        let request = ctx.resource_request(&[(headers::PAYMENT_SIGNATURE, value.as_str())]);
        match ctx
            .client
            .send(format!("malformed PAYMENT-SIGNATURE: {name}"), request)
            .await
        {
            Ok(index) => {
                completed += 1;
                let exchange = ctx.client.exchange(index);
                if exchange.is_success() || exchange.status >= 500 {
                    served.push(format!("{name} -> {}", exchange.status));
                    served_ev.push(index);
                }
                if exchange.status != 400 {
                    not_400.push(format!("{name} -> {}", exchange.status));
                    not_400_ev.push(index);
                }
                if let Some(reason) = refusal_reason(exchange) {
                    reasons.push(format!(
                        "{name}: {reason}{}",
                        if error_codes::is_standard(&reason) {
                            " (standard)"
                        } else {
                            ""
                        }
                    ));
                }
            }
            Err(error) => failed.push(format!("{name}: {error}")),
        }
    }
    if completed == 0 {
        let why = format!("no malformed request completed: {}", failed.join("; "));
        return vec![
            Finding::blocked(&HTTP_09_NOT_SERVED, Attribution::Dependency, why.clone(), &[]),
            Finding::skip(&HTTP_09_STATUS, why),
        ];
    }
    let suffix = if failed.is_empty() {
        String::new()
    } else {
        format!("; not completed: {}", failed.join("; "))
    };
    vec![
        judge(
            &HTTP_09_NOT_SERVED,
            served.is_empty(),
            if served.is_empty() {
                format!("{completed} malformed values, none served, none 5xx{suffix}")
            } else {
                format!("{}{suffix}", served.join("; "))
            },
            &served_ev,
        ),
        judge(
            &HTTP_09_STATUS,
            not_400.is_empty(),
            if not_400.is_empty() {
                format!("all {completed} answered 400{suffix}")
            } else {
                format!("{}{suffix}", not_400.join("; "))
            },
            &not_400_ev,
        ),
        Finding::info(
            &CORE_9_01,
            if reasons.is_empty() {
                "no machine-readable reason found in PAYMENT-REQUIRED.error or in a JSON body `error` member"
                    .to_owned()
            } else {
                reasons.join("; ")
            },
            &[],
        ),
    ]
}

async fn zero_signature_check(ctx: &mut Context, offers: &[PaymentRequirements]) -> Finding {
    let Some((offer, evm)) = offers
        .iter()
        .find_map(|o| Eip3009Offer::from_requirements(o).ok().map(|e| (o, e)))
    else {
        return Finding::cannot_assess(
            &CORE_6_1_09,
            "no exact eip3009 offer on an eip155 network: the tool cannot build a structurally valid payment",
            &[],
        );
    };
    let now = jiff::Timestamp::now().as_second().max(0).unsigned_abs();
    let payer = Payer::random();
    let mut payload = payer.sign(&evm, &AuthorizationParams::honest(&evm, now, 300));
    payload.signature = format!("0x{}", "00".repeat(65));
    let body = json!({ "x402Version": 2, "accepted": offer, "payload": payload.to_value() });
    let header = STANDARD.encode(body.to_string());
    let request = ctx.resource_request(&[(headers::PAYMENT_SIGNATURE, header.as_str())]);
    match ctx
        .client
        .send("well-formed payment with a zero signature", request)
        .await
    {
        Ok(index) => {
            let exchange = ctx.client.exchange(index);
            let receipt_success = exchange.payment_response().is_some_and(|r| r.success);
            if exchange.is_success() && receipt_success {
                Finding::blocked(
                    &CORE_6_1_09,
                    Attribution::Unknown,
                    format!(
                        "status {} with a success receipt: either the server skipped verification or its facilitator accepted a zero signature; the headers alone do not tell which",
                        exchange.status
                    ),
                    &[index],
                )
            } else {
                judge(
                    &CORE_6_1_09,
                    !exchange.is_success(),
                    format!(
                        "status {}{} (an HTTP refusal; whether the backend ran is not observable from here)",
                        exchange.status,
                        refusal_reason(exchange)
                            .map(|r| format!(", reason {r}"))
                            .unwrap_or_default()
                    ),
                    &[index],
                )
            }
        }
        Err(error) => Finding::blocked(
            &CORE_6_1_09,
            Attribution::Dependency,
            format!("transport error: {error}"),
            &[],
        ),
    }
}

fn refusal_reason(exchange: &Exchange) -> Option<String> {
    if let Some(pr) = exchange.payment_required()
        && let Some(error) = pr.error
    {
        return Some(error);
    }
    exchange
        .body_json()
        .and_then(|b| member(&b, "error").and_then(Value::as_str).map(str::to_owned))
}

fn body_description(exchange: &Exchange) -> String {
    format!(
        "{} bytes{}, content-type {}",
        exchange.body.text.len(),
        if exchange.body.truncated { "+" } else { "" },
        exchange.header("content-type").unwrap_or("absent")
    )
}
