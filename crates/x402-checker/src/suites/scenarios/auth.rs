//! How the server authenticates to its facilitator, as observed on the scripted one: outside the protocol, hence
//! an information, never a verdict.

use super::*;

const FACILITATOR_AUTH: Check = check(
    "SCN-FACILITATOR-AUTH",
    "how the server authenticates to its facilitator",
    Level::Optional,
    Source::Policy,
    "outside the protocol: x402 does not define facilitator authentication; providers such as the Coinbase facilitator require a signed JWT per call. Decoded, never verified: the signature is not in the trace",
);

/// How the server authenticates to its facilitator, as seen on the first verify call: outside the protocol, hence
/// an observation; a Bearer JWT is summarised (algorithm, key id, `uris`, lifetime) without being checked.
pub(super) fn facilitator_auth_finding(calls: &[Call], ev: &[usize]) -> Finding {
    let Some(call) = first(calls, Endpoint::Verify).or_else(|| first(calls, Endpoint::Settle)) else {
        return Finding::info(&FACILITATOR_AUTH, "no facilitator call to look at", ev);
    };
    let inspected = format!("call #{} {} {}", call.seq, call.method, call.path);
    let Some(value) = call.headers.get("authorization") else {
        return Finding::info(
            &FACILITATOR_AUTH,
            format!("no Authorization header on {inspected}"),
            ev,
        );
    };
    let Some(token) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    else {
        return Finding::info(
            &FACILITATOR_AUTH,
            format!(
                "{inspected}: Authorization scheme {}",
                value.split(' ').next().unwrap_or("?")
            ),
            ev,
        );
    };
    let parts: Vec<&str> = token.split('.').collect();
    let decoded = |i: usize| {
        parts.get(i).and_then(|p| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(p)
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        })
    };
    match (parts.len(), decoded(0), decoded(1)) {
        (3, Some(header), Some(claims)) => {
            let text =
                |v: &Value, k: &str| member(v, k).map_or("absent".to_owned(), |x| short(&x.to_string()));
            let lifetime = match (
                member(&claims, "exp").and_then(Value::as_i64),
                member(&claims, "nbf").and_then(Value::as_i64),
            ) {
                (Some(exp), Some(nbf)) => format!("{}s", exp - nbf),
                _ => "unknown".to_owned(),
            };
            // each entry is "METHOD authority/path": the method and the path are compared exactly, the authority
            // is not, since the one the server used to reach the double is unknown behind a public URL or a tunnel
            let uris_match = member(&claims, "uris").and_then(Value::as_array).map(|u| {
                u.iter().any(|x| {
                    x.as_str().is_some_and(|entry| {
                        let mut words = entry.splitn(2, ' ');
                        let method = words.next().unwrap_or_default();
                        let target = words.next().unwrap_or_default();
                        let path = target.find('/').map_or("/", |i| &target[i..]);
                        method == call.method && path == call.path
                    })
                })
            });
            Finding::info(
                &FACILITATOR_AUTH,
                format!(
                    "{inspected}: Bearer JWT decoded, not verified: alg {}, kid {}, iss {}, uris {} ({}), lifetime {lifetime}",
                    text(&header, "alg"),
                    text(&header, "kid"),
                    text(&claims, "iss"),
                    text(&claims, "uris"),
                    match uris_match {
                        Some(true) => "one entry has this call's method and path, authority not compared",
                        Some(false) => "no entry has this call's method and path",
                        None => "no uris claim",
                    }
                ),
                ev,
            )
        }
        _ => Finding::info(
            &FACILITATOR_AUTH,
            format!("{inspected}: Bearer token that is not a JWS compact serialisation"),
            ev,
        ),
    }
}
