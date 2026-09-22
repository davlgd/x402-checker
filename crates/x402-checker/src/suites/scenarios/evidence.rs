//! What a scenario observed, read back: the calls the doubles recorded, the facilitator request bodies against what
//! the tool sent, the receipt and the sidechannel in what the client received, and the findings that say a scenario
//! could not be carried out.

use super::{
    Attribution, Call, Check, Endpoint, Exchange, Finding, Observed, SIDECHANNEL, SIDECHANNEL_MARKER,
    SuiteResult, Value, headers, judge, member, short,
};

pub(super) fn quiet_note(observed: &Observed) -> &'static str {
    if observed.quiescent {
        ""
    } else {
        "; calls still in flight after the wait"
    }
}

pub(super) fn blocked_all(result: &mut SuiteResult, checks: &[&Check], why: &str) {
    for check in checks {
        result
            .findings
            .push(Finding::blocked(check, Attribution::Dependency, why, &[]));
    }
}

pub(super) fn unmet(result: &mut SuiteResult, checks: &[&Check], why: &str, ev: &[usize]) {
    for check in checks {
        result.findings.push(Finding::cannot_assess(check, why, ev));
    }
}

/// The request body of a facilitator call against what the tool sent and what the server offered (raw JSON).
pub(super) fn body_check(
    check: &Check,
    call: Option<&Call>,
    sent: &Value,
    offer_raw: &Value,
    ev: &[usize],
) -> Finding {
    let Some(call) = call else {
        return Finding::fail(check, "no such call", ev);
    };
    let Some(body) = &call.body_json else {
        return Finding::fail(check, format!("body is not JSON: {}", short(&call.body_text)), ev);
    };
    let mut problems = Vec::new();
    if member(body, "x402Version").and_then(Value::as_f64) != Some(2.0) {
        problems.push(format!(
            "x402Version = {}",
            member(body, "x402Version").map_or("absent".into(), Value::to_string)
        ));
    }
    if member(body, "paymentPayload") != Some(sent) {
        problems.push("paymentPayload differs from the PAYMENT-SIGNATURE sent".to_owned());
    }
    if member(body, "paymentRequirements") != Some(offer_raw) {
        problems.push("paymentRequirements differs from the offer as advertised".to_owned());
    }
    judge(
        check,
        problems.is_empty(),
        if problems.is_empty() {
            "as sent and as offered".to_owned()
        } else {
            problems.join("; ")
        },
        ev,
    )
}

/// The sidechannel marker must appear neither as a header, nor in the body, nor in the decoded receipt. When the
/// body could not be read entirely, the obligation is not established even if nothing leaked in what was read.
pub(super) fn sidechannel_check(exchange: &Exchange, ev: &[usize]) -> Finding {
    let mut leaks = Vec::new();
    if exchange.header(headers::EXTENSION_RESPONSES).is_some() {
        leaks.push("the EXTENSION-RESPONSES header is forwarded");
    }
    if exchange.body.text.contains(SIDECHANNEL_MARKER) {
        leaks.push("the marker appears in the response body");
    }
    if exchange.payment_response.as_ref().is_some_and(|d| {
        d.json
            .as_ref()
            .is_some_and(|j| j.to_string().contains(SIDECHANNEL_MARKER))
    }) {
        leaks.push("the marker appears in PAYMENT-RESPONSE");
    }
    if !leaks.is_empty() {
        return Finding::fail(&SIDECHANNEL, leaks.join("; "), ev);
    }
    if exchange.body.truncated || exchange.body.error.is_some() {
        return Finding::cannot_assess(
            &SIDECHANNEL,
            format!(
                "no leak in the headers, the receipt and the first {} bytes of the body, but the body was not read entirely",
                exchange.body.text.len()
            ),
            ev,
        );
    }
    Finding::pass(
        &SIDECHANNEL,
        "not forwarded: header absent, marker absent from the body and the receipt",
        ev,
    )
}

pub(super) fn count(calls: &[Call], endpoint: Endpoint) -> usize {
    calls.iter().filter(|c| c.endpoint == endpoint).count()
}

pub(super) fn first(calls: &[Call], endpoint: Endpoint) -> Option<&Call> {
    calls.iter().find(|c| c.endpoint == endpoint)
}

pub(super) fn seen(call: Option<&Call>) -> &'static str {
    if call.is_some() { "seen" } else { "not seen" }
}

pub(super) fn receipt_text(exchange: &Exchange) -> String {
    exchange
        .payment_response
        .as_ref()
        .map_or("absent".to_owned(), |d| {
            d.json
                .as_ref()
                .map_or_else(|| d.error.clone().unwrap_or_default(), Value::to_string)
        })
}

pub(super) fn refusal_reason(exchange: &Exchange) -> Option<String> {
    if let Some(pr) = exchange.payment_required()
        && let Some(error) = pr.error
    {
        return Some(error);
    }
    exchange
        .body_json()
        .and_then(|b| member(&b, "error").and_then(Value::as_str).map(str::to_owned))
}
