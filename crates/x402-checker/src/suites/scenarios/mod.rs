//! `scenarios`: the server under test talks to the tool's scripted facilitator, and when possible to its witness
//! backend, so that every outcome a facilitator can produce is exercised and every call the server makes is seen.
//!
//! Nothing here needs funds: the scripted facilitator validates no signature, so the payer is a random key. The
//! operator must first configure the server with the facilitator URL the tool prints (and the witness URL as its
//! upstream, to unlock the sequence checks).
//!
//! Every scenario first establishes that its scripted outcome was actually met (the facilitator saw the call the
//! scenario is about); otherwise its checks are reported as not demonstrated rather than passed. Sequence claims
//! use the recorded start and end of each call, and only the first call of each kind.

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jiff::Timestamp;
use serde_json::{Value, json};
use x402_checker_evm::{AuthorizationParams, Eip3009Offer, Payer};
use x402_checker_testbed::{
    Call, Endpoint, Facilitator, Script, SettleOutcome, VerifyOutcome, Witness, WitnessScript,
};
use x402_checker_types::{Caip2, PaymentRequired, PaymentRequirements, headers};

use super::{echoed_extensions, extensions::payment_identifier_required, fresh_payment_id, member, short};
use crate::check::{Attribution, Check, Finding, Level, Source, SuiteResult, Trace, judge};
use crate::http::Exchange;
use crate::target::Context;

use auth::facilitator_auth_finding;
use evidence::{
    blocked_all, body_check, count, first, quiet_note, receipt_text, refusal_reason, seen, sidechannel_check,
    unmet,
};

mod auth;
mod evidence;

mod mechanism;

use mechanism::Mechanism;
pub use mechanism::MechanismKind;

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

const WIRED: Check = check(
    "SCN-WIRED",
    "the server talks to the scripted facilitator (and to the witness, when one is started)",
    Level::Optional,
    Source::Policy,
    "precondition of this suite: the facilitator must see the server's calls and the receipt must carry its transaction hash",
);

const VERIFY_BODY: Check = check(
    "CORE-055",
    "the /verify request carries x402Version 2, the client's paymentPayload and the offered paymentRequirements",
    Level::Required,
    Source::Prose,
    "x402-specification-v2.md 7.1: request `{x402Version, paymentPayload, paymentRequirements}`",
);

const SETTLE_BODY: Check = check(
    "CORE-059",
    "the /settle request has the same structure and content as /verify",
    Level::Required,
    Source::Prose,
    "x402-specification-v2.md 7.2: \"Request: Same structure as /verify endpoint\"",
);

const ORDER_VERIFY_SETTLE: Check = check(
    "CORE-050a",
    "verify completes before settle starts",
    Level::Required,
    Source::Prose,
    "x402-specification-v2.md 6.1, authorization flow: \"verify → resource → settle → respond\"",
);

const ORDER_BACKEND: Check = check(
    "CORE-050",
    "the resource executes after verify completed and before settle starts",
    Level::Required,
    Source::Prose,
    "x402-specification-v2.md 6.1: \"Read-only verify before the resource executes; funds move only after it completes successfully\"",
);

const RECEIPT_RELAY: Check = check(
    "CORE-030",
    "the settlement outcome reaches the client in PAYMENT-RESPONSE with the facilitator's success, transaction and network",
    Level::Required,
    Source::Prose,
    "x402-specification-v2.md 5.3.1: \"the server includes transaction details in the payment response field\"; transports-v2/http.md, Settlement Response Delivery",
);

const SIDECHANNEL: Check = check(
    "CORE-064",
    "what the facilitator sent in EXTENSION-RESPONSES never reaches the client",
    Level::Required,
    Source::ExplicitMust,
    "x402-specification-v2.md 7.2.1: sidechannel \"not part of the JSON response body and not forwarded to buyers\"",
);

const SETTLE_COUNT: Check = check(
    "SCN-SETTLES",
    "number of /settle calls for one payment",
    Level::Optional,
    Source::Policy,
    "x402-specification-v2.md 7.2 allows several settles per payment; reported as a fact",
);

const INVALID_NO_SETTLE: Check = check(
    "CORE-054v",
    "a payment the facilitator finds invalid is neither settled nor served",
    Level::Required,
    Source::ExplicitMust,
    "x402-specification-v2.md 6.1: \"at least one check ... MUST run before the resource executes\"; authorization flow settles only after a successful resource",
);

const INVALID_NO_BACKEND: Check = check(
    "CORE-054b",
    "a payment the facilitator finds invalid does not reach the resource",
    Level::Required,
    Source::ExplicitMust,
    "x402-specification-v2.md 6.1: \"The resource never executes with nothing checked\"",
);

const INVALID_REASON: Check = check(
    "CORE-070v",
    "the facilitator's invalidReason is surfaced to the client",
    Level::Optional,
    Source::Prose,
    "x402-specification-v2.md 9: error codes \"help clients understand why a payment failed\"",
);

const REJECTED_RELAY: Check = check(
    "HTTP-006",
    "a rejected settlement is a 402 whose PAYMENT-RESPONSE relays success false, errorReason and transaction",
    Level::Required,
    Source::Prose,
    "transports-v2/http.md, Error Handling: Payment Failed 402; Settlement Response Delivery, Example (Failure): 402 with PAYMENT-RESPONSE `{success:false, errorReason, transaction:\"\", network}`",
);

const PENDING_RECEIPT: Check = check(
    "CORE-038",
    "a settlement_pending outcome reaches the client with its transaction and network, and is not presented as a success",
    Level::Required,
    Source::ExplicitMust,
    "x402-specification-v2.md 9: settlement_pending \"MUST carry a non-empty transaction ... and network\"; 5.3.2 transaction MUST be non-empty when errorReason is settlement_pending",
);

const PENDING_NO_CHALLENGE: Check = with_note(
    check(
        "SCN-PENDING-CHALLENGE",
        "a pending settlement does not come with a fresh PAYMENT-REQUIRED inviting a second signature",
        Level::Recommended,
        Source::Policy,
        "not a spec clause: a client that signs again after a pending outcome may pay twice",
    ),
    "the spec leaves the server's answer to a pending settlement open beyond the receipt content",
);

const UNREADABLE_NO_SUCCESS: Check = check(
    "SCN-UNREADABLE",
    "an unreadable settle answer is not presented as a successful settlement",
    Level::Required,
    Source::FieldTable,
    "transports-v2/http.md, Error Handling: 200 means \"Payment verified and settled successfully\"; nothing was established here",
);

const BACKEND_FAILURE_NO_SETTLE: Check = check(
    "CORE-051",
    "a failing resource is not settled",
    Level::Required,
    Source::Prose,
    "x402-specification-v2.md 6.1, authorization flow: \"funds move only after it completes successfully\"",
);

const PAYID_CONFLICT: Check = with_note(
    check(
        "PAYID-CONFLICT",
        "the same payment identifier with a different payload is refused with 409 and not settled again",
        Level::Recommended,
        Source::FieldTable,
        "extensions/payment_identifier.md, Idempotency Behavior: \"Same id, different payload | Return 409 Conflict\"",
    ),
    "the extension lets either the server or the facilitator consume the id; a server that delegates it to the facilitator is not wrong, so the tool warns rather than fails",
);

const PAYID_REQUIRED: Check = with_note(
    check(
        "PAYID-REQUIRED",
        "when required is true, a payment without an id is answered with 400",
        Level::Recommended,
        Source::FieldTable,
        "extensions/payment_identifier.md, Idempotency Behavior: \"required: true, no id provided | Return 400 Bad Request\"",
    ),
    "same consumer-profile caveat as PAYID-CONFLICT",
);

const REPLAY_LOCAL: Check = check(
    "CORE-072s",
    "a replayed payment whose nonce the facilitator refuses is not presented as a new success",
    Level::Required,
    Source::ExplicitMust,
    "schemes/exact/scheme_exact.md: \"A consumed primitive MUST produce a settlement failure, never a success\"",
);

/// What the operator gives the suite.
#[derive(Debug)]
pub struct ScenarioOptions {
    /// The scripted facilitator, already listening; the server must be configured to use it.
    pub facilitator: Facilitator,
    /// The witness backend, already listening, when the server's upstream is pointed at it.
    pub witness: Option<Witness>,
    /// How long the tool waits for the server's facilitator and witness calls after each response.
    pub settle_wait: Duration,
    /// The offer family to pay with.
    pub mechanism: MechanismKind,
}

/// The value the facilitator puts in EXTENSION-RESPONSES; it must appear nowhere in what the client receives.
const SIDECHANNEL_MARKER: &str = "sidechannel-marker-7f3a";

struct Run<'a> {
    offer: &'a PaymentRequirements,
    /// The offer as the server sent it, unknown members included.
    offer_raw: Value,
    mechanism: Mechanism,
    extensions: Option<x402_checker_types::Extensions>,
    /// Whether the happy path showed the witness being called: only then can its silence mean something.
    witness_wired: bool,
}

/// What one scenario observed.
struct Observed {
    index: usize,
    calls: Vec<Call>,
    /// False when calls were still in flight after `settle_wait`: nothing can be concluded from their absence.
    quiescent: bool,
}

/// Runs the scenarios suite.
pub async fn run(ctx: &mut Context, options: &ScenarioOptions) -> SuiteResult {
    let mut result = SuiteResult::new("scenarios", Vec::new());
    let Some((terms, terms_raw)) = terms(ctx, &mut result.findings).await else {
        return result;
    };
    let chosen = match options.mechanism {
        MechanismKind::Evm => terms.accepts.iter().enumerate().find_map(|(i, o)| {
            Eip3009Offer::from_requirements(o)
                .ok()
                .map(|evm| (i, o, Mechanism::Evm(Box::new((evm, Payer::random())))))
        }),
        // the scenarios script the authorization flow (verify, resource, settle): an offer under another flow
        // would be judged against an order it does not promise
        MechanismKind::Svm => terms.accepts.iter().enumerate().find_map(|(i, o)| {
            let svm = o.scheme == "exact"
                && o.network.parse::<Caip2>().is_ok_and(|n| n.is_svm())
                && o.extra
                    .get("feePayer")
                    .and_then(Value::as_str)
                    .is_some_and(|f| !f.is_empty())
                && o.extra
                    .get("paymentFlow")
                    .and_then(Value::as_str)
                    .is_none_or(|f| f == "authorization");
            svm.then_some((i, o, Mechanism::Svm))
        }),
    };
    let Some((position, offer, mechanism)) = chosen else {
        result.findings.push(Finding::cannot_assess(
            &WIRED,
            match options.mechanism {
                MechanismKind::Evm => "no exact eip3009 offer on an eip155 network under the authorization flow: the tool cannot build a payment",
                MechanismKind::Svm => "no exact offer on a solana network with an extra.feePayer under the authorization flow: nothing to pay with a transaction",
            },
            &[],
        ));
        return result;
    };
    let offer_raw = terms_raw
        .pointer(&format!("/accepts/{position}"))
        .cloned()
        .unwrap_or(Value::Null);
    let mut run = Run {
        offer,
        offer_raw,
        mechanism,
        extensions: terms.extensions.clone(),
        witness_wired: false,
    };
    let Some(happy) = happy_path(ctx, options, &mut run, &mut result).await else {
        return result;
    };
    verify_invalid(ctx, options, &run, &mut result).await;
    settle_rejected(ctx, options, &run, &mut result).await;
    settle_pending(ctx, options, &run, &mut result).await;
    settle_unreadable(ctx, options, &run, &mut result).await;
    backend_failure(ctx, options, &run, &mut result).await;
    payment_identifier(ctx, options, &run, &mut result).await;
    replay(ctx, options, &happy, &mut result).await;
    result
}

/// The payment-identifier extension, when advertised: same id with another payload, and a missing id when required.
async fn payment_identifier(
    ctx: &mut Context,
    options: &ScenarioOptions,
    run: &Run<'_>,
    result: &mut SuiteResult,
) {
    let Some(required) = payment_identifier_required(run.extensions.as_ref()) else {
        return;
    };
    let id = fresh_payment_id();
    let first = match scenario(
        ctx,
        options,
        "payment identifier, first use",
        Script::default(),
        &payment_header_with(run, Some(&id)),
        result,
    )
    .await
    {
        Ok(observed) => observed,
        Err(error) => return blocked_all(result, &[&PAYID_CONFLICT, &PAYID_REQUIRED], &error),
    };
    if count(&first.calls, Endpoint::Settle) == 0 {
        return unmet(
            result,
            &[&PAYID_CONFLICT],
            "the first payment with this id was not settled, so a conflict cannot be provoked",
            &[first.index],
        );
    }
    let script = Script {
        settle: SettleOutcome::Settled {
            transaction: run.mechanism.replay_tx().into(),
        },
        ..Script::default()
    };
    match scenario(
        ctx,
        options,
        "payment identifier, same id with another payload",
        script,
        &payment_header_with(run, Some(&id)),
        result,
    )
    .await
    {
        Ok(second) => {
            let exchange = ctx.client.exchange(second.index).clone();
            let settles = count(&second.calls, Endpoint::Settle);
            result.findings.push(judge(
                &PAYID_CONFLICT,
                exchange.status == 409 && settles == 0,
                format!(
                    "status {}, {settles} settle call(s), receipt {}",
                    exchange.status,
                    receipt_text(&exchange)
                ),
                &[first.index, second.index],
            ));
        }
        Err(error) => blocked_all(result, &[&PAYID_CONFLICT], &error),
    }
    if !required {
        result.findings.push(Finding::skip(
            &PAYID_REQUIRED,
            "the server advertises required: false",
        ));
        return;
    }
    match scenario(
        ctx,
        options,
        "payment identifier required, none sent",
        Script::default(),
        &payment_header_with(run, None),
        result,
    )
    .await
    {
        Ok(observed) => {
            let exchange = ctx.client.exchange(observed.index).clone();
            result.findings.push(judge(
                &PAYID_REQUIRED,
                exchange.status == 400,
                format!("status {}", exchange.status),
                &[observed.index],
            ));
        }
        Err(error) => blocked_all(result, &[&PAYID_REQUIRED], &error),
    }
}

struct Happy {
    index: usize,
    header: String,
    /// The transaction the facilitator answered with, and the one it would answer a new settlement with.
    settled_tx: &'static str,
    other_tx: &'static str,
}

/// The default script: everything valid, settled with a known transaction hash. Also the precondition of the
/// suite: if the facilitator saw nothing and the receipt does not carry its hash, the server is not talking to it.
async fn happy_path(
    ctx: &mut Context,
    options: &ScenarioOptions,
    run: &mut Run<'_>,
    result: &mut SuiteResult,
) -> Option<Happy> {
    let script = Script {
        settle: SettleOutcome::Settled {
            transaction: run.mechanism.happy_tx().into(),
        },
        extension_responses: Some(json!({ "review": SIDECHANNEL_MARKER })),
        ..Script::default()
    };
    let header = payment_header(run);
    let observed = match scenario(ctx, options, "happy path payment", script, &header, result).await {
        Ok(observed) => observed,
        Err(error) => {
            result.findings.push(Finding::cannot_assess(
                &WIRED,
                format!("the target could not be reached: {error}"),
                &[],
            ));
            return None;
        }
    };
    let exchange = ctx.client.exchange(observed.index).clone();
    let calls = &observed.calls;
    let ev = [observed.index];
    let receipt = exchange.payment_response();
    let facilitator_seen = count(calls, Endpoint::Verify) + count(calls, Endpoint::Settle) > 0;
    if !facilitator_seen
        && receipt
            .as_ref()
            .is_none_or(|r| r.transaction != run.mechanism.happy_tx())
    {
        let svm_note = match run.mechanism {
            Mechanism::Svm => {
                "; the tool's transaction is random bytes, so a server that parses Solana transactions itself refuses it before any facilitator call, which is not judged"
            }
            Mechanism::Evm(_) => "",
        };
        result.findings.push(Finding::cannot_assess(&WIRED, format!("the scripted facilitator at {} received no call and the response carries no receipt from it (status {}): configure the server to use it, then rerun{svm_note}", options.facilitator.url(), exchange.status), &ev));
        return None;
    }
    run.witness_wired = count(calls, Endpoint::Backend) > 0;
    let witness_note = match (&options.witness, run.witness_wired) {
        (None, _) => "no witness started".to_owned(),
        (Some(w), true) => format!("witness at {} called", w.url()),
        (Some(w), false) => format!(
            "witness at {} started but never called: the server's upstream is not the witness, so nothing can be concluded from its silence",
            w.url()
        ),
    };
    result.findings.push(Finding::info(
        &WIRED,
        format!(
            "{} verify, {} settle, {} backend call(s); {witness_note}{}",
            count(calls, Endpoint::Verify),
            count(calls, Endpoint::Settle),
            count(calls, Endpoint::Backend),
            quiet_note(&observed)
        ),
        &ev,
    ));

    result.findings.push(facilitator_auth_finding(calls, &ev));

    let sent: Value =
        serde_json::from_slice(&STANDARD.decode(&header).unwrap_or_default()).unwrap_or(Value::Null);
    let verify = first(calls, Endpoint::Verify);
    let settle = first(calls, Endpoint::Settle);
    let backend = first(calls, Endpoint::Backend);
    result
        .findings
        .push(body_check(&VERIFY_BODY, verify, &sent, &run.offer_raw, &ev));
    result
        .findings
        .push(body_check(&SETTLE_BODY, settle, &sent, &run.offer_raw, &ev));
    result.findings.extend(order_findings(
        options, run, &observed, verify, backend, settle, &ev,
    ));
    let relayed = exchange.is_success()
        && receipt.is_some_and(|r| {
            r.success && r.transaction == run.mechanism.happy_tx() && r.network == run.offer.network
        });
    result.findings.push(judge(
        &RECEIPT_RELAY,
        relayed,
        format!("status {}, receipt {}", exchange.status, receipt_text(&exchange)),
        &ev,
    ));
    result.findings.push(sidechannel_check(&exchange, &ev));
    result.findings.push(Finding::info(
        &SETTLE_COUNT,
        format!("{} settle call(s)", count(calls, Endpoint::Settle)),
        &ev,
    ));
    Some(Happy {
        index: observed.index,
        header,
        settled_tx: run.mechanism.happy_tx(),
        other_tx: run.mechanism.replay_tx(),
    })
}

/// The order of the server's calls, on the first call of each kind, from their recorded start and end.
fn order_findings(
    options: &ScenarioOptions,
    run: &Run<'_>,
    observed: &Observed,
    verify: Option<&Call>,
    backend: Option<&Call>,
    settle: Option<&Call>,
    ev: &[usize],
) -> Vec<Finding> {
    let calls = &observed.calls;
    let mut findings = Vec::new();
    findings.push(match (verify, settle) {
        (Some(v), Some(s)) => judge(
            &ORDER_VERIFY_SETTLE,
            v.finished_at.is_some_and(|f| f <= s.started_at),
            format!(
                "first verify finished {:?}, first settle started {:?}",
                v.finished_at, s.started_at
            ),
            ev,
        ),
        _ if !observed.quiescent => Finding::blocked(
            &ORDER_VERIFY_SETTLE,
            Attribution::Unknown,
            "calls still in flight after the wait, the sequence is not established",
            ev,
        ),
        _ => Finding::fail(
            &ORDER_VERIFY_SETTLE,
            format!(
                "{} verify and {} settle call(s)",
                count(calls, Endpoint::Verify),
                count(calls, Endpoint::Settle)
            ),
            ev,
        ),
    });
    findings.push(match (&options.witness, run.witness_wired, verify, backend, settle) {
        (None, ..) => Finding::skip(&ORDER_BACKEND, "no witness backend: point the server's upstream at --witness-listen to observe the resource call"),
        (Some(_), false, ..) => Finding::cannot_assess(&ORDER_BACKEND, "the witness was never called: the server's upstream is not the witness", ev),
        (Some(_), true, Some(v), Some(b), Some(s)) => {
            let ordered = v.finished_at.is_some_and(|f| f <= b.started_at) && b.finished_at.is_some_and(|f| f <= s.started_at);
            judge(&ORDER_BACKEND, ordered, format!("first verify finished {:?}, first backend call {:?}..{:?}, first settle started {:?}", v.finished_at, b.started_at, b.finished_at, s.started_at), ev)
        }
        (Some(_), true, v, b, s) => Finding::fail(&ORDER_BACKEND, format!("verify {}, backend {}, settle {}", seen(v), seen(b), seen(s)), ev),
    });
    findings
}

/// The facilitator finds the payment invalid. Established only if the facilitator received the /verify call.
async fn verify_invalid(
    ctx: &mut Context,
    options: &ScenarioOptions,
    run: &Run<'_>,
    result: &mut SuiteResult,
) {
    let checks: [&Check; 2] = [&INVALID_NO_SETTLE, &INVALID_NO_BACKEND];
    let script = Script {
        verify: VerifyOutcome::Invalid {
            reason: "insufficient_funds".into(),
        },
        ..Script::default()
    };
    let observed = match scenario(
        ctx,
        options,
        "verify invalid",
        script,
        &payment_header(run),
        result,
    )
    .await
    {
        Ok(observed) => observed,
        Err(error) => return blocked_all(result, &checks, &error),
    };
    let exchange = ctx.client.exchange(observed.index).clone();
    let calls = &observed.calls;
    let ev = [observed.index];
    if count(calls, Endpoint::Verify) == 0 {
        return unmet(
            result,
            &checks,
            "the facilitator received no /verify call: the server refused earlier, the scripted outcome was not met",
            &ev,
        );
    }
    if !observed.quiescent {
        return blocked_all(result, &checks, "calls still in flight after the wait");
    }
    let settles = count(calls, Endpoint::Settle);
    result.findings.push(judge(
        &INVALID_NO_SETTLE,
        !exchange.is_success() && settles == 0,
        format!("status {}, {settles} settle call(s)", exchange.status),
        &ev,
    ));
    result.findings.push(match (&options.witness, run.witness_wired) {
        (None, _) => Finding::skip(&INVALID_NO_BACKEND, "no witness backend"),
        (Some(_), false) => Finding::cannot_assess(
            &INVALID_NO_BACKEND,
            "the witness is not the server's upstream",
            &ev,
        ),
        (Some(_), true) => judge(
            &INVALID_NO_BACKEND,
            count(calls, Endpoint::Backend) == 0,
            format!("{} backend call(s)", count(calls, Endpoint::Backend)),
            &ev,
        ),
    });
    result.findings.push(Finding::info(
        &INVALID_REASON,
        match refusal_reason(&exchange) {
            Some(r) => format!("reason {r}"),
            None => "no reason surfaced".to_owned(),
        },
        &ev,
    ));
}

/// The facilitator rejects the settlement without broadcasting anything.
async fn settle_rejected(
    ctx: &mut Context,
    options: &ScenarioOptions,
    run: &Run<'_>,
    result: &mut SuiteResult,
) {
    let script = Script {
        settle: SettleOutcome::Rejected {
            reason: "invalid_transaction_state".into(),
            transaction: String::new(),
        },
        ..Script::default()
    };
    let Some((exchange, ev)) = settle_scenario(
        ctx,
        options,
        run,
        "settle rejected",
        script,
        &[&REJECTED_RELAY],
        result,
    )
    .await
    else {
        return;
    };
    let relayed = exchange.payment_response().is_some_and(|r| {
        !r.success
            && r.error_reason.as_deref() == Some("invalid_transaction_state")
            && r.transaction.is_empty()
    });
    result.findings.push(judge(
        &REJECTED_RELAY,
        exchange.status == 402 && relayed,
        format!("status {}, receipt {}", exchange.status, receipt_text(&exchange)),
        &ev,
    ));
}

/// The facilitator broadcast but could not confirm.
async fn settle_pending(
    ctx: &mut Context,
    options: &ScenarioOptions,
    run: &Run<'_>,
    result: &mut SuiteResult,
) {
    let script = Script {
        settle: SettleOutcome::Pending {
            transaction: "0xdead".into(),
        },
        ..Script::default()
    };
    let Some((exchange, ev)) = settle_scenario(
        ctx,
        options,
        run,
        "settle pending",
        script,
        &[&PENDING_RECEIPT, &PENDING_NO_CHALLENGE],
        result,
    )
    .await
    else {
        return;
    };
    let ok = exchange
        .payment_response()
        .is_some_and(|r| !r.success && r.is_pending() && r.transaction == "0xdead" && !r.network.is_empty());
    let challenged = exchange.payment_required.is_some();
    result.findings.push(judge(
        &PENDING_RECEIPT,
        ok,
        format!("status {}, receipt {}", exchange.status, receipt_text(&exchange)),
        &ev,
    ));
    result.findings.push(judge(
        &PENDING_NO_CHALLENGE,
        !challenged,
        if challenged {
            "a PAYMENT-REQUIRED header accompanies the pending outcome"
        } else {
            "no fresh challenge"
        },
        &ev,
    ));
}

/// The facilitator answers something that is not a `SettleResponse`.
async fn settle_unreadable(
    ctx: &mut Context,
    options: &ScenarioOptions,
    run: &Run<'_>,
    result: &mut SuiteResult,
) {
    let script = Script {
        settle: SettleOutcome::Raw {
            status: 502,
            content_type: "text/html".into(),
            body: "<h1>Bad gateway</h1>".into(),
        },
        ..Script::default()
    };
    let Some((exchange, ev)) = settle_scenario(
        ctx,
        options,
        run,
        "settle unreadable",
        script,
        &[&UNREADABLE_NO_SUCCESS],
        result,
    )
    .await
    else {
        return;
    };
    let detail = format!("status {}, receipt {}", exchange.status, receipt_text(&exchange));
    result.findings.push(match exchange.payment_response() {
        Some(r) if r.success => Finding::fail(&UNREADABLE_NO_SUCCESS, format!("{detail}: a success receipt was presented although the facilitator answered nothing readable"), &ev),
        None if exchange.is_success() => Finding::blocked(&UNREADABLE_NO_SUCCESS, Attribution::Unknown, format!("{detail}: the resource was delivered without a receipt; whether a settlement is claimed is not established"), &ev),
        _ => Finding::pass(&UNREADABLE_NO_SUCCESS, detail, &ev),
    });
}

/// A scenario about the settle answer: established only if the facilitator received the /settle call.
async fn settle_scenario(
    ctx: &mut Context,
    options: &ScenarioOptions,
    run: &Run<'_>,
    label: &str,
    script: Script,
    checks: &[&Check],
    result: &mut SuiteResult,
) -> Option<(Exchange, [usize; 1])> {
    let observed = match scenario(ctx, options, label, script, &payment_header(run), result).await {
        Ok(observed) => observed,
        Err(error) => {
            blocked_all(result, checks, &error);
            return None;
        }
    };
    let ev = [observed.index];
    if count(&observed.calls, Endpoint::Settle) == 0 {
        unmet(
            result,
            checks,
            "the facilitator received no /settle call: the scripted outcome was not met",
            &ev,
        );
        return None;
    }
    Some((ctx.client.exchange(observed.index).clone(), ev))
}

/// The resource fails; needs the witness as the server's upstream.
async fn backend_failure(
    ctx: &mut Context,
    options: &ScenarioOptions,
    run: &Run<'_>,
    result: &mut SuiteResult,
) {
    let Some(witness) = &options.witness else {
        result.findings.push(Finding::skip(
            &BACKEND_FAILURE_NO_SETTLE,
            "no witness backend: point the server's upstream at --witness-listen to exercise it",
        ));
        return;
    };
    if !run.witness_wired {
        result.findings.push(Finding::cannot_assess(
            &BACKEND_FAILURE_NO_SETTLE,
            "the witness is not the server's upstream",
            &[],
        ));
        return;
    }
    witness.set_script(WitnessScript {
        status: 503,
        latency: Duration::ZERO,
    });
    let outcome = scenario(
        ctx,
        options,
        "backend failure",
        Script::default(),
        &payment_header(run),
        result,
    )
    .await;
    witness.set_script(WitnessScript::default());
    let observed = match outcome {
        Ok(observed) => observed,
        Err(error) => return blocked_all(result, &[&BACKEND_FAILURE_NO_SETTLE], &error),
    };
    let ev = [observed.index];
    if count(&observed.calls, Endpoint::Backend) == 0 {
        return unmet(
            result,
            &[&BACKEND_FAILURE_NO_SETTLE],
            "the witness was not called in this scenario: the resource failure was not met",
            &ev,
        );
    }
    if !observed.quiescent {
        return blocked_all(
            result,
            &[&BACKEND_FAILURE_NO_SETTLE],
            "calls still in flight after the wait",
        );
    }
    let exchange = ctx.client.exchange(observed.index).clone();
    let settles = count(&observed.calls, Endpoint::Settle);
    let charged = exchange.payment_response().is_some_and(|r| r.success);
    result.findings.push(judge(
        &BACKEND_FAILURE_NO_SETTLE,
        settles == 0 && !charged,
        format!(
            "status {}, {settles} settle call(s), receipt {}",
            exchange.status,
            receipt_text(&exchange)
        ),
        &ev,
    ));
}

/// The happy path header again. The facilitator keeps the nonces it settled, so a second settle is refused; and
/// it would now answer a different hash, so a new success could not be mistaken for the cached receipt. What the
/// tool can see is the receipt: a success receipt naming a new transaction is its observable proxy for a second
/// settlement; without a receipt nothing is established.
async fn replay(ctx: &mut Context, options: &ScenarioOptions, happy: &Happy, result: &mut SuiteResult) {
    let script = Script {
        settle: SettleOutcome::Settled {
            transaction: happy.other_tx.into(),
        },
        ..Script::default()
    };
    let observed = match scenario(
        ctx,
        options,
        "replay of the happy path payment",
        script,
        &happy.header,
        result,
    )
    .await
    {
        Ok(observed) => observed,
        Err(error) => return blocked_all(result, &[&REPLAY_LOCAL], &error),
    };
    let exchange = ctx.client.exchange(observed.index).clone();
    let receipt = exchange.payment_response();
    let settles = count(&observed.calls, Endpoint::Settle);
    let ev = [happy.index, observed.index];
    let detail = format!(
        "status {}, receipt {}, {settles} settle call(s) on replay",
        exchange.status,
        receipt_text(&exchange)
    );
    result.findings.push(match receipt {
        _ if !observed.quiescent => Finding::blocked(
            &REPLAY_LOCAL,
            Attribution::Unknown,
            format!("{detail}; calls still in flight after the wait"),
            &ev,
        ),
        Some(r) if r.success && r.transaction != happy.settled_tx => Finding::fail(
            &REPLAY_LOCAL,
            format!("{detail}: a success receipt with a new transaction"),
            &ev,
        ),
        None if exchange.is_success() => Finding::cannot_assess(
            &REPLAY_LOCAL,
            format!(
                "{detail}: served again without a receipt, whether a settlement is claimed is not established"
            ),
            &ev,
        ),
        _ => Finding::pass(&REPLAY_LOCAL, detail, &ev),
    });
}

/// Waits for quiet, sets `script`, sends `header`, waits for quiet again, records the trace. Errors are a target
/// still busy from the previous scenario (nothing is mutated then) or a transport error towards the target; in both
/// cases the calls seen so far stay in the trace.
async fn scenario(
    ctx: &mut Context,
    options: &ScenarioOptions,
    label: &str,
    script: Script,
    header: &str,
    result: &mut SuiteResult,
) -> Result<Observed, String> {
    let (leftover, quiet) = wait_quiet(options).await;
    if !quiet {
        result.traces.push(Trace {
            label: format!("{label} (not started)"),
            calls: leftover,
            quiescent: false,
        });
        return Err(format!(
            "calls of the previous scenario still in flight after {:?}: {label} not started",
            options.settle_wait
        ));
    }
    options.facilitator.set_script(script);
    options.facilitator.recorder().clear();
    let sent = ctx
        .client
        .send(
            label,
            ctx.resource_request(&[(headers::PAYMENT_SIGNATURE, header)]),
        )
        .await;
    let (calls, quiescent) = wait_quiet(options).await;
    result.traces.push(Trace {
        label: label.to_owned(),
        calls: calls.clone(),
        quiescent,
    });
    let index = sent.map_err(|e| e.to_string())?;
    Ok(Observed {
        index,
        calls,
        quiescent,
    })
}

/// Waits until no facilitator or witness call is in flight, bounded by `settle_wait`, then a short grace for a
/// call the server might start right after answering. Returns the calls and whether quiet was reached.
async fn wait_quiet(options: &ScenarioOptions) -> (Vec<Call>, bool) {
    let recorder = options.facilitator.recorder();
    let deadline = Timestamp::now() + jiff::SignedDuration::try_from(options.settle_wait).unwrap_or_default();
    tokio::time::sleep(Duration::from_millis(200)).await;
    while recorder.has_in_flight() && Timestamp::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let quiescent = !recorder.has_in_flight();
    (recorder.calls(), quiescent)
}

fn payment_header(run: &Run<'_>) -> String {
    payment_header_with(run, Some(&fresh_payment_id()))
}

/// A fresh payment with the given payment identifier (`None` sends no id even when the extension is advertised).
fn payment_header_with(run: &Run<'_>, payment_id: Option<&str>) -> String {
    let mut body = json!({ "x402Version": 2, "accepted": run.offer_raw, "payload": run.mechanism.payload() });
    if let Some(echoed) = echoed_extensions(run.extensions.as_ref(), payment_id) {
        body["extensions"] = Value::Object(echoed);
    }
    STANDARD.encode(body.to_string())
}

async fn terms(ctx: &mut Context, findings: &mut Vec<Finding>) -> Option<(PaymentRequired, Value)> {
    let index = match ctx
        .client
        .send("unpaid request for the terms", ctx.resource_request(&[]))
        .await
    {
        Ok(index) => index,
        Err(error) => {
            findings.push(Finding::cannot_assess(
                &WIRED,
                format!("the target could not be reached: {error}"),
                &[],
            ));
            return None;
        }
    };
    let exchange = ctx.client.exchange(index);
    match (exchange.payment_required(), exchange.payment_required_json()) {
        (Some(terms), Some(raw)) if exchange.status == 402 => Some((terms, raw.clone())),
        _ => {
            findings.push(Finding::cannot_assess(
                &WIRED,
                format!(
                    "no usable 402 with PAYMENT-REQUIRED (status {}); run `probe` for the details",
                    exchange.status
                ),
                &[index],
            ));
            None
        }
    }
}
