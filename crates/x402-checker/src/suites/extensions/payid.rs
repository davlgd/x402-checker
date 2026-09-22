//! The `payment-identifier` extension (`spec/extensions_payment_identifier.md`): what the server declares about
//! idempotency keys.

use super::{Check, Finding, Level, Source, Value, check, judge, member, with_note};

const PAYID_INFO: Check = with_note(
    check(
        "PAYID-INFO",
        "payment-identifier info.required, when present, is a boolean",
        Level::Required,
        Source::FieldTable,
        "extensions/payment_identifier.md, `required` Field: Type boolean, Default false",
    ),
    "the example schema lists required among its required members while the field table gives it a default; an absent value is read as false, not as a failure",
);

const PAYID_SCHEMA: Check = check(
    "PAYID-SCHEMA",
    "how the payment-identifier schema expresses the 16..128 character bound on id",
    Level::Optional,
    Source::Example,
    "extensions/payment_identifier.md, `id` Format: Length 16-128 characters; the example schema uses minLength 16 and maxLength 128",
);

pub(super) fn payid_checks(payid: &Value, ev: &[usize]) -> Vec<Finding> {
    let info = member(payid, "info");
    let required = info.and_then(|i| member(i, "required"));
    let id_schema = member(payid, "schema")
        .and_then(|s| member(s, "properties"))
        .and_then(|p| member(p, "id"));
    let as_example = id_schema.is_some_and(|s| {
        member(s, "minLength").and_then(Value::as_u64) == Some(16)
            && member(s, "maxLength").and_then(Value::as_u64) == Some(128)
    });
    vec![
        judge(
            &PAYID_INFO,
            required.is_none_or(Value::is_boolean),
            format!(
                "info.required = {}",
                required.map_or("absent (defaults to false)".into(), Value::to_string)
            ),
            ev,
        ),
        Finding::info(
            &PAYID_SCHEMA,
            if as_example {
                "minLength 16, maxLength 128 as in the example".to_owned()
            } else {
                format!(
                    "schema.properties.id = {}",
                    id_schema.map_or("absent".into(), |s| super::short(&s.to_string()))
                )
            },
            ev,
        ),
    ]
}

/// Whether the server requires a payment identifier (`info.required` true).
pub fn payment_identifier_required(extensions: Option<&x402_checker_types::Extensions>) -> Option<bool> {
    let ext = extensions?.get("payment-identifier")?;
    member(ext, "info")?.get("required")?.as_bool()
}
