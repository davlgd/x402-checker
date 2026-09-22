//! The suites (`probe`, `pay`, `scenarios`: a `run` function returning a [`crate::check::SuiteResult`]) and the
//! check groups they share: `extensions` (declarations in a 402, `declaration_checks`) and `ledger` (a receipt read
//! on chain, `verify`, also the `ledger` command).

pub mod extensions;
pub mod ledger;
pub mod pay;
pub mod probe;
pub mod scenarios;

use serde_json::Value;

/// A JSON member by key when the value is an object.
pub(crate) fn member<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    value.as_object().and_then(|o| o.get(key))
}

/// Whether every character is printable ASCII (0x20 to 0x7E).
pub(crate) fn printable_ascii(text: &str) -> bool {
    text.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

/// Whether the text is a non-empty string of ASCII digits.
pub(crate) fn decimal_integer(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// The first 80 characters of a text, with an ellipsis when it was longer.
pub(crate) fn short(text: &str) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(80).collect();
    if chars.next().is_some() {
        format!("{head}\u{2026}")
    } else {
        head
    }
}

/// The `extensions` object a client echoes, with a fresh `payment-identifier` id appended when the server advertises
/// that extension (`spec/extensions_payment_identifier.md`, `PaymentPayload`: "Client echoes the extension and appends
/// an id"). `None` when there is nothing to echo.
pub(crate) fn echoed_extensions(
    advertised: Option<&x402_checker_types::Extensions>,
    payment_id: Option<&str>,
) -> Option<serde_json::Map<String, Value>> {
    let mut echoed = advertised.filter(|e| !e.is_empty())?.clone();
    if let (Some(id), Some(Value::Object(ext))) = (payment_id, echoed.get_mut("payment-identifier"))
        && let Some(Value::Object(info)) = ext.get_mut("info")
    {
        info.insert("id".to_owned(), Value::String(id.to_owned()));
    }
    Some(echoed)
}

/// A fresh payment identifier in the recommended form: a `pay_` prefix and 32 hex characters.
pub(crate) fn fresh_payment_id() -> String {
    format!(
        "pay_{}",
        alloy_primitives::hex::encode(x402_checker_evm::random_nonce().0)
            .chars()
            .take(32)
            .collect::<String>()
    )
}
