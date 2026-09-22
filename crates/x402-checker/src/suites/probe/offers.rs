//! What a 402 offers: the `accepts[]` entries field by field, then what the EVM and Solana bindings of `exact` add
//! to their offers, and the bounds of `ResourceInfo`. Pure functions over the raw JSON of the challenge.

use super::{
    CORE_5_1_07, CORE_5_1_08, CORE_5_1_09, CORE_5_1_13, CORE_5_1_16, Caip2, Check, EVM_ADDRESSES, EVM_EXTRA,
    EVM_METHODS, Finding, SVM_ADDRESSES, SVM_FEE_PAYER, SVM_FLOW, SVM_HINTS, Value, decimal_integer, judge,
    member, printable_ascii, short,
};

pub(super) fn resource_bounds(resource: &Value, ev: &[usize]) -> Finding {
    let mut problems = Vec::new();
    for key in ["description", "mimeType"] {
        if let Some(v) = member(resource, key)
            && !v.is_string()
        {
            problems.push(format!("{key} is {}", json_kind(v)));
        }
    }
    match member(resource, "serviceName") {
        None => {}
        Some(Value::String(s)) if printable_ascii(s) && s.len() <= 32 => {}
        Some(v) => problems.push(format!(
            "serviceName must be printable ASCII of at most 32 characters, got {}",
            short(&v.to_string())
        )),
    }
    match member(resource, "tags") {
        None => {}
        Some(Value::Array(tags))
            if tags.len() <= 5
                && tags
                    .iter()
                    .all(|t| t.as_str().is_some_and(|t| printable_ascii(t) && t.len() <= 32)) => {}
        Some(v) => problems.push(format!(
            "tags must be at most 5 printable ASCII strings of at most 32 characters, got {}",
            short(&v.to_string())
        )),
    }
    match member(resource, "iconUrl") {
        None => {}
        Some(Value::String(s)) if s.chars().count() <= 2048 && is_absolute_http_url(s) => {}
        Some(v) => problems.push(format!(
            "iconUrl must be an absolute http(s) URL with a host, of at most 2048 characters, got {}",
            short(&v.to_string())
        )),
    }
    judge(
        &CORE_5_1_16,
        problems.is_empty(),
        if problems.is_empty() {
            "within bounds".to_owned()
        } else {
            problems.join("; ")
        },
        ev,
    )
}

/// Absolute `http` or `https` URL with a host, as `iconUrl` requires.
fn is_absolute_http_url(text: &str) -> bool {
    url::Url::parse(text)
        .is_ok_and(|u| matches!(u.scheme(), "http" | "https") && u.host_str().is_some_and(|h| !h.is_empty()))
}

pub(super) fn offer_checks(offers: &[Value], ev: &[usize]) -> Vec<Finding> {
    let mut shape = Vec::new();
    let mut networks = Vec::new();
    let mut amounts = Vec::new();
    let mut reserved = Vec::new();
    let (mut networks_seen, mut amounts_seen) = (0usize, 0usize);

    for (i, offer) in offers.iter().enumerate() {
        let string = |k: &str| member(offer, k).and_then(Value::as_str);
        for k in ["scheme", "network", "amount", "asset", "payTo"] {
            if string(k).is_none() {
                shape.push(format!("accepts[{i}].{k} missing or not a string"));
            }
        }
        if !member(offer, "maxTimeoutSeconds").is_some_and(Value::is_number) {
            shape.push(format!("accepts[{i}].maxTimeoutSeconds missing or not a number"));
        }
        if let Some(extra) = member(offer, "extra")
            && !extra.is_object()
        {
            shape.push(format!("accepts[{i}].extra is {}", json_kind(extra)));
        }
        if let Some(n) = string("network") {
            networks_seen += 1;
            if n.parse::<Caip2>().is_err() {
                networks.push(format!("accepts[{i}].network = {n:?}"));
            }
        }
        if let Some(a) = string("amount") {
            amounts_seen += 1;
            if !decimal_integer(a) {
                amounts.push(format!("accepts[{i}].amount = {a:?}"));
            }
        }
        let extra = member(offer, "extra").and_then(Value::as_object);
        if let Some(flow) = extra.and_then(|e| e.get("paymentFlow"))
            && !matches!(flow.as_str(), Some("authorization" | "upfront" | "escrow"))
        {
            reserved.push(format!("accepts[{i}].extra.paymentFlow = {flow}"));
        }
        if let Some(method) = extra.and_then(|e| e.get("assetTransferMethod"))
            && !method.is_string()
        {
            reserved.push(format!("accepts[{i}].extra.assetTransferMethod = {method}"));
        }
    }

    let counted = |check: &Check, seen: usize, problems: &[String], ok: &str| {
        if seen == 0 {
            Finding::skip(check, "no string value to validate (see CORE-5.1-07)")
        } else {
            judge(
                check,
                problems.is_empty(),
                ok_or(problems, format!("{ok} ({seen} checked)")),
                ev,
            )
        }
    };
    let mut findings = vec![
        judge(
            &CORE_5_1_07,
            shape.is_empty(),
            ok_or(&shape, format!("{} offer(s) well-formed", offers.len())),
            ev,
        ),
        counted(&CORE_5_1_08, networks_seen, &networks, "all CAIP-2"),
        counted(&CORE_5_1_09, amounts_seen, &amounts, "all decimal integers"),
        judge(
            &CORE_5_1_13,
            reserved.is_empty(),
            ok_or(&reserved, "reserved keys absent or valid".into()),
            ev,
        ),
    ];
    findings.extend(evm_offer_checks(offers, ev));
    findings.extend(svm_offer_checks(offers, ev));
    findings
}

/// What the Solana binding of `exact` adds for offers on `solana` networks.
fn svm_offer_checks(offers: &[Value], ev: &[usize]) -> Vec<Finding> {
    let mut seen = 0usize;
    let mut missing_fee_payer = Vec::new();
    let mut bad_addresses = Vec::new();
    let mut bad_hints = Vec::new();
    let mut flows = Vec::new();

    for (i, offer) in offers.iter().enumerate() {
        let string = |k: &str| member(offer, k).and_then(Value::as_str);
        let svm = string("network")
            .and_then(|n| n.parse::<Caip2>().ok())
            .is_some_and(|n| n.is_svm());
        if string("scheme") != Some("exact") || !svm {
            continue;
        }
        seen += 1;
        let extra = member(offer, "extra").and_then(Value::as_object);
        let extra_str = |k: &str| extra.and_then(|e| e.get(k));
        match extra_str("feePayer").and_then(Value::as_str) {
            Some(f) if x402_checker_types::base58::is_public_key(f) => {}
            Some(f) => missing_fee_payer.push(format!(
                "accepts[{i}].extra.feePayer = {f:?} is not a base58 public key"
            )),
            None => missing_fee_payer.push(format!("accepts[{i}].extra.feePayer absent")),
        }
        for k in ["asset", "payTo"] {
            if !string(k).is_some_and(x402_checker_types::base58::is_public_key) {
                bad_addresses.push(format!("accepts[{i}].{k} = {:?}", string(k).unwrap_or_default()));
            }
        }
        if let Some(memo) = extra_str("memo") {
            match memo.as_str() {
                Some(m) if m.len() <= 256 => {}
                Some(m) => bad_hints.push(format!("accepts[{i}].extra.memo is {} bytes", m.len())),
                None => bad_hints.push(format!("accepts[{i}].extra.memo is {}", json_kind(memo))),
            }
        }
        if let Some(hash) = extra_str("recentBlockhash")
            && !hash
                .as_str()
                .is_some_and(x402_checker_types::base58::is_public_key)
        {
            bad_hints.push(format!(
                "accepts[{i}].extra.recentBlockhash = {hash} is not a base58 32-byte hash"
            ));
        }
        if let Some(height) = extra_str("lastValidBlockHeight")
            && !height.as_str().is_some_and(decimal_integer)
        {
            bad_hints.push(format!(
                "accepts[{i}].extra.lastValidBlockHeight = {height} is not a decimal string"
            ));
        }
        flows.push(format!(
            "accepts[{i}]: {}",
            extra_str("paymentFlow")
                .and_then(Value::as_str)
                .unwrap_or("authorization (default)")
        ));
    }

    if seen == 0 {
        let why = "no exact offer on a solana network";
        return vec![
            Finding::cannot_assess(&SVM_FEE_PAYER, why, ev),
            Finding::cannot_assess(&SVM_ADDRESSES, why, ev),
            Finding::cannot_assess(&SVM_HINTS, why, ev),
            Finding::cannot_assess(&SVM_FLOW, why, ev),
        ];
    }
    vec![
        judge(
            &SVM_FEE_PAYER,
            missing_fee_payer.is_empty(),
            ok_or(
                &missing_fee_payer,
                format!("{seen} solana offer(s), each with a base58 fee payer"),
            ),
            ev,
        ),
        judge(
            &SVM_ADDRESSES,
            bad_addresses.is_empty(),
            ok_or(&bad_addresses, "base58 32-byte mint and merchant keys".into()),
            ev,
        ),
        judge(
            &SVM_HINTS,
            bad_hints.is_empty(),
            ok_or(&bad_hints, "hints absent or well formed".into()),
            ev,
        ),
        Finding::info(&SVM_FLOW, flows.join("; "), ev),
    ]
}

/// What the EVM binding of `exact` adds for offers on `eip155` networks.
fn evm_offer_checks(offers: &[Value], ev: &[usize]) -> Vec<Finding> {
    let mut missing_extra = Vec::new();
    let mut bad_addresses = Vec::new();
    let mut methods = Vec::new();
    let mut eip3009_offers = 0usize;

    for (i, offer) in offers.iter().enumerate() {
        let string = |k: &str| member(offer, k).and_then(Value::as_str);
        let evm = string("network")
            .and_then(|n| n.parse::<Caip2>().ok())
            .is_some_and(|n| n.is_evm());
        if string("scheme") != Some("exact") || !evm {
            continue;
        }
        let extra = member(offer, "extra").and_then(Value::as_object);
        let method = extra
            .and_then(|e| e.get("assetTransferMethod"))
            .and_then(Value::as_str)
            .unwrap_or("eip3009 (default)");
        methods.push(format!("accepts[{i}]: {method}"));
        if method.starts_with("eip3009") {
            eip3009_offers += 1;
            for k in ["name", "version"] {
                if !extra.and_then(|e| e.get(k)).is_some_and(Value::is_string) {
                    missing_extra.push(format!("accepts[{i}].extra.{k}"));
                }
            }
        }
        for k in ["asset", "payTo"] {
            if !string(k).is_some_and(is_hex_address) {
                bad_addresses.push(format!("accepts[{i}].{k} = {:?}", string(k).unwrap_or_default()));
            }
        }
    }

    if methods.is_empty() {
        let why = "no exact offer on an eip155 network";
        return vec![
            Finding::cannot_assess(&EVM_EXTRA, why, ev),
            Finding::cannot_assess(&EVM_ADDRESSES, why, ev),
        ];
    }
    let extra = if eip3009_offers == 0 {
        Finding::cannot_assess(
            &EVM_EXTRA,
            "no eip3009 offer; name and version are only conditional for permit2 and not needed for erc7710",
            ev,
        )
    } else {
        judge(
            &EVM_EXTRA,
            missing_extra.is_empty(),
            ok_or(
                &missing_extra,
                format!("name and version present ({eip3009_offers} eip3009 offer(s))"),
            ),
            ev,
        )
    };
    vec![
        extra,
        judge(
            &EVM_ADDRESSES,
            bad_addresses.is_empty(),
            ok_or(
                &bad_addresses,
                format!("asset and payTo are addresses ({} offer(s))", methods.len()),
            ),
            ev,
        ),
        Finding::info(&EVM_METHODS, methods.join("; "), ev),
    ]
}

/// `ok` when there is no problem, the problems joined otherwise.
fn ok_or(problems: &[String], ok: String) -> String {
    if problems.is_empty() {
        ok
    } else {
        problems.join("; ")
    }
}

pub(super) fn is_hex_address(text: &str) -> bool {
    text.len() == 42 && text.starts_with("0x") && text[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

pub(super) fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}
