//! The `bazaar` extension (`spec/extensions_bazaar.md`): the discovery `info`, its schema, the route template and
//! the service metadata of `resource`.

use super::{Check, Finding, Level, Source, Value, check, judge, member, printable_ascii, string, with_note};

const BAZAAR_INPUT: Check = check(
    "BAZAAR-INPUT",
    "bazaar info.input follows the http or mcp structure of the spec",
    Level::Required,
    Source::FieldTable,
    "extensions/bazaar.md, Discovery Info Structure: input.type http with method GET/HEAD/DELETE, or POST/PUT/PATCH with bodyType (json, form-data, text) and body; input.type mcp with toolName and inputSchema",
);

const BAZAAR_OUTPUT: Check = check(
    "BAZAAR-OUTPUT",
    "bazaar info.output, when present, has a string type",
    Level::Required,
    Source::FieldTable,
    "extensions/bazaar.md, Output Types: type string Yes; format string No; example any No",
);

const BAZAAR_SCHEMA_SHAPE: Check = with_note(
    check(
        "BAZAAR-SCHEMA",
        "the bazaar schema requires input and actually constrains input.type, the HTTP method or the MCP fields",
        Level::Required,
        Source::ExplicitMust,
        "extensions/bazaar.md, Schema Validation: \"Must use JSON Schema Draft 2020-12\", \"Must define an input property (required)\", \"Must validate that input.type equals http ... or mcp\", \"Must validate the appropriate method enum\", \"Must require toolName and inputSchema\"",
    ),
    "the constraints are checked by asking the schema to reject counter-examples (a foreign input.type, a method outside the enum, an mcp input without toolName or inputSchema): what the schema accepts, it does not constrain",
);

const BAZAAR_ROUTE_TEMPLATE: Check = with_note(
    check(
        "BAZAAR-ROUTE",
        "routeTemplate, when present, is a template a facilitator keeps",
        Level::Recommended,
        Source::ExplicitMust,
        "extensions/bazaar.md, routeTemplate Validation Rules: non-empty, starts with /, matches ^/[a-zA-Z0-9_/:.\\-~%]+$, no .. and no :// after percent-decoding",
    ),
    "the rules are the facilitator's drop rules; a server that breaks them is catalogued under the concrete path instead, so the tool warns",
);

const BAZAAR_METADATA: Check = with_note(
    check(
        "BAZAAR-META",
        "service metadata on resource survives the facilitator's soft-drop rules",
        Level::Recommended,
        Source::ExplicitMust,
        "extensions/bazaar.md, Service Metadata Validation Rules: serviceName printable ASCII non-empty, at most 32; tags at most 5, each printable ASCII non-empty at most 32, deduplicated case-insensitively; iconUrl absolute http(s), no userinfo, not an IP literal or localhost, at most 2048",
    ),
    "the core bounds are CORE-016 (required); these are the stricter Bazaar drop rules, so the tool warns when a field would be dropped from the catalogue",
);

/// Why `info.input` does not follow the http or mcp structure, or `None` when it does.
pub(super) fn input_problem(input: Option<&Value>) -> Option<String> {
    match string(input, "type") {
        None => Some("input.type missing or not a string".to_owned()),
        Some("http") => match string(input, "method") {
            Some("GET" | "HEAD" | "DELETE") => None,
            Some("POST" | "PUT" | "PATCH") => {
                let body_type = string(input, "bodyType");
                let body = input.and_then(|i| member(i, "body"));
                if !matches!(body_type, Some("json" | "form-data" | "text")) {
                    Some(format!(
                        "bodyType must be json, form-data or text, got {body_type:?}"
                    ))
                } else if !body.is_some_and(|b| b.is_object() || b.is_string()) {
                    Some("body (object or string) is required for body methods".to_owned())
                } else {
                    None
                }
            }
            other => Some(format!(
                "method must be GET, HEAD, DELETE, POST, PUT or PATCH, got {other:?}"
            )),
        },
        Some("mcp") => {
            if string(input, "toolName").is_none() {
                Some("toolName is required for mcp".to_owned())
            } else if !input
                .and_then(|i| member(i, "inputSchema"))
                .is_some_and(Value::is_object)
            {
                Some("inputSchema (object) is required for mcp".to_owned())
            } else {
                None
            }
        }
        Some(other) => Some(format!("input.type must be http or mcp, got {other:?}")),
    }
}

/// The Bazaar schema: dialect, and the constraints the text demands, established by having the schema reject
/// counter-examples built from the server's own `info` (which the schema must accept first, or nothing can be
/// inferred from the rejections). No syntactic form is required: a schema expressing the same constraints through
/// `allOf` or local `$ref` is judged by what it rejects.
pub(super) fn bazaar_schema_check(schema: Option<&Value>, info: Option<&Value>, ev: &[usize]) -> Finding {
    let Some(schema) = schema else {
        return Finding::fail(&BAZAAR_SCHEMA_SHAPE, "no schema", ev);
    };
    let mut problems = Vec::new();
    match member(schema, "$schema").and_then(Value::as_str) {
        None
        | Some(
            "https://json-schema.org/draft/2020-12/schema" | "https://json-schema.org/draft/2020-12/schema#",
        ) => {}
        Some(other) => problems.push(format!("$schema is {other}, not Draft 2020-12")),
    }
    let Ok(validator) = jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(schema)
    else {
        problems.push("the schema does not compile".to_owned());
        return Finding::fail(&BAZAAR_SCHEMA_SHAPE, problems.join("; "), ev);
    };
    let Some(info) = info.filter(|i| i.is_object()) else {
        return Finding::cannot_assess(
            &BAZAAR_SCHEMA_SHAPE,
            "no info object to derive counter-examples from",
            ev,
        );
    };
    if !validator.is_valid(info) {
        return Finding::cannot_assess(
            &BAZAAR_SCHEMA_SHAPE,
            "info itself is rejected by the schema (see CORE-019v), so rejections of counter-examples would prove nothing",
            ev,
        );
    }
    let rejects = |mutate: &dyn Fn(&mut Value)| {
        let mut counter = info.clone();
        mutate(&mut counter);
        !validator.is_valid(&counter)
    };
    let set = |path: &'static str, value: Value| {
        move |v: &mut Value| {
            if let Some(target) = v.pointer_mut(path) {
                *target = value.clone();
            }
        }
    };
    let remove_input_key = |key: &'static str| {
        move |v: &mut Value| {
            if let Some(input) = v.pointer_mut("/input").and_then(Value::as_object_mut) {
                input.remove(key);
            }
        }
    };
    let mut tried = vec!["info without input"];
    if !rejects(&|v: &mut Value| {
        if let Some(o) = v.as_object_mut() {
            o.remove("input");
        }
    }) {
        problems.push("the schema accepts an info without input".to_owned());
    }
    tried.push("a foreign input.type");
    if !rejects(&set("/input/type", Value::String("not-a-type".into()))) {
        problems.push("the schema accepts an input.type that is neither http nor mcp".to_owned());
    }
    match info.pointer("/input/type").and_then(Value::as_str) {
        Some("http") => {
            tried.push("a method outside the HTTP enum");
            if !rejects(&set("/input/method", Value::String("TRACE".into()))) {
                problems.push("the schema accepts a method outside the HTTP enum".to_owned());
            }
        }
        Some("mcp") => {
            tried.push("an mcp input without toolName, then without inputSchema");
            if !rejects(&remove_input_key("toolName")) {
                problems.push("the schema does not require toolName".to_owned());
            }
            if !rejects(&remove_input_key("inputSchema")) {
                problems.push("the schema does not require inputSchema".to_owned());
            }
        }
        _ => {}
    }
    let dialect =
        member(schema, "$schema").map_or(" ($schema absent: validated as Draft 2020-12 by choice)", |_| "");
    let ok = format!(
        "info accepted; the schema rejects the counter-examples tried ({}){dialect}; nothing more is claimed about the schema",
        tried.join(", ")
    );
    judge(
        &BAZAAR_SCHEMA_SHAPE,
        problems.is_empty(),
        if problems.is_empty() {
            ok
        } else {
            problems.join("; ")
        },
        ev,
    )
}

pub(super) fn bazaar_checks(bazaar: &Value, resource: Option<&Value>, ev: &[usize]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let info = member(bazaar, "info");
    let input = info.and_then(|i| member(i, "input"));
    let input_problem = input_problem(input);
    findings.push(judge(
        &BAZAAR_INPUT,
        input_problem.is_none(),
        input_problem.unwrap_or_else(|| {
            format!(
                "input.type {}, method {}",
                string(input, "type").unwrap_or("?"),
                string(input, "method")
                    .or(string(input, "toolName"))
                    .unwrap_or("?")
            )
        }),
        ev,
    ));
    if let Some(output) = info.and_then(|i| member(i, "output")) {
        findings.push(judge(
            &BAZAAR_OUTPUT,
            member(output, "type").is_some_and(Value::is_string),
            format!("output = {}", super::short(&output.to_string())),
            ev,
        ));
    }
    findings.push(bazaar_schema_check(member(bazaar, "schema"), info, ev));
    if let Some(template) = member(bazaar, "routeTemplate") {
        let problem = template.as_str().map_or(Some("not a string".to_owned()), |t| {
            route_template_problem(t).map(str::to_owned)
        });
        findings.push(judge(
            &BAZAAR_ROUTE_TEMPLATE,
            problem.is_none(),
            problem.unwrap_or_else(|| format!("routeTemplate {template}")),
            ev,
        ));
    }
    if let Some(resource) = resource {
        let problems = metadata_problems(resource);
        findings.push(judge(
            &BAZAAR_METADATA,
            problems.is_empty(),
            if problems.is_empty() {
                "would be kept by a facilitator".to_owned()
            } else {
                problems.join("; ")
            },
            ev,
        ));
    }
    findings
}

/// The facilitator's `routeTemplate` rules, applied after percent-decoding for the traversal and scheme checks.
pub(super) fn route_template_problem(template: &str) -> Option<&'static str> {
    if template.is_empty() {
        return Some("empty");
    }
    if !template.starts_with('/') {
        return Some("does not start with /");
    }
    if !template
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_/:.-~%".contains(&b))
    {
        return Some("contains a character outside ^/[a-zA-Z0-9_/:.\\-~%]+$");
    }
    let decoded = percent_decode(template);
    if decoded.contains("..") {
        return Some("contains .. after percent-decoding");
    }
    if decoded.contains("://") {
        return Some("contains :// after percent-decoding");
    }
    None
}

pub(super) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&text[i + 1..i + 3], 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The Bazaar soft-drop rules on `resource.serviceName`, `tags` and `iconUrl`.
pub(super) fn metadata_problems(resource: &Value) -> Vec<String> {
    let mut problems = Vec::new();
    if let Some(name) = member(resource, "serviceName") {
        match name.as_str() {
            Some(n) if !n.is_empty() && printable_ascii(n) && n.len() <= 32 => {}
            _ => problems
                .push("serviceName would be dropped (non-empty printable ASCII, at most 32)".to_owned()),
        }
    }
    if let Some(tags) = member(resource, "tags") {
        match tags.as_array() {
            Some(tags) => {
                let valid: Vec<&str> = tags
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|t| !t.is_empty() && printable_ascii(t) && t.len() <= 32)
                    .collect();
                let mut seen: Vec<String> = Vec::new();
                for tag in &valid {
                    let lower = tag.to_ascii_lowercase();
                    if !seen.contains(&lower) {
                        seen.push(lower);
                    }
                }
                if valid.len() != tags.len() || seen.len() != valid.len() || tags.len() > 5 {
                    problems.push(format!(
                        "tags: {} of {} would be kept (invalid, duplicate or beyond 5 dropped)",
                        seen.len().min(5),
                        tags.len()
                    ));
                }
            }
            None => problems.push("tags is not an array".to_owned()),
        }
    }
    if let Some(icon) = member(resource, "iconUrl") {
        let ok = icon.as_str().is_some_and(|s| {
            s.chars().count() <= 2048
                && url::Url::parse(s).is_ok_and(|u| {
                    matches!(u.scheme(), "http" | "https")
                        && u.username().is_empty()
                        && u.password().is_none()
                        && match u.host() {
                            Some(url::Host::Domain(d)) => {
                                !matches!(
                                    d,
                                    "localhost" | "localhost.localdomain" | "ip6-localhost" | "ip6-loopback"
                                ) && !d.bytes().all(|b| b.is_ascii_digit())
                                    && !d.starts_with("0x")
                            }
                            _ => false,
                        }
                })
        });
        if !ok {
            problems.push("iconUrl would be dropped (absolute http(s) URL, no userinfo, a domain name that is neither an IP literal nor localhost, at most 2048 characters)".to_owned());
        }
    }
    problems
}
