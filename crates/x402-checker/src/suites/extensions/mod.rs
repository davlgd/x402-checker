//! What a server declares under `PaymentRequired.extensions` for the two extensions the tool knows: `bazaar`
//! (`spec/extensions_bazaar.md`) and `payment-identifier` (`spec/extensions_payment_identifier.md`).
//!
//! Everything here is judged from the 402 alone. The core pattern (`info` plus a `schema` that validates it) is
//! checked with a real JSON Schema validator. External `$ref`/`$id` values are refused for the Bazaar extension,
//! whose spec demands it; for the others they are reported and the validation is not attempted.

use serde_json::Value;

use super::{member, printable_ascii, short};
use crate::check::{Check, Finding, Level, Source, judge};

mod bazaar;

mod payid;

use bazaar::bazaar_checks;
#[cfg(test)]
use bazaar::{metadata_problems, route_template_problem};
use payid::payid_checks;
pub use payid::payment_identifier_required;

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

const SCHEMA_LOCAL: Check = check(
    "BAZAAR-SCHEMA-REFS",
    "an extension schema uses only same-document references",
    Level::Required,
    Source::ExplicitMust,
    "extensions/bazaar.md, Schema Validation: \"$ref and $id values must be same-document JSON Pointer fragments (starting with #); external references ... are not allowed\"",
);

const INFO_VALIDATES: Check = with_note(
    check(
        "CORE-019v",
        "an extension's info validates against its own schema",
        Level::Required,
        Source::Prose,
        "x402-specification-v2.md 5.1.2: schema \"JSON Schema defining the expected structure of info\"; extensions/bazaar.md: \"Facilitators must validate info against schema before cataloging\"",
    ),
    "the core text defines schema as describing info; a server whose info fails its own schema advertises something no facilitator would catalog. Sign-In with X is excluded: its example schema describes the client's proof, not the challenge",
);

/// Findings about the advertised extensions, from the raw `extensions` object of the 402.
pub fn declaration_checks(extensions: &Value, resource: Option<&Value>, ev: &[usize]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Some(map) = extensions.as_object() else {
        return findings;
    };
    findings.extend(schema_checks(map, ev));
    if let Some(bazaar) = map.get("bazaar") {
        findings.extend(bazaar_checks(bazaar, resource, ev));
    }
    if let Some(payid) = map.get("payment-identifier") {
        findings.extend(payid_checks(payid, ev));
    }
    findings
}

/// Self-validation of `info` against `schema` for every extension except Sign-In with X, and the Bazaar rule that
/// its schema references stay in the document. Another extension whose schema points outside the document is not
/// judged (the rule is Bazaar's), and its self-validation is reported as not assessable since the tool resolves
/// nothing remote.
fn schema_checks(map: &serde_json::Map<String, Value>, ev: &[usize]) -> Vec<Finding> {
    let mut invalid = Vec::new();
    let mut unresolved = Vec::new();
    let mut validated = 0usize;
    let mut findings = Vec::new();
    for (name, ext) in map {
        let (Some(info), Some(schema)) = (member(ext, "info"), member(ext, "schema")) else {
            continue; // CORE-019 already reports the missing objects
        };
        let mut refs = Vec::new();
        collect_refs(schema, &mut refs);
        let external: Vec<&String> = refs.iter().filter(|r| !r.starts_with('#')).collect();
        if name == "bazaar" {
            findings.push(judge(
                &SCHEMA_LOCAL,
                external.is_empty(),
                if external.is_empty() {
                    "no external $ref or $id".to_owned()
                } else {
                    format!(
                        "external: {}",
                        external.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                    )
                },
                ev,
            ));
        }
        if name == "sign-in-with-x" {
            continue;
        }
        if !external.is_empty() {
            unresolved.push(format!(
                "{name} (references {})",
                external.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
            ));
            continue;
        }
        validated += 1;
        match jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .build(schema)
        {
            Ok(validator) => {
                let errors: Vec<String> = validator
                    .iter_errors(info)
                    .map(|e| format!("{} at {}", e, e.instance_path()))
                    .take(3)
                    .collect();
                if !errors.is_empty() {
                    invalid.push(format!("{name}: {}", errors.join("; ")));
                }
            }
            Err(error) => invalid.push(format!("{name}: schema does not compile: {error}")),
        }
    }
    if validated > 0 {
        let detail = if invalid.is_empty() {
            format!("{validated} extension(s) validated")
        } else {
            invalid.join("; ")
        };
        findings.push(judge(&INFO_VALIDATES, invalid.is_empty(), detail, ev));
    }
    if !unresolved.is_empty() {
        findings.push(Finding::cannot_assess(
            &INFO_VALIDATES,
            format!(
                "not validated, the tool resolves no remote schema: {}",
                unresolved.join("; ")
            ),
            ev,
        ));
    }
    findings
}

/// `$ref` and `$id` values at schema positions. Data-bearing keywords (`const`, `enum`, `examples`, `default`) are
/// not descended into: a literal `$ref` key in an example is data, not a reference.
fn collect_refs(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if matches!(k.as_str(), "const" | "enum" | "examples" | "default") {
                    continue;
                }
                if (k == "$ref" || k == "$id")
                    && let Some(s) = v.as_str()
                {
                    out.push(s.to_owned());
                }
                collect_refs(v, out);
            }
        }
        Value::Array(items) => items.iter().for_each(|v| collect_refs(v, out)),
        _ => {}
    }
}

fn string<'a>(v: Option<&'a Value>, k: &str) -> Option<&'a str> {
    v.and_then(|v| member(v, k)).and_then(Value::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn route_templates() {
        assert_eq!(route_template_problem("/users/:userId"), None);
        assert_eq!(route_template_problem("/weather/:country/:city"), None);
        assert!(route_template_problem("users/:id").is_some());
        assert!(route_template_problem("/users/../admin").is_some());
        assert!(route_template_problem("/users/%2e%2e/admin").is_some());
        assert!(route_template_problem("/http://evil.com").is_some());
        assert!(route_template_problem("/a b").is_some());
        assert!(route_template_problem("").is_some());
    }

    #[test]
    fn metadata_drop_rules() {
        let ok = json!({ "serviceName": "site2md", "tags": ["markdown", "scraping"], "iconUrl": "https://example.com/icon.png" });
        assert!(metadata_problems(&ok).is_empty());
        let bad = json!({ "serviceName": "", "tags": ["a", "A", "b", "c", "d", "e", "f"], "iconUrl": "http://127.0.0.1/icon.png" });
        assert_eq!(metadata_problems(&bad).len(), 3);
        assert_eq!(
            metadata_problems(&json!({ "iconUrl": "https://user@example.com/x.png" })).len(),
            1
        );
        assert_eq!(
            metadata_problems(&json!({ "iconUrl": "https://localhost/x.png" })).len(),
            1
        );
    }

    #[test]
    fn the_spec_payment_identifier_declaration_passes() {
        let ext = json!({ "payment-identifier": { "info": { "required": false }, "schema": {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
            "properties": { "required": { "type": "boolean" }, "id": { "type": "string", "minLength": 16, "maxLength": 128 } },
            "required": ["required"] } } });
        let findings = declaration_checks(&ext, None, &[]);
        assert!(
            findings.iter().all(|f| matches!(
                f.verdict,
                crate::check::Verdict::Pass | crate::check::Verdict::Info
            )),
            "{findings:#?}"
        );
        assert_eq!(
            payment_identifier_required(Some(ext.as_object().unwrap())),
            Some(false)
        );
        // an absent required is the default, not a failure; a literal $ref inside an example is data
        let lax = json!({ "payment-identifier": { "info": {}, "schema": { "type": "object", "examples": [{ "$ref": "https://not-a-reference.example" }] } } });
        let findings = declaration_checks(&lax, None, &[]);
        assert!(
            findings.iter().all(|f| matches!(
                f.verdict,
                crate::check::Verdict::Pass | crate::check::Verdict::Info
            )),
            "{findings:#?}"
        );
    }

    #[test]
    fn a_bazaar_declaration_whose_info_breaks_its_schema_fails() {
        let ext = json!({ "bazaar": {
            "info": { "input": { "type": "http", "method": "POST", "bodyType": "json", "body": { "q": "x" } }, "output": { "type": "json" } },
            "schema": { "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object", "required": ["input"],
                "properties": { "input": { "type": "object", "required": ["type", "method"], "properties": { "type": { "const": "http" }, "method": { "enum": ["GET"] } } } } }
        } });
        let findings = declaration_checks(&ext, None, &[]);
        let by_id = |id: &str| findings.iter().find(|f| f.check.id == id).map(|f| f.verdict);
        assert_eq!(by_id("BAZAAR-INPUT"), Some(crate::check::Verdict::Pass));
        assert_eq!(
            by_id("BAZAAR-SCHEMA"),
            Some(crate::check::Verdict::CannotAssess),
            "info is rejected by its own schema, nothing to infer"
        );
        // a schema that requires input but constrains nothing inside it
        let loose = json!({ "bazaar": {
            "info": { "input": { "type": "http", "method": "GET" } },
            "schema": { "type": "object", "required": ["input"], "properties": { "input": { "type": "object" } } }
        } });
        let loose_findings = declaration_checks(&loose, None, &[]);
        let schema_finding = loose_findings
            .iter()
            .find(|f| f.check.id == "BAZAAR-SCHEMA")
            .unwrap();
        assert_eq!(
            schema_finding.verdict,
            crate::check::Verdict::Fail,
            "{}",
            schema_finding.detail
        );
        assert!(
            schema_finding.detail.contains("neither http nor mcp")
                && schema_finding.detail.contains("method")
        );
        // the same constraints through allOf and a local $ref are judged by what they reject, not by their form
        let by_ref = json!({ "bazaar": {
            "info": { "input": { "type": "http", "method": "GET" } },
            "schema": { "$schema": "https://json-schema.org/draft/2020-12/schema", "type": "object",
                "allOf": [{ "$ref": "#/$defs/hasInput" }],
                "$defs": { "hasInput": { "required": ["input"], "properties": { "input": { "type": "object", "required": ["type", "method"],
                    "properties": { "type": { "const": "http" }, "method": { "enum": ["GET", "HEAD", "DELETE"] } } } } } } }
        } });
        let f = declaration_checks(&by_ref, None, &[]);
        let schema_finding = f.iter().find(|f| f.check.id == "BAZAAR-SCHEMA").unwrap();
        assert_eq!(
            schema_finding.verdict,
            crate::check::Verdict::Pass,
            "{}",
            schema_finding.detail
        );
        // when the schema rejects the info itself, rejections of counter-examples prove nothing
        let f = declaration_checks(&ext, None, &[]);
        assert_eq!(
            f.iter().find(|f| f.check.id == "BAZAAR-SCHEMA").unwrap().verdict,
            crate::check::Verdict::CannotAssess
        );
        assert_eq!(
            by_id("CORE-019v"),
            Some(crate::check::Verdict::Fail),
            "POST is not in the schema's method enum"
        );
        let external = json!({ "bazaar": { "info": { "input": { "type": "http", "method": "GET" } }, "schema": { "$ref": "https://evil.example/schema.json" } } });
        let findings = declaration_checks(&external, None, &[]);
        assert_eq!(
            findings
                .iter()
                .find(|f| f.check.id == "BAZAAR-SCHEMA-REFS")
                .unwrap()
                .verdict,
            crate::check::Verdict::Fail
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.check.id == "CORE-019v")
                .unwrap()
                .verdict,
            crate::check::Verdict::CannotAssess,
            "nothing remote is resolved"
        );
        // another extension may reference outside the document: not judged by the Bazaar rule, not validated either
        let other = json!({ "custom": { "info": { "a": 1 }, "schema": { "$ref": "https://schemas.example/custom.json" } } });
        let findings = declaration_checks(&other, None, &[]);
        assert!(findings.iter().all(|f| f.check.id != "BAZAAR-SCHEMA-REFS"));
        assert_eq!(
            findings
                .iter()
                .find(|f| f.check.id == "CORE-019v")
                .unwrap()
                .verdict,
            crate::check::Verdict::CannotAssess
        );
    }
}
