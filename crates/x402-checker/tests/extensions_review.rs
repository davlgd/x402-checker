//! Fixtures proposed in review for the extension declaration checks: no HTTP, no payment.
use serde_json::json;
use x402_checker::check::Verdict;
use x402_checker::suites::extensions::declaration_checks;

#[test]
fn payment_identifier_required_defaults_to_false() {
    let findings = declaration_checks(
        &json!({"payment-identifier": {"info": {}, "schema": {"type":"object"}}}),
        None,
        &[],
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.check.id == "PAYID-INFO" && f.verdict == Verdict::Fail),
        "{findings:?}"
    );
}

#[test]
fn bazaar_reference_restriction_is_not_a_rule_for_other_extensions() {
    let findings = declaration_checks(
        &json!({"example-extension": {"info": {}, "schema": {"$id":"https://example.invalid/schema", "type":"object"}}}),
        None,
        &[],
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.check.id == "BAZAAR-SCHEMA-REFS" && f.verdict == Verdict::Fail),
        "{findings:?}"
    );
}

#[test]
fn a_literal_ref_key_in_an_example_is_not_a_schema_reference() {
    let findings = declaration_checks(
        &json!({"bazaar": {"info": {"input":{"type":"http","method":"GET"}}, "schema": {"type":"object", "properties":{"input":{"type":"object"}}, "required":["input"], "examples":[{"$ref":"this is example data"}]}}}),
        None,
        &[],
    );
    assert!(
        !findings
            .iter()
            .any(|f| f.check.id == "BAZAAR-SCHEMA-REFS" && f.verdict == Verdict::Fail),
        "{findings:?}"
    );
}
