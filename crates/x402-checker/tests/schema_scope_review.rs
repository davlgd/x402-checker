//! Fixtures proposed in review for the Bazaar schema check: composition through allOf, and an info the schema rejects.
use serde_json::json;
use x402_checker::check::Verdict;
use x402_checker::suites::extensions::declaration_checks;
#[test]
fn composed_schema_defines_and_requires_input() {
    let value = json!({"bazaar":{"info":{"input":{"type":"http","method":"GET"}},"schema":{"allOf":[{"type":"object","properties":{"input":{"type":"object","properties":{"type":{"const":"http"},"method":{"enum":["GET"]}},"required":["type","method"]}},"required":["input"]}]}}});
    let findings = declaration_checks(&value, None, &[]);
    assert!(
        !findings
            .iter()
            .any(|f| f.check.id == "BAZAAR-SCHEMA" && f.verdict == Verdict::Fail),
        "{findings:?}"
    );
}
#[test]
fn invalid_baseline_cannot_prove_schema_constraints() {
    let value = json!({"bazaar":{"info":{"input":{"type":"http","method":"GET"}},"schema":{"type":"object","properties":{"input":{"type":"object"},"marker":{"const":"ok"}},"required":["input","marker"]}}});
    let findings = declaration_checks(&value, None, &[]);
    assert!(
        !findings
            .iter()
            .any(|f| f.check.id == "BAZAAR-SCHEMA" && f.verdict == Verdict::Pass),
        "{findings:?}"
    );
}
