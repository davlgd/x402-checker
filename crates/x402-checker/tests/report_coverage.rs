//! Coverage and attribution rules of the report, as proposed in review: no HTTP, no payment.

use jiff::Timestamp;
use x402_checker::check::{Attribution, Check, Finding, Level, Source, SuiteResult};
use x402_checker::report::{Outcome, Report};

const REQUIRED: Check = Check {
    id: "REVIEW-REQUIRED",
    title: "an obligation with no available observation",
    level: Level::Required,
    source: Source::FieldTable,
    clause: "review fixture",
    ambiguity: None,
};
const OBSERVED: Check = Check {
    id: "REVIEW-OBSERVED",
    ..REQUIRED
};

fn report(findings: Vec<Finding>, strict: bool) -> Report {
    Report::build(
        "local report fixture".into(),
        Timestamp::now(),
        strict,
        vec![SuiteResult::new("review", findings)],
        vec![],
        vec![],
    )
}

#[test]
fn a_dependency_failure_alone_provides_no_conformance_evidence() {
    let actual = report(
        vec![Finding::blocked(
            &REQUIRED,
            Attribution::Dependency,
            "RPC unavailable",
            &[],
        )],
        false,
    );
    assert_eq!(actual.outcome, Outcome::CannotAssess);
    assert_eq!(actual.exit_code, 2);
}

#[test]
fn an_unassessed_required_check_remains_in_the_coverage_report() {
    let actual = report(
        vec![
            Finding::pass(&OBSERVED, "observed one different property", &[]),
            Finding::cannot_assess(&REQUIRED, "no supported verifier", &[]),
        ],
        true,
    );
    assert!(actual.summary.incomplete.iter().any(|id| id == REQUIRED.id));
    assert_ne!(
        actual.exit_code, 0,
        "strict coverage cannot succeed with a missing required observation"
    );
}
