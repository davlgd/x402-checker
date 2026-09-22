//! The report: findings, evidence, scope, outcome and exit code.

use jiff::Timestamp;
use serde::Serialize;

use crate::check::{Level, SuiteResult, Verdict};
use crate::http::Exchange;

/// Bumped when the JSON layout changes in a way a consumer must know about.
pub const SCHEMA_VERSION: u32 = 1;

/// The overall outcome of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// No required check failed in the executed scope.
    Conformant,
    /// At least one required check failed, attributed to the target.
    NotConformant,
    /// No target failure, but `--strict` was on and some required checks were not demonstrated: the run proves
    /// neither conformance nor its absence.
    Incomplete,
    /// Nothing could be graded: target unreachable, or outside what the tool can judge.
    CannotAssess,
}

impl Outcome {
    /// The process exit code for this outcome.
    pub fn exit_code(self) -> i32 {
        match self {
            Self::Conformant => 0,
            Self::NotConformant => 1,
            Self::Incomplete | Self::CannotAssess => 2,
        }
    }
}

/// Counts and lists a reader needs before the details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct Summary {
    /// Passed checks.
    pub pass: usize,
    /// Failed checks attributed to the target.
    pub fail: usize,
    /// Failed checks attributed to a dependency or to the tool.
    pub blocked: usize,
    /// Warnings.
    pub warn: usize,
    /// Informational findings.
    pub info: usize,
    /// Skipped checks.
    pub skip: usize,
    /// Checks the target is out of scope for.
    pub cannot_assess: usize,
    /// Ids of required checks that were not demonstrated against the target in this run (skipped, blocked by a
    /// dependency or the tool, out of scope, or not attributable): what this run does not certify.
    pub incomplete: Vec<String>,
}

/// Everything a run produced.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Report {
    /// JSON layout version.
    pub schema_version: u32,
    /// Tool name and version.
    pub tool: String,
    /// Upstream commit of the specification copy the tool was built from (`spec/UPSTREAM_COMMIT`).
    pub spec_commit: &'static str,
    /// Upstream commit of the pinned EIP-3009 text (`spec/external/`), cited by the ledger binding check.
    pub eip3009_commit: &'static str,
    /// The URL under test.
    pub target: String,
    /// When the run started.
    pub started_at: Timestamp,
    /// When the run ended.
    pub finished_at: Timestamp,
    /// Which suites ran, in order.
    pub scope: Vec<&'static str>,
    /// Suites that were not run, with the reason.
    pub omitted: Vec<String>,
    /// Whether `--strict` was on: required checks left undemonstrated make the outcome incomplete (exit code 2),
    /// which is not a verdict against the target.
    pub strict: bool,
    /// Findings, per suite.
    pub suites: Vec<SuiteResult>,
    /// Every HTTP exchange with the target, in order; findings reference them by index.
    pub exchanges: Vec<Exchange>,
    /// Counts and the list of unexercised required checks.
    pub summary: Summary,
    /// The verdict of the run.
    pub outcome: Outcome,
    /// The process exit code.
    pub exit_code: i32,
}

impl Report {
    /// Assembles the report and computes summary, outcome and exit code.
    pub fn build(
        target: String,
        started_at: Timestamp,
        strict: bool,
        suites: Vec<SuiteResult>,
        omitted: Vec<String>,
        exchanges: Vec<Exchange>,
    ) -> Self {
        let mut summary = Summary::default();
        let mut graded = 0usize;
        for finding in suites.iter().flat_map(|s| s.findings.iter()) {
            let demonstrated = match finding.verdict {
                Verdict::Pass => {
                    summary.pass += 1;
                    true
                }
                Verdict::Fail if finding.counts_against_target() => {
                    summary.fail += 1;
                    true
                }
                Verdict::Fail => {
                    summary.blocked += 1;
                    false
                }
                Verdict::Warn => {
                    summary.warn += 1;
                    true
                }
                Verdict::Info => {
                    summary.info += 1;
                    false
                }
                Verdict::Skip => {
                    summary.skip += 1;
                    false
                }
                Verdict::CannotAssess => {
                    summary.cannot_assess += 1;
                    false
                }
            };
            if demonstrated {
                graded += 1;
            } else if finding.check.level == Level::Required
                && !summary.incomplete.contains(&finding.check.id.to_owned())
            {
                summary.incomplete.push(finding.check.id.to_owned());
            }
        }
        let outcome = if summary.fail > 0 {
            Outcome::NotConformant
        } else if strict && !summary.incomplete.is_empty() {
            Outcome::Incomplete
        } else if graded == 0 {
            Outcome::CannotAssess
        } else {
            Outcome::Conformant
        };
        Self {
            schema_version: SCHEMA_VERSION,
            tool: concat!("x402-checker ", env!("CARGO_PKG_VERSION")).to_owned(),
            spec_commit: crate::pins::SPEC_COMMIT,
            eip3009_commit: crate::pins::EIP3009_COMMIT,
            target,
            started_at,
            finished_at: Timestamp::now(),
            scope: suites.iter().map(|s| s.name).collect(),
            omitted,
            strict,
            suites,
            exchanges,
            summary,
            outcome,
            exit_code: outcome.exit_code(),
        }
    }

    /// The report as pretty JSON.
    ///
    /// # Panics
    ///
    /// Never in practice: the report only holds serialisable values.
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("a report is serialisable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::check::{Attribution, Check, Finding, Source};

    const REQUIRED: Check = Check {
        id: "T-001",
        title: "test",
        level: Level::Required,
        source: Source::ExplicitMust,
        clause: "none",
        ambiguity: None,
    };
    const RECOMMENDED: Check = Check {
        id: "T-002",
        level: Level::Recommended,
        ..REQUIRED
    };

    fn report(findings: Vec<Finding>, strict: bool) -> Report {
        Report::build(
            "t".into(),
            Timestamp::now(),
            strict,
            vec![SuiteResult::new("probe", findings)],
            vec![],
            vec![],
        )
    }

    #[test]
    fn outcome_follows_target_failures_only() {
        assert_eq!(
            report(vec![Finding::pass(&REQUIRED, "", &[])], false).outcome,
            Outcome::Conformant
        );
        assert_eq!(
            report(vec![Finding::fail(&REQUIRED, "", &[])], false).outcome,
            Outcome::NotConformant
        );
        assert_eq!(
            report(vec![Finding::fail(&RECOMMENDED, "", &[])], false).outcome,
            Outcome::Conformant
        );
        let blocked = report(
            vec![
                Finding::pass(&REQUIRED, "", &[]),
                Finding::blocked(&REQUIRED, Attribution::Dependency, "", &[]),
            ],
            false,
        );
        assert_eq!(blocked.outcome, Outcome::Conformant);
        assert_eq!(blocked.summary.blocked, 1);
    }

    #[test]
    fn nothing_graded_means_cannot_assess() {
        let r = report(
            vec![
                Finding::cannot_assess(&REQUIRED, "v1 only", &[]),
                Finding::skip(&REQUIRED, "no key"),
            ],
            false,
        );
        assert_eq!(r.outcome, Outcome::CannotAssess);
        assert_eq!(r.exit_code, 2);
        assert_eq!(
            r.summary.incomplete,
            ["T-001"],
            "listed once although two findings did not demonstrate it"
        );
    }

    #[test]
    fn strict_mode_counts_unexercised_required_checks() {
        let findings = || {
            vec![
                Finding::pass(&REQUIRED, "", &[]),
                Finding::skip(&REQUIRED, "no key"),
            ]
        };
        assert_eq!(report(findings(), false).outcome, Outcome::Conformant);
        assert_eq!(
            report(findings(), true).outcome,
            Outcome::Incomplete,
            "strict refuses the coverage without blaming the target"
        );
        assert_eq!(report(findings(), true).exit_code, 2);
    }
}
