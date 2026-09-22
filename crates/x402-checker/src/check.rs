//! The check model: what a check claims, how strongly the spec backs it, and what was found.
//!
//! See `docs/DESIGN.md`, "Levels, sources and verdicts". Checks are static data declared next to the code that
//! evaluates them; findings are plain values so that reports can be serialised and compared between runs.

use serde::{Deserialize, Serialize};

/// What a failure of the check means for conformance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    /// MUST, MUST NOT, a "Required" field, prescriptive prose: a failure means not conformant.
    Required,
    /// SHOULD, SHOULD NOT, or an operational policy the tool names as such: a failure is a warning.
    Recommended,
    /// MAY, examples, open choices: information only, never judged.
    Optional,
}

/// How strong the textual basis of the check is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// An RFC 2119 keyword in the text.
    ExplicitMust,
    /// The Required/Optional column of a schema table.
    FieldTable,
    /// Prescriptive prose without a keyword.
    Prose,
    /// Only shown by example.
    Example,
    /// Not in the spec: an operational policy the tool names as such, or a fact worth reporting.
    Policy,
}

/// The outcome of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Verdict {
    /// Observed behaviour satisfies the clause.
    Pass,
    /// Observed behaviour contradicts the clause.
    Fail,
    /// A recommended clause is not followed.
    Warn,
    /// An optional clause: what was observed, without judgement.
    Info,
    /// Precondition not met on the tool's side; the check did not run.
    Skip,
    /// The target is outside what the check can judge.
    CannotAssess,
}

/// Who is responsible for a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Attribution {
    /// The server under test.
    Target,
    /// Something the tool depends on: a real facilitator, an RPC node, a clock, a wallet balance.
    Dependency,
    /// The tool itself.
    Harness,
    /// The observation does not tell who is responsible; nothing is concluded against the target.
    Unknown,
}

/// A requirement the tool can test, declared once as static data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Check {
    /// Stable id, a row of `docs/requirements.md`.
    pub id: &'static str,
    /// One line, imperative, what conformant behaviour is.
    pub title: &'static str,
    /// Level of the requirement.
    pub level: Level,
    /// Strength of the textual basis.
    pub source: Source,
    /// Where in the spec, with a short quote.
    pub clause: &'static str,
    /// When the spec is silent or contradictory on the point measured, the tool's reading, stated as such.
    pub ambiguity: Option<&'static str>,
}

/// The result of one check in one run.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    /// The check.
    pub check: Check,
    /// The verdict.
    pub verdict: Verdict,
    /// What was observed, in one or two sentences, with the values that matter.
    pub detail: String,
    /// Indexes into the report's exchanges that support the detail.
    pub evidence: Vec<usize>,
    /// Who is responsible, for a `Fail`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribution: Option<Attribution>,
}

impl Finding {
    fn new(check: &Check, verdict: Verdict, detail: impl Into<String>, evidence: &[usize]) -> Self {
        Self {
            check: *check,
            verdict,
            detail: detail.into(),
            evidence: evidence.to_vec(),
            attribution: None,
        }
    }

    /// The clause is satisfied.
    pub fn pass(check: &Check, detail: impl Into<String>, evidence: &[usize]) -> Self {
        Self::new(check, Verdict::Pass, detail, evidence)
    }

    /// The clause is contradicted by the target. For a `recommended` check this is a warning, for an `optional`
    /// one an information: the level decides, so that no check can turn a MAY into a failure.
    pub fn fail(check: &Check, detail: impl Into<String>, evidence: &[usize]) -> Self {
        match check.level {
            Level::Required => {
                let mut finding = Self::new(check, Verdict::Fail, detail, evidence);
                finding.attribution = Some(Attribution::Target);
                finding
            }
            Level::Recommended => Self::new(check, Verdict::Warn, detail, evidence),
            Level::Optional => Self::new(check, Verdict::Info, detail, evidence),
        }
    }

    /// The check could not be carried out because of something other than the target.
    pub fn blocked(check: &Check, by: Attribution, detail: impl Into<String>, evidence: &[usize]) -> Self {
        let mut finding = Self::new(check, Verdict::Fail, detail, evidence);
        finding.attribution = Some(by);
        finding
    }

    /// An observation on an optional point, or a note attached to a pass.
    pub fn info(check: &Check, detail: impl Into<String>, evidence: &[usize]) -> Self {
        Self::new(check, Verdict::Info, detail, evidence)
    }

    /// Precondition not met on the tool's side.
    pub fn skip(check: &Check, why: impl Into<String>) -> Self {
        Self::new(check, Verdict::Skip, why, &[])
    }

    /// Outside what the check can judge for this target.
    pub fn cannot_assess(check: &Check, why: impl Into<String>, evidence: &[usize]) -> Self {
        Self::new(check, Verdict::CannotAssess, why, evidence)
    }

    /// Whether this finding counts against conformance.
    pub fn counts_against_target(&self) -> bool {
        self.verdict == Verdict::Fail && self.attribution == Some(Attribution::Target)
    }
}

/// A condition on the target that decides between pass and fail in one line. An `optional` check never passes or
/// fails: the observation is reported as information whatever `ok` says.
pub fn judge(check: &Check, ok: bool, detail: impl Into<String>, evidence: &[usize]) -> Finding {
    if check.level == Level::Optional {
        Finding::info(check, detail, evidence)
    } else if ok {
        Finding::pass(check, detail, evidence)
    } else {
        Finding::fail(check, detail, evidence)
    }
}

/// The calls the tool's doubles received during one scenario, kept so that a reader can reinspect the evidence.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Trace {
    /// The scenario.
    pub label: String,
    /// The calls, in arrival order, with start and end times.
    pub calls: Vec<x402_checker_testbed::Call>,
    /// Whether every call had finished when the trace was taken.
    pub quiescent: bool,
}

/// What one JSON-RPC node answered about a settlement transaction, kept so that the ledger findings can be
/// re-examined against the data observed at the time of the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LedgerSnapshot {
    /// The node.
    pub node: String,
    /// When the receipt was obtained.
    pub observed_at: jiff::Timestamp,
    /// `eth_chainId` as the node answered it.
    pub chain_id: u64,
    /// `sealed` or `preconfirmed` (zero block hash).
    pub state: &'static str,
    /// The receipt, logs included, as decoded.
    pub receipt: x402_checker_ledger::TransactionReceipt,
}

/// The findings of one suite.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct SuiteResult {
    /// `probe`, `pay`, `scenarios`, `ledger`.
    pub name: &'static str,
    /// In evaluation order.
    pub findings: Vec<Finding>,
    /// Traces of the tool's doubles, for suites that host them.
    pub traces: Vec<Trace>,
    /// Receipts read from the chain, for suites that read it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ledger: Vec<LedgerSnapshot>,
}

impl SuiteResult {
    /// A suite result without traces or snapshots.
    pub fn new(name: &'static str, findings: Vec<Finding>) -> Self {
        Self {
            name,
            findings,
            traces: Vec::new(),
            ledger: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REQUIRED: Check = Check {
        id: "T-001",
        title: "test",
        level: Level::Required,
        source: Source::ExplicitMust,
        clause: "none",
        ambiguity: None,
    };
    const OPTIONAL: Check = Check {
        level: Level::Optional,
        ..REQUIRED
    };
    const RECOMMENDED: Check = Check {
        level: Level::Recommended,
        ..REQUIRED
    };

    #[test]
    fn a_failure_is_graded_by_the_level() {
        assert_eq!(Finding::fail(&REQUIRED, "", &[]).verdict, Verdict::Fail);
        assert_eq!(Finding::fail(&RECOMMENDED, "", &[]).verdict, Verdict::Warn);
        assert_eq!(Finding::fail(&OPTIONAL, "", &[]).verdict, Verdict::Info);
    }

    #[test]
    fn only_target_failures_count() {
        assert!(Finding::fail(&REQUIRED, "", &[]).counts_against_target());
        assert!(!Finding::blocked(&REQUIRED, Attribution::Dependency, "", &[]).counts_against_target());
        assert!(!Finding::fail(&RECOMMENDED, "", &[]).counts_against_target());
        assert!(!judge(&REQUIRED, true, "", &[]).counts_against_target());
    }

    #[test]
    fn optional_checks_only_inform() {
        assert_eq!(judge(&OPTIONAL, true, "", &[]).verdict, Verdict::Info);
        assert_eq!(judge(&OPTIONAL, false, "", &[]).verdict, Verdict::Info);
    }
}
