//! Checks an x402 v2 resource server against the specification.
//!
//! The crate is organised as data in, data out: a suite sends requests through the recording [`http::Client`],
//! turns what it sees into [`check::Finding`]s, and the [`report::Report`] assembles findings, evidence, scope
//! and outcome. `docs/DESIGN.md` explains the levels, verdicts and exit codes; `docs/requirements.md` lists the
//! clauses behind every check id.

pub mod check;
pub mod http;
pub mod pins;
pub mod render;
pub mod report;
pub mod suites;
pub mod target;
