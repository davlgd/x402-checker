//! Text rendering of a report for a terminal.

use std::fmt::Write as _;

use owo_colors::{OwoColorize, Stream, Style};

use crate::check::{Finding, Level, Verdict};
use crate::report::{Outcome, Report};

/// How much to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Print every exchange, not only those a failure points at.
    pub verbose: bool,
    /// Colour policy for stdout.
    pub color: Color,
}

/// Colour policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Color {
    /// Colour when stdout is a terminal.
    Auto,
    /// Always.
    Always,
    /// Never.
    Never,
}

impl Color {
    fn apply(self) {
        match self {
            Self::Auto => {}
            Self::Always => owo_colors::set_override(true),
            Self::Never => owo_colors::set_override(false),
        }
    }
}

fn styled(text: &str, style: Style) -> String {
    text.if_supports_color(Stream::Stdout, |t| t.style(style))
        .to_string()
}

fn verdict_tag(finding: &Finding) -> String {
    let (text, style) = match finding.verdict {
        Verdict::Pass => ("PASS", Style::new().green().bold()),
        Verdict::Fail if finding.counts_against_target() => ("FAIL", Style::new().red().bold()),
        Verdict::Fail => ("BLOCK", Style::new().magenta().bold()),
        Verdict::Warn => ("WARN", Style::new().yellow().bold()),
        Verdict::Info => ("INFO", Style::new().blue()),
        Verdict::Skip => ("SKIP", Style::new().dimmed()),
        Verdict::CannotAssess => (" N/A", Style::new().magenta()),
    };
    styled(text, style)
}

fn level_tag(level: Level) -> &'static str {
    match level {
        Level::Required => "required",
        Level::Recommended => "recommended",
        Level::Optional => "optional",
    }
}

/// Renders `report` as text.
///
/// # Panics
///
/// Never in practice: writing to a `String` cannot fail.
pub fn text(report: &Report, options: Options) -> String {
    options.color.apply();
    let mut out = String::new();
    let dim = Style::new().dimmed();
    let bold = Style::new().bold();

    writeln!(
        out,
        "{}",
        styled(&format!("x402-checker: {}", report.target), bold)
    )
    .unwrap();
    writeln!(
        out,
        "{}",
        styled(
            &format!("scope: {}  ({})", report.scope.join(", "), report.tool),
            dim
        )
    )
    .unwrap();

    for omitted in &report.omitted {
        writeln!(out, "{}", styled(&format!("not run: {omitted}"), dim)).unwrap();
    }
    for suite in &report.suites {
        writeln!(out).unwrap();
        writeln!(out, "{}", styled(&format!("[{}]", suite.name), bold)).unwrap();
        for finding in &suite.findings {
            render_finding(&mut out, finding, report, options.verbose);
        }
        if options.verbose {
            for snapshot in &suite.ledger {
                writeln!(
                    out,
                    "       {}",
                    styled(
                        &format!(
                            "ledger: {} {} block {} ({}), status {}, {} logs, read from {} at {}",
                            snapshot.state,
                            snapshot.receipt.transaction_hash,
                            snapshot.receipt.block_number,
                            snapshot.receipt.block_hash,
                            snapshot.receipt.status,
                            snapshot.receipt.logs.len(),
                            snapshot.node,
                            snapshot.observed_at
                        ),
                        dim
                    )
                )
                .unwrap();
            }
            for trace in &suite.traces {
                writeln!(
                    out,
                    "       {}",
                    styled(
                        &format!(
                            "trace: {}{}",
                            trace.label,
                            if trace.quiescent {
                                ""
                            } else {
                                " (calls still in flight)"
                            }
                        ),
                        dim
                    )
                )
                .unwrap();
                for call in &trace.calls {
                    writeln!(
                        out,
                        "         #{} {:?} {} {} -> {:?} ({:?} .. {:?})",
                        call.seq,
                        call.endpoint,
                        call.method,
                        call.path,
                        call.answered_status,
                        call.started_at,
                        call.finished_at
                    )
                    .unwrap();
                }
            }
        }
    }

    render_summary(&mut out, report);
    if options.verbose {
        writeln!(out).unwrap();
        writeln!(out, "{}", styled("exchanges", bold)).unwrap();
        for exchange in &report.exchanges {
            render_exchange(&mut out, exchange, true);
        }
    }
    out
}

fn render_summary(out: &mut String, report: &Report) {
    let bold = Style::new().bold();
    writeln!(out).unwrap();
    let s = &report.summary;
    writeln!(
        out,
        "{}",
        styled(
            &format!(
                "summary: {} pass, {} fail, {} warn, {} info, {} skip, {} n/a{}",
                s.pass,
                s.fail,
                s.warn,
                s.info,
                s.skip,
                s.cannot_assess,
                if s.blocked > 0 {
                    format!(
                        ", {} blocked (a dependency, the tool, or not attributable)",
                        s.blocked
                    )
                } else {
                    String::new()
                }
            ),
            bold
        )
    )
    .unwrap();
    if !s.incomplete.is_empty() {
        writeln!(
            out,
            "not certified by this run ({} required checks not exercised): {}",
            s.incomplete.len(),
            s.incomplete.join(", ")
        )
        .unwrap();
    }
    let (word, style) = match report.outcome {
        Outcome::Conformant => (
            "CONFORMANT within the executed scope",
            Style::new().green().bold(),
        ),
        Outcome::NotConformant => ("NOT CONFORMANT", Style::new().red().bold()),
        Outcome::Incomplete => (
            "INCOMPLETE: required checks not demonstrated (strict mode)",
            Style::new().yellow().bold(),
        ),
        Outcome::CannotAssess => ("CANNOT ASSESS", Style::new().magenta().bold()),
    };
    writeln!(
        out,
        "outcome: {} (exit code {})",
        styled(word, style),
        report.exit_code
    )
    .unwrap();
}

fn render_finding(out: &mut String, finding: &Finding, report: &Report, verbose: bool) {
    let check = &finding.check;
    writeln!(
        out,
        "  {} {:<12} {}  {}",
        verdict_tag(finding),
        check.id,
        check.title,
        styled(&format!("({})", level_tag(check.level)), Style::new().dimmed())
    )
    .unwrap();
    let show_detail = verbose || !matches!(finding.verdict, Verdict::Pass);
    if show_detail && !finding.detail.is_empty() {
        writeln!(out, "       {}", finding.detail).unwrap();
    }
    if matches!(finding.verdict, Verdict::Fail | Verdict::Warn) {
        writeln!(
            out,
            "       {}",
            styled(&format!("spec: {}", check.clause), Style::new().dimmed())
        )
        .unwrap();
        if let Some(ambiguity) = check.ambiguity {
            writeln!(
                out,
                "       {}",
                styled(&format!("note: {ambiguity}"), Style::new().dimmed())
            )
            .unwrap();
        }
        if !verbose {
            for &index in &finding.evidence {
                if let Some(exchange) = report.exchanges.get(index) {
                    render_exchange(out, exchange, false);
                }
            }
        }
    }
}

/// One exchange: the line that identifies it, then the x402 headers. Decoded JSON is cut short unless `verbose`.
fn render_exchange(out: &mut String, exchange: &crate::http::Exchange, verbose: bool) {
    let dim = Style::new().dimmed();
    writeln!(
        out,
        "       {}",
        styled(
            &format!(
                "#{} {} {} {} -> {} ({} ms)",
                exchange.seq,
                exchange.label,
                exchange.method,
                exchange.url,
                exchange.status,
                exchange.elapsed_ms
            ),
            dim
        )
    )
    .unwrap();
    let cap = if verbose { usize::MAX } else { 200 };
    for (name, decoded) in [
        ("payment-required", &exchange.payment_required),
        ("payment-response", &exchange.payment_response),
    ] {
        let Some(decoded) = decoded else { continue };
        if let Some(json) = &decoded.json {
            writeln!(out, "         {name}: {}", cut(&json.to_string(), cap)).unwrap();
        } else if let Some(error) = &decoded.error {
            writeln!(
                out,
                "         {name}: {} (value {})",
                error,
                cut(&decoded.raw, 60)
            )
            .unwrap();
        }
    }
    if let Some(error) = &exchange.body.error {
        writeln!(out, "         body not read to the end: {error}").unwrap();
    }
}

fn cut(text: &str, cap: usize) -> String {
    let mut chars = text.chars();
    let head: String = chars.by_ref().take(cap).collect();
    if chars.next().is_some() {
        format!("{head}…")
    } else {
        head
    }
}
