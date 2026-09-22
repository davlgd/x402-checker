//! The command line: help, argument errors, and the exit code when the target cannot be reached.

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_lists_the_commands() {
    Command::cargo_bin("x402-checker")
        .unwrap()
        .arg("--help")
        .assert()
        .success()
        .stdout(
            predicate::str::contains("probe")
                .and(predicate::str::contains("scenarios"))
                .and(predicate::str::contains("serve")),
        );
}

#[test]
fn pay_without_a_key_explains_what_to_set() {
    Command::cargo_bin("x402-checker")
        .unwrap()
        .env_remove("X402_PAYER_KEY")
        .args(["pay", "http://127.0.0.1:9/paid"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("X402_PAYER_KEY"));
}

#[test]
fn an_unreachable_target_cannot_be_assessed() {
    Command::cargo_bin("x402-checker")
        .unwrap()
        .args([
            "probe",
            "http://127.0.0.1:9/paid",
            "--color",
            "never",
            "--timeout",
            "2",
        ])
        .assert()
        .code(2)
        .stdout(
            predicate::str::contains("CANNOT ASSESS").and(predicate::str::contains("could not be reached")),
        );
}

#[test]
fn a_malformed_header_flag_is_rejected_before_any_request() {
    Command::cargo_bin("x402-checker")
        .unwrap()
        .args(["probe", "http://127.0.0.1:9/paid", "-H", "no-colon"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("Name: value"));
}

#[test]
fn ledger_reads_a_settlement_without_paying() {
    Command::cargo_bin("x402-checker")
        .unwrap()
        .args(["ledger", "--help"])
        .assert()
        .success()
        .stdout(
            predicate::str::contains("--rpc-url")
                .and(predicate::str::contains("--nonce"))
                .and(predicate::str::contains("without paying again")),
        );
}
