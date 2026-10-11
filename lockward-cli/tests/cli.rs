use assert_cmd::Command;
use predicates::prelude::*;

fn lockward() -> Command {
    Command::cargo_bin("lockward").expect("lockward binary")
}

#[test]
fn help_lists_scan() {
    lockward()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("führt keinen Paketcode aus"));
}

#[test]
fn version_is_printed() {
    lockward()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("lockward"));
}

#[test]
fn scan_placeholder_succeeds() {
    lockward()
        .args(["scan", "."])
        .assert()
        .success()
        .stdout(predicate::str::contains("Platzhalter-Scan von ."));
}
