use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::path::PathBuf;

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
fn offline_corpus_exits_with_warning() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lockward-core/tests/fixtures/hooks/corpus");
    lockward()
        .args(["scan", corpus.to_str().expect("utf-8 path"), "--offline"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("Warnung"))
        .stdout(predicate::str::contains("install_scripts"));
}

#[test]
fn enforce_fail_policy_exits_2() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../lockward-core/tests/fixtures/hooks/corpus");
    let policy = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fail-install.yaml");
    lockward()
        .args([
            "scan",
            corpus.to_str().expect("utf-8 path"),
            "--offline",
            "--policy",
            policy.to_str().expect("utf-8 path"),
            "--mode",
            "enforce",
        ])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("Block"));
}

#[test]
fn clean_project_exits_ok() {
    let dir = std::env::temp_dir().join(format!("lockward-cli-clean-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(
        dir.join("package.json"),
        r#"{ "name": "clean-app", "version": "1.0.0" }"#,
    )
    .unwrap();
    fs::write(
        dir.join("package-lock.json"),
        r#"{
          "name": "clean-app",
          "version": "1.0.0",
          "lockfileVersion": 3,
          "packages": { "": { "name": "clean-app", "version": "1.0.0" } }
        }"#,
    )
    .unwrap();
    lockward()
        .args(["scan", dir.to_str().expect("utf-8 path"), "--offline"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("OK"));
    fs::remove_dir_all(&dir).unwrap();
}
