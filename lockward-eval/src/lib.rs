// SPDX-License-Identifier: AGPL-3.0-only

//! Offline evaluation of the labeled Lockward corpus.
//!
//! The harness scans each fixture through [`lockward_core::scan::analyze`]. It does
//! not run package scripts, does not use the network, and stamps a fixed
//! `scanned_at` so two runs produce the same report.

#![forbid(unsafe_code)]

use lockward_core::advisories::HttpTransport;
use lockward_core::policy::expected_binary_fetch;
use lockward_core::scan::{AnalyzeOptions, analyze};
use lockward_core::{Error as CoreError, Result as CoreResult, load_policy};
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Fixed timestamp. The measurement does not read the clock.
pub const SCANNED_AT: &str = "2026-10-13T00:00:00Z";

const SCOPE: &str = "hooks_and_heuristics";
const SCOPE_NOTE: &str = "Dieser Korpus misst Install-Hooks und Heuristiken und ist bewusst gutartig-lastig. Precision und FP-Rate sind die Leitkennzahlen. known_vulnerable bleibt offline ohne Cache leer und ist hier keine vollständige OSV-Messung.";

/// Policy rules that count as a detection. `advisory_coverage` and
/// `new_dependencies` are intentionally absent.
const POLICY_DETECTIONS: &[&str] = &[
    "install_scripts",
    "no_outbound_build",
    "secret_path_access",
    "known_vulnerable",
];

/// Failure while reading the corpus or scanning a case.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The corpus directory or a required child is missing.
    #[error("Korpus fehlt oder ist unvollständig: {0}")]
    Missing(String),
    /// A `label.yaml` does not match the directory or the schema.
    #[error("Label {path}: {message}")]
    Label { path: String, message: String },
    /// YAML could not be parsed.
    #[error("YAML {path}: {message}")]
    Yaml { path: String, message: String },
    /// The scanner rejected a fixture.
    #[error(transparent)]
    Scan(#[from] CoreError),
    /// Filesystem error.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The report could not be encoded.
    #[error("Report konnte nicht geschrieben werden: {0}")]
    Report(String),
}

/// Confusion matrix at case level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Confusion {
    /// Malicious and flagged.
    pub tp: u32,
    /// Benign and flagged.
    pub fp: u32,
    /// Malicious and not flagged.
    #[serde(rename = "fn")]
    pub fn_count: u32,
    /// Benign and not flagged.
    pub tn: u32,
}

/// Ratios as fixed four-decimal strings. `n/a` when the denominator is zero.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Metrics {
    /// TP / (TP + FP).
    pub precision: String,
    /// TP / (TP + FN).
    pub recall: String,
    /// 2 TP / (2 TP + FP + FN).
    pub f1: String,
    /// FP / (FP + TN).
    pub false_positive_rate: String,
}

/// Whether an expected rule fired on the malicious cases that name it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleRecall {
    /// Policy rule or heuristic id.
    pub rule: String,
    /// Malicious cases that list this rule.
    pub expected: u32,
    /// Those cases where the rule fired.
    pub hit: u32,
    /// Case ids where it was expected and did not fire.
    pub misses: Vec<String>,
}

/// A malicious case the detection set did not flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FalseNegative {
    /// `malicious/<name>`.
    pub case: String,
    /// Detection-set rules that did fire.
    pub fired: Vec<String>,
    /// Expected rules that did not fire.
    pub missing_rules: Vec<String>,
}

/// A benign case the detection set flagged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FalsePositive {
    /// `benign/<name>`.
    pub case: String,
    /// `clean`, `allowlisted_install`, `held_out_install`, or `heuristic_probe`.
    pub cohort: String,
    /// Detection-set rules that fired.
    pub fired: Vec<String>,
}

/// One corpus case after the scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CaseResult {
    /// `malicious/<name>` or `benign/<name>`.
    pub id: String,
    /// Label expectation.
    pub expected: String,
    /// At least one detection-set rule fired.
    pub flagged: bool,
    /// `tp`, `fn`, `fp`, or `tn`.
    pub outcome: String,
    /// Rules the label says should fire.
    pub expected_rules: Vec<String>,
    /// Detection-set rules that fired.
    pub fired: Vec<String>,
    /// Expected rules absent from `fired`.
    pub missing_rules: Vec<String>,
    /// Measurement bucket. Malicious cases use `malicious`.
    pub cohort: String,
    /// Provenance line from the label.
    pub source: String,
    /// Optional label note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// Flag rate inside one measurement bucket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CohortStats {
    /// `allowlisted_install`, `held_out_install`, `clean`, `heuristic_probe`, or `malicious`.
    pub cohort: String,
    /// Cases in the bucket.
    pub cases: u32,
    /// Cases the detection set flagged.
    pub flagged: u32,
    /// `flagged / cases` for benign buckets. `n/a` for malicious.
    pub false_positive_rate: String,
}

/// Machine-readable corpus report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    /// Schema version of this document.
    pub schema_version: u32,
    /// What this corpus measures.
    pub scope: String,
    /// Human-readable limit of the measurement.
    pub scope_note: String,
    /// Fixed scan timestamp.
    pub scanned_at: String,
    /// Policy file name, not a machine-specific path.
    pub policy: String,
    /// Case-level confusion matrix.
    pub confusion: Confusion,
    /// Precision, recall, F1, and false-positive rate.
    pub metrics: Metrics,
    /// Per-rule recall on malicious cases.
    pub rule_recall: Vec<RuleRecall>,
    /// Malicious cases with no detection-set hit.
    pub false_negatives: Vec<FalseNegative>,
    /// Benign cases with a detection-set hit.
    pub false_positives: Vec<FalsePositive>,
    /// Flag rates split by cohort. Held-out is not used to extend the allowlist.
    pub cohorts: Vec<CohortStats>,
    /// Every case, sorted by id.
    pub cases: Vec<CaseResult>,
}

#[derive(Debug, Deserialize)]
struct Label {
    expected: String,
    #[serde(default)]
    expected_rules: Vec<String>,
    source: String,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    cohort: Option<String>,
}

struct Offline;

impl HttpTransport for Offline {
    fn post_json(&self, url: &str, _body: &Value) -> CoreResult<Value> {
        Err(CoreError::Advisory {
            url: url.to_owned(),
            message: "eval offline".to_owned(),
        })
    }

    fn get_json(&self, url: &str) -> CoreResult<Value> {
        Err(CoreError::Advisory {
            url: url.to_owned(),
            message: "eval offline".to_owned(),
        })
    }
}

/// Scan `corpus_dir` with the policy file and build a deterministic report.
pub fn evaluate(corpus_dir: &Path, policy_path: &Path) -> Result<Report, Error> {
    let policy = load_policy(policy_path)?;
    let policy_name = file_name(policy_path)?;
    let mut cases = Vec::new();
    for class in ["malicious", "benign"] {
        let class_dir = corpus_dir.join(class);
        if !class_dir.is_dir() {
            return Err(Error::Missing(class_dir.display().to_string()));
        }
        for case_dir in read_case_dirs(&class_dir)? {
            cases.push(evaluate_case(&case_dir, class, &policy)?);
        }
    }
    cases.sort_by(|left, right| left.id.cmp(&right.id));
    Ok(assemble(policy_name, cases))
}

/// Render the German summary, including every FN and FP.
pub fn render_text(report: &Report) -> String {
    let mut out = String::new();
    push(&mut out, &report.scope_note);
    push(&mut out, &format!("scanned_at: {}", report.scanned_at));
    let benign = report.confusion.fp + report.confusion.tn;
    let malicious = report.confusion.tp + report.confusion.fn_count;
    push(
        &mut out,
        &format!("Fälle: {benign} gutartig, {malicious} bösartig"),
    );
    push(&mut out, "");
    push(
        &mut out,
        &format!("{:<18} {:>12} {:>14}", "", "markiert", "unmarkiert"),
    );
    push(
        &mut out,
        &format!(
            "{:<18} {:>12} {:>14}",
            "bösartig",
            format!("TP {}", report.confusion.tp),
            format!("FN {}", report.confusion.fn_count)
        ),
    );
    push(
        &mut out,
        &format!(
            "{:<18} {:>12} {:>14}",
            "gutartig",
            format!("FP {}", report.confusion.fp),
            format!("TN {}", report.confusion.tn)
        ),
    );
    push(&mut out, "");
    push(
        &mut out,
        &format!("precision            {}", report.metrics.precision),
    );
    push(
        &mut out,
        &format!("recall               {}", report.metrics.recall),
    );
    push(
        &mut out,
        &format!("f1                   {}", report.metrics.f1),
    );
    push(
        &mut out,
        &format!(
            "false_positive_rate  {}",
            report.metrics.false_positive_rate
        ),
    );
    push(&mut out, "");
    push(&mut out, "FP-Rate nach Kohorte (Allowlist vs. Held-out)");
    push(
        &mut out,
        &format!("{:<24} {:>8} {:>10}  fp_rate", "cohort", "cases", "flagged"),
    );
    for cohort in &report.cohorts {
        push(
            &mut out,
            &format!(
                "{:<24} {:>8} {:>10}  {}",
                cohort.cohort, cohort.cases, cohort.flagged, cohort.false_positive_rate
            ),
        );
    }
    push(&mut out, "");
    push(
        &mut out,
        "Regel-Recall (nur bösartige Fälle, expected_rules)",
    );
    push(
        &mut out,
        &format!("{:<22} {:>12}  misses", "rule", "hit/expected"),
    );
    if report.rule_recall.is_empty() {
        push(&mut out, "(keine)");
    }
    for rule in &report.rule_recall {
        let misses = if rule.misses.is_empty() {
            "-".to_owned()
        } else {
            rule.misses.join(", ")
        };
        push(
            &mut out,
            &format!(
                "{:<22} {:>12}  {misses}",
                rule.rule,
                format!("{}/{}", rule.hit, rule.expected)
            ),
        );
    }
    push(&mut out, "");
    push(&mut out, "False negatives");
    if report.false_negatives.is_empty() {
        push(&mut out, "(keine)");
    }
    for miss in &report.false_negatives {
        push(
            &mut out,
            &format!(
                "- {}  fired=[{}]  missing=[{}]",
                miss.case,
                miss.fired.join(", "),
                miss.missing_rules.join(", ")
            ),
        );
    }
    push(&mut out, "");
    push(&mut out, "False positives");
    if report.false_positives.is_empty() {
        push(&mut out, "(keine)");
    }
    for hit in &report.false_positives {
        push(
            &mut out,
            &format!(
                "- {}  cohort={}  fired=[{}]",
                hit.case,
                hit.cohort,
                hit.fired.join(", ")
            ),
        );
    }
    out
}

/// Write `report` as pretty JSON.
pub fn write_json(report: &Report, output: &Path) -> Result<(), Error> {
    let mut bytes =
        serde_json::to_vec_pretty(report).map_err(|err| Error::Report(err.to_string()))?;
    bytes.push(b'\n');
    if let Some(parent) = output.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, bytes)?;
    Ok(())
}

/// Evaluate, print the summary, and write the JSON report.
pub fn run(corpus_dir: &Path, policy_path: &Path, output: &Path) -> Result<(), Error> {
    let report = evaluate(corpus_dir, policy_path)?;
    print!("{}", render_text(&report));
    write_json(&report, output)
}

fn evaluate_case(
    case_dir: &Path,
    class: &str,
    policy: &lockward_core::Policy,
) -> Result<CaseResult, Error> {
    let name = file_name(case_dir)?;
    let id = format!("{class}/{name}");
    let label = read_label(&case_dir.join("label.yaml"), &id)?;
    if class == "malicious" {
        if label.expected != "malicious" {
            return Err(Error::Label {
                path: id,
                message: "Verzeichnis malicious erwartet expected: malicious".to_owned(),
            });
        }
    } else if label.expected != "benign" {
        return Err(Error::Label {
            path: id,
            message: "Verzeichnis benign erwartet expected: benign".to_owned(),
        });
    }
    if label.expected == "benign" && !label.expected_rules.is_empty() {
        return Err(Error::Label {
            path: id,
            message: "gutartige Fälle brauchen expected_rules: []".to_owned(),
        });
    }
    let analysis = analyze(
        case_dir,
        &Offline,
        &AnalyzeOptions {
            offline: true,
            cache_dir: None,
            policy: policy.clone(),
            baseline: None,
        },
    )?;
    let mut fired = BTreeSet::new();
    for violation in &analysis.decision.violations {
        if POLICY_DETECTIONS.contains(&violation.rule) {
            fired.insert(violation.rule.to_owned());
        }
    }
    for finding in &analysis.heuristics {
        if finding.rule_id == "LW-H003" && expected_binary_fetch(policy, &finding.package_name) {
            continue;
        }
        if finding.rule_id.starts_with("LW-H") {
            fired.insert(finding.rule_id.to_owned());
        }
    }
    let expected_rules = unique_sorted(label.expected_rules.clone());
    let missing_rules: Vec<String> = expected_rules
        .iter()
        .filter(|rule| !fired.contains(*rule))
        .cloned()
        .collect();
    let fired: Vec<String> = fired.into_iter().collect();
    let flagged = !fired.is_empty();
    let malicious = label.expected == "malicious";
    let outcome = match (malicious, flagged) {
        (true, true) => "tp",
        (true, false) => "fn",
        (false, true) => "fp",
        (false, false) => "tn",
    };
    let names: BTreeSet<String> = analysis
        .hooks
        .findings
        .iter()
        .map(|finding| finding.package_name.clone())
        .collect();
    let cohort = cohort_of(&label, &names, policy, &id)?;
    Ok(CaseResult {
        id,
        expected: label.expected,
        flagged,
        outcome: outcome.to_owned(),
        expected_rules,
        fired,
        missing_rules,
        cohort,
        source: label.source,
        notes: label.notes,
    })
}

fn assemble(policy_name: String, cases: Vec<CaseResult>) -> Report {
    let mut confusion = Confusion {
        tp: 0,
        fp: 0,
        fn_count: 0,
        tn: 0,
    };
    let mut false_negatives = Vec::new();
    let mut false_positives = Vec::new();
    let mut rule_names = BTreeSet::new();
    for case in &cases {
        match case.outcome.as_str() {
            "tp" => confusion.tp += 1,
            "fp" => confusion.fp += 1,
            "fn" => confusion.fn_count += 1,
            "tn" => confusion.tn += 1,
            _ => {}
        }
        if case.outcome == "fn" {
            false_negatives.push(FalseNegative {
                case: case.id.clone(),
                fired: case.fired.clone(),
                missing_rules: case.missing_rules.clone(),
            });
        }
        if case.outcome == "fp" {
            false_positives.push(FalsePositive {
                case: case.id.clone(),
                cohort: case.cohort.clone(),
                fired: case.fired.clone(),
            });
        }
        if case.expected == "malicious" {
            rule_names.extend(case.expected_rules.iter().cloned());
        }
    }
    let rule_recall = rule_names
        .into_iter()
        .map(|rule| {
            let mut expected = 0;
            let mut hit = 0;
            let mut misses = Vec::new();
            for case in cases.iter().filter(|case| case.expected == "malicious") {
                if !case.expected_rules.iter().any(|item| item == &rule) {
                    continue;
                }
                expected += 1;
                if case.fired.iter().any(|item| item == &rule) {
                    hit += 1;
                } else {
                    misses.push(case.id.clone());
                }
            }
            RuleRecall {
                rule,
                expected,
                hit,
                misses,
            }
        })
        .collect();
    let cohorts = cohort_stats(&cases);
    Report {
        schema_version: 2,
        scope: SCOPE.to_owned(),
        scope_note: SCOPE_NOTE.to_owned(),
        scanned_at: SCANNED_AT.to_owned(),
        policy: policy_name,
        confusion,
        metrics: Metrics {
            precision: ratio(confusion.tp, confusion.tp + confusion.fp),
            recall: ratio(confusion.tp, confusion.tp + confusion.fn_count),
            f1: ratio(
                2 * confusion.tp,
                2 * confusion.tp + confusion.fp + confusion.fn_count,
            ),
            false_positive_rate: ratio(confusion.fp, confusion.fp + confusion.tn),
        },
        rule_recall,
        false_negatives,
        false_positives,
        cohorts,
        cases,
    }
}

fn cohort_of(
    label: &Label,
    names: &BTreeSet<String>,
    policy: &lockward_core::Policy,
    id: &str,
) -> Result<String, Error> {
    let malicious = label.expected == "malicious";
    let inferred = if malicious {
        "malicious"
    } else if names.is_empty() {
        "clean"
    } else if names.iter().all(|name| {
        policy
            .rules
            .install_scripts
            .allow
            .iter()
            .any(|allowed| allowed == name)
    }) {
        "allowlisted_install"
    } else {
        "held_out_install"
    };
    let Some(declared) = label.cohort.as_deref() else {
        if malicious {
            return Ok("malicious".to_owned());
        }
        return Err(Error::Label {
            path: id.to_owned(),
            message: "gutartige Fälle brauchen cohort".to_owned(),
        });
    };
    let ok = match declared {
        "heuristic_probe" => inferred == "held_out_install",
        "malicious" => malicious,
        other => other == inferred,
    };
    if !ok {
        return Err(Error::Label {
            path: id.to_owned(),
            message: format!("cohort {declared} passt nicht zur Allowlist ({inferred})"),
        });
    }
    Ok(declared.to_owned())
}

fn cohort_stats(cases: &[CaseResult]) -> Vec<CohortStats> {
    let mut names = BTreeSet::new();
    for case in cases {
        names.insert(case.cohort.clone());
    }
    names
        .into_iter()
        .map(|cohort| {
            let bucket: Vec<_> = cases.iter().filter(|case| case.cohort == cohort).collect();
            let count = u32::try_from(bucket.len()).unwrap_or(u32::MAX);
            let flagged = u32::try_from(bucket.iter().filter(|case| case.flagged).count())
                .unwrap_or(u32::MAX);
            let false_positive_rate = if cohort == "malicious" {
                "n/a".to_owned()
            } else {
                ratio(flagged, count)
            };
            CohortStats {
                cohort,
                cases: count,
                flagged,
                false_positive_rate,
            }
        })
        .collect()
}

fn read_label(path: &Path, id: &str) -> Result<Label, Error> {
    let text = fs::read_to_string(path)?;
    let label: Label = noyalib::from_str(&text).map_err(|err| Error::Yaml {
        path: id.to_owned(),
        message: err.to_string(),
    })?;
    if label.expected != "malicious" && label.expected != "benign" {
        return Err(Error::Label {
            path: id.to_owned(),
            message: format!(
                "expected muss malicious oder benign sein, war {}",
                label.expected
            ),
        });
    }
    if label.source.trim().is_empty() {
        return Err(Error::Label {
            path: id.to_owned(),
            message: "source fehlt".to_owned(),
        });
    }
    Ok(label)
}

fn read_case_dirs(class_dir: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut dirs = Vec::new();
    for entry in fs::read_dir(class_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            dirs.push(entry.path());
        }
    }
    dirs.sort();
    if dirs.is_empty() {
        return Err(Error::Missing(format!(
            "{} enthält keine Fälle",
            class_dir.display()
        )));
    }
    Ok(dirs)
}

fn file_name(path: &Path) -> Result<String, Error> {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .ok_or_else(|| Error::Missing(path.display().to_string()))
}

fn unique_sorted(mut rules: Vec<String>) -> Vec<String> {
    rules.sort();
    rules.dedup();
    rules
}

fn ratio(numerator: u32, denominator: u32) -> String {
    if denominator == 0 {
        return "n/a".to_owned();
    }
    format!("{:.4}", f64::from(numerator) / f64::from(denominator))
}

fn push(out: &mut String, line: &str) {
    out.push_str(line);
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../corpus")
    }

    fn policy() -> PathBuf {
        corpus().join("eval-policy.yaml")
    }

    #[test]
    fn report_is_deterministic_and_ignores_coverage() {
        let first = evaluate(&corpus(), &policy()).expect("first scan");
        let second = evaluate(&corpus(), &policy()).expect("second scan");
        let left = serde_json::to_string(&first).expect("json");
        let right = serde_json::to_string(&second).expect("json");
        assert_eq!(left, right);
        assert_eq!(first.scanned_at, SCANNED_AT);
        assert_eq!(first.scope, SCOPE);
        assert!(first.cases.len() >= 24);
        for case in &first.cases {
            assert!(
                !case
                    .fired
                    .iter()
                    .any(|rule| rule == "advisory_coverage" || rule == "new_dependencies"),
                "{} zählt eine Nicht-Detektion: {:?}",
                case.id,
                case.fired
            );
        }
        let text = render_text(&first);
        assert!(text.contains("False negatives"));
        assert!(text.contains("False positives"));
        assert!(text.contains(SCOPE_NOTE));
        assert!(text.contains("FP-Rate nach Kohorte"));
    }

    #[test]
    fn tuning_keeps_staged_detection_and_does_not_absorb_held_out() {
        let report = evaluate(&corpus(), &policy()).expect("scan");
        let case = |id: &str| {
            report
                .cases
                .iter()
                .find(|item| item.id == id)
                .unwrap_or_else(|| panic!("missing {id}"))
        };
        assert_eq!(case("malicious/ua-parser-js-staged").outcome, "tp");
        assert_eq!(case("malicious/node-ipc-protestware").outcome, "fn");
        assert!(
            case("malicious/crypto-stealer-combo")
                .fired
                .iter()
                .any(|rule| rule == "LW-H001")
        );
        assert!(
            case("malicious/crypto-stealer-combo")
                .fired
                .iter()
                .any(|rule| rule == "LW-H002")
        );
        assert!(
            case("malicious/obfuscated-hook")
                .fired
                .iter()
                .any(|rule| rule == "LW-H001")
        );
        assert!(
            case("malicious/obfuscated-hook")
                .fired
                .iter()
                .any(|rule| rule == "LW-H002")
        );
        assert!(
            !case("benign/embedded-asset")
                .fired
                .iter()
                .any(|rule| rule == "LW-H002")
        );
        assert!(
            !case("benign/minified-asset")
                .fired
                .iter()
                .any(|rule| rule == "LW-H001")
        );
        assert!(!case("benign/puppeteer").flagged);
        assert!(!case("benign/esbuild").flagged);
        let allowlisted = report
            .cohorts
            .iter()
            .find(|item| item.cohort == "allowlisted_install")
            .expect("allowlisted cohort");
        assert_eq!(allowlisted.flagged, 0);
        let held = report
            .cohorts
            .iter()
            .find(|item| item.cohort == "held_out_install")
            .expect("held-out cohort");
        assert!(held.cases >= 10);
        let policy = load_policy(&policy()).expect("policy");
        for item in report
            .cases
            .iter()
            .filter(|item| item.cohort == "held_out_install")
        {
            assert!(
                !policy
                    .rules
                    .install_scripts
                    .allow
                    .iter()
                    .any(|name| item.id.ends_with(name.as_str())),
                "{} steht auf der Allowlist",
                item.id
            );
        }
    }

    #[test]
    fn fixtures_stay_inert() {
        let root = corpus();
        for class in ["malicious", "benign"] {
            for case_dir in read_case_dirs(&root.join(class)).expect("cases") {
                walk_inert(&case_dir);
            }
        }
    }

    fn walk_inert(dir: &Path) {
        for entry in fs::read_dir(dir).expect("read") {
            let entry = entry.expect("entry");
            let path = entry.path();
            if path.is_dir() {
                walk_inert(&path);
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let text = fs::read_to_string(&path).expect("utf-8 fixture");
            if name == "package.json" {
                assert_scripts_inert(&path, &text);
            }
            if name.ends_with(".js") {
                assert!(
                    text.lines().all(inert_js_line),
                    "{} enthält ausführbaren Code",
                    path.display()
                );
            }
        }
    }

    fn assert_scripts_inert(path: &Path, text: &str) {
        let value: Value = serde_json::from_str(text).expect("package.json");
        let Some(scripts) = value.get("scripts").and_then(Value::as_object) else {
            return;
        };
        for (hook, body) in scripts {
            let body = body.as_str().unwrap_or("");
            assert!(
                body.starts_with("node -e \"console.log('LOCKWARD_EVAL_FIXTURE")
                    && body.ends_with("')\""),
                "{} script {hook} ist kein inerter Marker: {body}",
                path.display()
            );
        }
    }

    fn inert_js_line(line: &str) -> bool {
        let trimmed = line.trim();
        trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed == "console.log(\"LOCKWARD_EVAL_FIXTURE\");"
    }
}
