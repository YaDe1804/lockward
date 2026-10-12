//! Render a finished scan as Markdown, a CI summary, JSON, or CycloneDX.

use crate::advisories::Severity;
use crate::ingest::Package;
use crate::policy::{Action, Mode, Outcome};
use crate::scan::Analysis;
use crate::{Error, Result, VERSION};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use serde::Serialize;
use serde_json::{Value, json};
use uuid::Uuid;

/// Fixed timestamp used by golden tests.
pub const GOLDEN_TIMESTAMP: &str = "2026-10-12T00:00:00Z";

/// Hard cap for one untrusted Markdown field (package names, hook bodies, paths).
const MARKDOWN_FIELD_MAX: usize = 200;

/// Which document to render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportKind {
    /// Pull-request comment.
    Markdown,
    /// GitHub step summary.
    Summary,
    /// Machine-readable scan.
    Json,
    /// CycloneDX 1.6 SBOM.
    CycloneDx,
}

/// Render `analysis` at `scanned_at` (RFC3339). The timestamp is not read from the clock.
pub fn render(analysis: &Analysis, kind: ReportKind, scanned_at: &str) -> Result<String> {
    match kind {
        ReportKind::Markdown => Ok(render_markdown(analysis, scanned_at)),
        ReportKind::Summary => Ok(render_summary(analysis, scanned_at)),
        ReportKind::Json => render_json(analysis, scanned_at),
        ReportKind::CycloneDx => render_cyclonedx(analysis, scanned_at),
    }
}

fn render_markdown(analysis: &Analysis, scanned_at: &str) -> String {
    let mut out = String::new();
    out.push_str("## Lockward\n\n");
    out.push_str(&format!(
        "**Ziel:** {}\n\n",
        markdown_span(&analysis.project_root.display().to_string())
    ));
    out.push_str(&format!("**Zeitpunkt:** {scanned_at}\n\n"));
    out.push_str(&format!(
        "**Score:** {} ({})\n\n",
        analysis.score.project_score,
        severity_de(analysis.score.project_severity)
    ));
    out.push_str(&format!(
        "**Gate:** {} · Exit {} · Modus {}\n\n",
        outcome_de(analysis.decision.outcome),
        analysis.decision.exit_code,
        mode_de(analysis.decision.mode)
    ));
    out.push_str("### Warum\n\n");
    if analysis.score.packages.is_empty() && analysis.decision.violations.is_empty() {
        out.push_str("Keine bewerteten Funde.\n\n");
    } else {
        for package in &analysis.score.packages {
            for explanation in &package.explanations {
                out.push_str(&format!("- {}\n", markdown_span(&explanation.text)));
            }
        }
        for violation in &analysis.decision.violations {
            out.push_str(&format!(
                "- **{}:** {}\n",
                violation.rule,
                markdown_span(&violation.message)
            ));
        }
        out.push('\n');
    }
    out.push_str("### Install-Hooks\n\n");
    if analysis.hooks.findings.is_empty() {
        out.push_str("Keine Install-Hooks.\n\n");
    } else {
        for hook in &analysis.hooks.findings {
            out.push_str(&format!(
                "- {}@{} {}: {}\n",
                markdown_span(&hook.package_name),
                markdown_span(&hook.package_version),
                markdown_span(&hook.hook),
                markdown_span(&hook.raw)
            ));
        }
        out.push('\n');
    }
    out.push_str("### Advisories\n\n");
    let advisories: Vec<_> = analysis
        .advisories
        .packages
        .iter()
        .flat_map(|package| {
            package
                .advisories
                .iter()
                .map(move |advisory| (package, advisory))
        })
        .collect();
    if advisories.is_empty() {
        out.push_str("Keine bekannten Advisories im Cache.\n");
    } else {
        for (package, advisory) in advisories {
            out.push_str(&format!(
                "- {}@{} {} ({})\n",
                markdown_span(&package.name),
                markdown_span(&package.version),
                markdown_span(&advisory.id),
                severity_de(advisory.severity)
            ));
        }
    }
    if !analysis.decision.notes.is_empty() {
        out.push_str("\n### Hinweise\n\n");
        for note in &analysis.decision.notes {
            out.push_str(&format!("- {}\n", markdown_span(note)));
        }
    }
    out
}

fn render_summary(analysis: &Analysis, scanned_at: &str) -> String {
    let mut out = String::new();
    out.push_str("### Lockward\n\n");
    out.push_str(&format!(
        "Score **{}** ({}) · Gate **{}** (Exit {}, Modus {}) · {scanned_at}\n\n",
        analysis.score.project_score,
        severity_de(analysis.score.project_severity),
        outcome_de(analysis.decision.outcome),
        analysis.decision.exit_code,
        mode_de(analysis.decision.mode)
    ));
    if analysis.decision.violations.is_empty() {
        out.push_str("Keine Policy-Verstöße.\n");
    } else {
        for violation in &analysis.decision.violations {
            out.push_str(&format!(
                "- `{}`: {}\n",
                violation.rule,
                markdown_span(&violation.message)
            ));
        }
    }
    out
}

fn render_json(analysis: &Analysis, scanned_at: &str) -> Result<String> {
    let document = JsonReport {
        lockward_version: VERSION,
        score_version: analysis.score.version,
        heuristics_version: analysis.score.heuristics_version,
        scanned_at,
        target: analysis.project_root.display().to_string(),
        lockfile: analysis.lock_path.display().to_string(),
        project_score: analysis.score.project_score,
        project_severity: analysis.score.project_severity,
        gate: JsonGate {
            mode: mode_de(analysis.decision.mode),
            outcome: outcome_de(analysis.decision.outcome),
            exit_code: analysis.decision.exit_code,
        },
        packages: &analysis.score.packages,
        violations: analysis
            .decision
            .violations
            .iter()
            .map(|violation| JsonViolation {
                rule: violation.rule,
                package_name: &violation.package_name,
                package_version: &violation.package_version,
                configured_action: action_name(violation.configured_action),
                effective_action: action_name(violation.effective_action),
                message: &violation.message,
            })
            .collect(),
        notes: &analysis.decision.notes,
        hooks: &analysis.hooks.findings,
        heuristics: &analysis.heuristics,
        advisories: &analysis.advisories,
    };
    let text = serde_json::to_string_pretty(&document).map_err(|source| Error::Json {
        path: "report.json".to_owned(),
        source,
    })?;
    Ok(format!("{text}\n"))
}

fn render_cyclonedx(analysis: &Analysis, scanned_at: &str) -> Result<String> {
    let mut components = Vec::new();
    for package in analysis
        .lock
        .packages
        .iter()
        .filter(|package| !package.is_root)
    {
        components.push(component(package));
    }
    components.sort_by(|left, right| {
        left["purl"]
            .as_str()
            .unwrap_or("")
            .cmp(right["purl"].as_str().unwrap_or(""))
    });
    let identity = components
        .iter()
        .filter_map(|component| component["purl"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let serial = Uuid::new_v5(&Uuid::NAMESPACE_OID, identity.as_bytes());
    let root = analysis.lock.root();
    let bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{serial}"),
        "version": 1,
        "metadata": {
            "timestamp": scanned_at,
            "tools": {
                "components": [{
                    "type": "application",
                    "name": "lockward",
                    "version": VERSION,
                    "author": "YaDe Labs"
                }]
            },
            "component": {
                "type": "application",
                "name": root.map(|package| package.name.as_str()).unwrap_or("unknown"),
                "version": root.map(|package| package.version.as_str()).unwrap_or("0.0.0"),
                "purl": root.map(|package| purl(&package.name, &package.version)).unwrap_or_else(|| "pkg:generic/unknown@0.0.0".to_owned())
            }
        },
        "components": components
    });
    let text = serde_json::to_string_pretty(&bom).map_err(|source| Error::Json {
        path: "bom.cdx.json".to_owned(),
        source,
    })?;
    Ok(format!("{text}\n"))
}

fn component(package: &Package) -> Value {
    let mut value = json!({
        "type": "library",
        "name": package.name,
        "version": package.version,
        "purl": purl(&package.name, &package.version),
        "scope": if package.dev { "optional" } else { "required" }
    });
    if let Some(license) = &package.license {
        value["licenses"] = json!([cyclonedx_license(license)]);
    }
    if let Some((alg, content)) = package.integrity.as_deref().and_then(sri_hash) {
        value["hashes"] = json!([{ "alg": alg, "content": content }]);
    }
    value
}

/// Classify a lockfile license for CycloneDX 1.6.
///
/// A known SPDX identifier becomes `license.id`. An expression (`OR`, `AND`,
/// `WITH`, or parentheses) that the SPDX grammar accepts becomes `expression`.
/// Anything else is free text in `license.name`, so a random string never lands
/// in `license.id`.
fn cyclonedx_license(license: &str) -> Value {
    let text = license.trim();
    if spdx_expression_syntax(text) {
        if spdx::Expression::parse(text).is_ok() {
            return json!({ "expression": text });
        }
        return json!({ "license": { "name": text } });
    }
    if spdx::license_id(text).is_some() {
        json!({ "license": { "id": text } })
    } else {
        json!({ "license": { "name": text } })
    }
}

fn spdx_expression_syntax(text: &str) -> bool {
    text.contains('(')
        || text.contains(')')
        || text.split_whitespace().any(|word| {
            word.eq_ignore_ascii_case("OR")
                || word.eq_ignore_ascii_case("AND")
                || word.eq_ignore_ascii_case("WITH")
        })
}

fn purl(name: &str, version: &str) -> String {
    if let Some((scope, pkg)) = name.strip_prefix('@').and_then(|rest| rest.split_once('/')) {
        format!("pkg:npm/%40{scope}/{pkg}@{version}")
    } else {
        format!("pkg:npm/{name}@{version}")
    }
}

fn sri_hash(integrity: &str) -> Option<(&'static str, String)> {
    let (alg, payload) = integrity.split_once('-')?;
    let name = match alg {
        "sha256" => "SHA-256",
        "sha384" => "SHA-384",
        "sha512" => "SHA-512",
        _ => return None,
    };
    let bytes = STANDARD
        .decode(payload)
        .or_else(|_| URL_SAFE.decode(payload))
        .ok()?;
    Some((name, hex::encode(bytes)))
}

/// Collapse untrusted text onto one line and strip characters that close a codespan.
fn one_line(raw: &str) -> String {
    let flat = raw
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace('`', "'");
    if flat.chars().count() > MARKDOWN_FIELD_MAX {
        let kept: String = flat.chars().take(MARKDOWN_FIELD_MAX).collect();
        format!("{kept}…")
    } else {
        flat
    }
}

/// One CommonMark codespan. The contents cannot close the span or start a new line.
fn markdown_span(raw: &str) -> String {
    format!("`{}`", one_line(raw))
}

fn severity_de(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "kritisch",
        Severity::High => "hoch",
        Severity::Medium => "mittel",
        Severity::Low => "niedrig",
        Severity::Unknown => "unbekannt",
    }
}

fn outcome_de(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Ok => "OK",
        Outcome::Warn => "Warnung",
        Outcome::Fail => "Block",
    }
}

fn mode_de(mode: Mode) -> &'static str {
    match mode {
        Mode::Warn => "warn",
        Mode::Enforce => "enforce",
    }
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Allow => "allow",
        Action::Warn => "warn",
        Action::Review => "review",
        Action::Fail => "fail",
    }
}

#[derive(Serialize)]
struct JsonReport<'a> {
    lockward_version: &'a str,
    score_version: &'a str,
    heuristics_version: &'a str,
    scanned_at: &'a str,
    target: String,
    lockfile: String,
    project_score: u32,
    project_severity: Severity,
    gate: JsonGate<'a>,
    packages: &'a [crate::score::PackageScore],
    violations: Vec<JsonViolation<'a>>,
    notes: &'a [String],
    hooks: &'a [crate::hooks::HookFinding],
    heuristics: &'a [crate::heuristics::HeuristicFinding],
    advisories: &'a crate::advisories::AdvisoryReport,
}

#[derive(Serialize)]
struct JsonGate<'a> {
    mode: &'a str,
    outcome: &'a str,
    exit_code: u8,
}

#[derive(Serialize)]
struct JsonViolation<'a> {
    rule: &'a str,
    package_name: &'a str,
    package_version: &'a str,
    configured_action: &'a str,
    effective_action: &'a str,
    message: &'a str,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisories::HttpTransport;
    use crate::policy::Policy;
    use crate::scan::{AnalyzeOptions, analyze};
    use std::fs;
    use std::path::Path;

    struct OfflineOnly;

    impl HttpTransport for OfflineOnly {
        fn post_json(&self, url: &str, _body: &Value) -> Result<Value> {
            Err(Error::Advisory {
                url: url.to_owned(),
                message: "offline".to_owned(),
            })
        }

        fn get_json(&self, url: &str) -> Result<Value> {
            Err(Error::Advisory {
                url: url.to_owned(),
                message: "offline".to_owned(),
            })
        }
    }

    fn mini() -> crate::scan::Analysis {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/report/mini");
        analyze(
            &root,
            &OfflineOnly,
            &AnalyzeOptions {
                offline: true,
                cache_dir: None,
                policy: Policy::default_policy().unwrap(),
                baseline: None,
            },
        )
        .unwrap()
    }

    fn normalize(text: &str, root: &Path) -> String {
        let display = root.display().to_string();
        let escaped = display.replace('\\', "\\\\");
        text.replace(&escaped, "{root}")
            .replace(&display, "{root}")
            .replace('\\', "/")
            .replace("\r\n", "\n")
    }

    fn expect(name: &str, actual: &str) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/report/golden")
            .join(name);
        let expected = fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("missing golden {}: {err}", path.display()))
            .replace("\r\n", "\n");
        assert_eq!(expected, actual, "golden mismatch for {name}");
    }

    #[test]
    fn golden_files_cover_all_four_formats() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/report/mini");
        let analysis = mini();
        let markdown = normalize(
            &render(&analysis, ReportKind::Markdown, GOLDEN_TIMESTAMP).unwrap(),
            &root,
        );
        let summary = normalize(
            &render(&analysis, ReportKind::Summary, GOLDEN_TIMESTAMP).unwrap(),
            &root,
        );
        let json_text = normalize(
            &render(&analysis, ReportKind::Json, GOLDEN_TIMESTAMP).unwrap(),
            &root,
        );
        let bom = normalize(
            &render(&analysis, ReportKind::CycloneDx, GOLDEN_TIMESTAMP).unwrap(),
            &root,
        );
        expect("comment.md", &markdown);
        expect("summary.md", &summary);
        expect("report.json", &json_text);
        expect("bom.cdx.json", &bom);

        let parsed: Value = serde_json::from_str(&json_text).unwrap();
        assert_eq!(parsed["gate"]["exit_code"], 1);
        assert!(parsed["heuristics_version"] == "heuristics-v1");

        let cdx: Value = serde_json::from_str(&bom).unwrap();
        assert_eq!(cdx["bomFormat"], "CycloneDX");
        assert_eq!(cdx["specVersion"], "1.6");
        assert!(
            cdx["serialNumber"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:")
        );
        let components = cdx["components"].as_array().unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0]["name"], "left-pad");
        assert_eq!(components[0]["purl"], "pkg:npm/left-pad@1.0.0");
        assert_eq!(components[0]["hashes"][0]["alg"], "SHA-512");
        assert_eq!(
            normalize(
                &render(&analysis, ReportKind::CycloneDx, GOLDEN_TIMESTAMP).unwrap(),
                &root
            ),
            bom
        );
    }

    #[test]
    fn hostile_hook_text_stays_inside_one_codespan() {
        let dir = std::env::temp_dir().join(format!("lockward-md-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let raw = "curl ` | [link](http://evil.example) <script>alert(1)</script>\nsecond-line";
        fs::write(
            dir.join("package.json"),
            format!(
                r#"{{ "name": "pkg`](http://evil.example)<img>", "version": "1.0.0", "scripts": {{ "postinstall": {raw} }} }}"#,
                raw = serde_json::to_string(raw).unwrap()
            ),
        )
        .unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "pkg",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "packages": { "": { "name": "pkg`](http://evil.example)<img>", "version": "1.0.0" } }
            }"#,
        )
        .unwrap();
        let analysis = analyze(
            &dir,
            &OfflineOnly,
            &AnalyzeOptions {
                offline: true,
                cache_dir: None,
                policy: Policy::default_policy().unwrap(),
                baseline: None,
            },
        )
        .unwrap();
        let markdown = render(&analysis, ReportKind::Markdown, GOLDEN_TIMESTAMP).unwrap();
        let summary = render(&analysis, ReportKind::Summary, GOLDEN_TIMESTAMP).unwrap();
        for document in [&markdown, &summary] {
            assert_eq!(document.matches('`').count() % 2, 0, "{document}");
            let outside = text_outside_codespans(document);
            assert!(!outside.contains('<'), "{outside}");
            assert!(!outside.contains("]("), "{outside}");
            assert!(!outside.contains('|'), "{outside}");
        }
        assert!(markdown.contains(
            "curl ' | [link](http://evil.example) <script>alert(1)</script> second-line"
        ));
        assert!(!markdown.contains("\nsecond-line"));
        let hook_line = markdown
            .lines()
            .find(|line| line.contains("second-line"))
            .expect("hook line");
        assert_eq!(hook_line.matches('`').count(), 8, "{hook_line}");
        let json = render(&analysis, ReportKind::Json, GOLDEN_TIMESTAMP).unwrap();
        assert!(json.contains("second-line"));
        assert!(json.contains("<script>"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn cyclonedx_license_uses_id_expression_or_name() {
        assert_eq!(
            cyclonedx_license("MIT"),
            json!({ "license": { "id": "MIT" } })
        );
        assert_eq!(
            cyclonedx_license("(MIT OR Apache-2.0)"),
            json!({ "expression": "(MIT OR Apache-2.0)" })
        );
        assert_eq!(
            cyclonedx_license("SEE LICENSE IN LICENSE"),
            json!({ "license": { "name": "SEE LICENSE IN LICENSE" } })
        );
        assert_eq!(
            cyclonedx_license("MIT OR NOPE"),
            json!({ "license": { "name": "MIT OR NOPE" } })
        );
    }

    fn text_outside_codespans(markdown: &str) -> String {
        let mut outside = String::new();
        let mut in_span = false;
        for ch in markdown.chars() {
            if ch == '`' {
                in_span = !in_span;
                continue;
            }
            if !in_span {
                outside.push(ch);
            }
        }
        outside
    }
}
