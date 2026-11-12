// SPDX-License-Identifier: AGPL-3.0-only

//! Render a finished scan as Markdown, a CI summary, JSON, or CycloneDX.

use crate::advisories::Severity;
use crate::ingest::Package;
use crate::scan::Analysis;
use crate::{Error, Result, VERSION};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
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
        "**Target:** {}\n\n",
        markdown_span(&analysis.project_root.display().to_string())
    ));
    out.push_str(&format!("**Scanned at:** {scanned_at}\n\n"));
    out.push_str(&format!(
        "**Score:** {} ({})\n\n",
        analysis.score.project_score,
        analysis.score.project_severity.label()
    ));
    out.push_str(&format!(
        "**Gate:** {} · Exit {} · mode {}\n\n",
        analysis.decision.outcome.label(),
        analysis.decision.exit_code,
        analysis.decision.mode.label()
    ));
    out.push_str("### Why\n\n");
    if analysis.score.packages.is_empty() && analysis.decision.violations.is_empty() {
        out.push_str("No scored findings.\n\n");
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
    out.push_str("### Install hooks\n\n");
    if analysis.hooks.findings.is_empty() {
        out.push_str("No install hooks.\n\n");
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
        out.push_str("No advisories in the cache.\n");
    } else {
        for (package, advisory) in advisories {
            out.push_str(&format!(
                "- {}@{} {} ({})\n",
                markdown_span(&package.name),
                markdown_span(&package.version),
                markdown_span(&advisory.id),
                advisory.severity.label()
            ));
        }
    }
    if !analysis.decision.notes.is_empty() {
        out.push_str("\n### Notes\n\n");
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
        "Score **{}** ({}) · Gate **{}** (Exit {}, mode {}) · {scanned_at}\n\n",
        analysis.score.project_score,
        analysis.score.project_severity.label(),
        analysis.decision.outcome.label(),
        analysis.decision.exit_code,
        analysis.decision.mode.label()
    ));
    if analysis.decision.violations.is_empty() {
        out.push_str("No policy findings.\n");
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
        report_version: REPORT_VERSION,
        score_version: analysis.score.version,
        heuristics_version: analysis.score.heuristics_version,
        scanned_at,
        target: analysis.project_root.display().to_string(),
        lockfile: analysis.lock_path.display().to_string(),
        project_score: analysis.score.project_score,
        project_severity: analysis.score.project_severity,
        gate: JsonGate {
            mode: analysis.decision.mode.as_str(),
            outcome: analysis.decision.outcome.as_str(),
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
                configured_action: violation.configured_action.as_str(),
                effective_action: violation.effective_action.as_str(),
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

struct MergedPackage {
    name: String,
    version: String,
    purl: String,
    dev: bool,
    optional: bool,
    peer: bool,
    license: Option<String>,
    integrity: Option<String>,
}

impl MergedPackage {
    fn from_package(package: &Package) -> Self {
        Self {
            purl: purl(&package.name, &package.version),
            name: package.name.clone(),
            version: package.version.clone(),
            dev: package.dev,
            optional: package.optional,
            peer: package.peer,
            license: package.license.clone(),
            integrity: package.integrity.clone(),
        }
    }

    /// The less restrictive scope wins. A string that is already set stays,
    /// so the lexicographically smallest path that had a value keeps it.
    fn merge(&mut self, package: &Package) {
        if !package.dev && self.dev {
            self.dev = false;
            self.optional = package.optional;
        } else if !self.dev && self.optional && !package.dev && !package.optional {
            self.optional = false;
        }
        self.peer |= package.peer;
        if self.license.is_none() {
            self.license.clone_from(&package.license);
        }
        if self.integrity.is_none() {
            self.integrity.clone_from(&package.integrity);
        }
    }

    fn to_component(&self) -> Value {
        let mut value = json!({
            "type": "library",
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "bom-ref": self.purl,
        });
        let (scope, properties) = scope_and_properties(self.dev, self.optional, self.peer);
        value["scope"] = json!(scope);
        if !properties.is_empty() {
            value["properties"] = property_values(&properties);
        }
        if let Some(license) = &self.license {
            value["licenses"] = json!([cyclonedx_license(license)]);
        }
        if let Some((alg, content)) = self.integrity.as_deref().and_then(sri_hash) {
            value["hashes"] = json!([{ "alg": alg, "content": content }]);
        }
        value
    }
}

fn property_values(properties: &[(&str, &str)]) -> Value {
    json!(
        properties
            .iter()
            .map(|(name, property_value)| json!({ "name": name, "value": property_value }))
            .collect::<Vec<_>>()
    )
}

fn bom_document(
    lock: &crate::ingest::Lockfile,
    graph: &crate::resolve::Graph,
    scanned_at: &str,
) -> Value {
    let mut packages: Vec<&Package> = lock
        .packages
        .iter()
        .filter(|package| !package.is_root)
        .collect();
    packages.sort_by(|left, right| left.path.cmp(&right.path));

    let mut merged: BTreeMap<String, MergedPackage> = BTreeMap::new();
    let mut path_ref: BTreeMap<&str, String> = BTreeMap::new();
    for package in packages {
        let component_ref = purl(&package.name, &package.version);
        path_ref.insert(package.path.as_str(), component_ref.clone());
        merged
            .entry(component_ref)
            .and_modify(|existing| existing.merge(package))
            .or_insert_with(|| MergedPackage::from_package(package));
    }

    let root = lock.root();
    let root_name = root
        .map(|package| package.name.as_str())
        .unwrap_or("unknown");
    let root_version = root
        .map(|package| package.version.as_str())
        .unwrap_or("0.0.0");
    let root_ref = root
        .map(|package| purl(&package.name, &package.version))
        .unwrap_or_else(|| "pkg:generic/unknown@0.0.0".to_owned());
    path_ref.insert("", root_ref.clone());

    let mut depends: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    depends.insert(root_ref.clone(), BTreeSet::new());
    for component_ref in merged.keys() {
        depends.insert(component_ref.clone(), BTreeSet::new());
    }
    for edge in &graph.edges {
        let from = graph.nodes[edge.from].package_path.as_str();
        let to = graph.nodes[edge.to].package_path.as_str();
        let (Some(from_ref), Some(to_ref)) = (path_ref.get(from), path_ref.get(to)) else {
            continue;
        };
        depends
            .entry(from_ref.clone())
            .or_default()
            .insert(to_ref.clone());
    }

    let components: Vec<Value> = merged.values().map(MergedPackage::to_component).collect();
    let dependencies: Vec<Value> = depends
        .iter()
        .map(|(component_ref, targets)| {
            json!({
                "ref": component_ref,
                "dependsOn": targets.iter().cloned().collect::<Vec<_>>()
            })
        })
        .collect();
    let mut bom = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
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
                "bom-ref": root_ref,
                "name": root_name,
                "version": root_version,
                "purl": root_ref,
                "properties": [{
                    "name": "lockward:unresolved-edges",
                    "value": graph.unresolved.len().to_string()
                }]
            }
        },
        "components": components,
        "dependencies": dependencies
    });
    let serial = content_serial(&bom);
    if let Some(object) = bom.as_object_mut() {
        object.insert("serialNumber".to_owned(), json!(serial));
    }
    bom
}

/// RFC 4122 UUID v5 of the BOM with `serialNumber` and `metadata.timestamp` removed.
///
/// Object keys are sorted so two equivalent documents hash the same. CycloneDX
/// recommends a fresh serial for every generated BOM; this content hash is the
/// deliberate exception, recorded in ADR 015.
fn content_serial(bom: &Value) -> String {
    let mut canonical = bom.clone();
    if let Some(object) = canonical.as_object_mut() {
        object.remove("serialNumber");
    }
    if let Some(metadata) = canonical.get_mut("metadata").and_then(Value::as_object_mut) {
        metadata.remove("timestamp");
    }
    let serial = Uuid::new_v5(&Uuid::NAMESPACE_OID, canonical_json(&canonical).as_bytes());
    format!("urn:uuid:{serial}")
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => serde_json::to_string(text).unwrap_or_else(|_| "\"\"".to_owned()),
        Value::Array(items) => {
            let body = items
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",");
            format!("[{body}]")
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let body = keys
                .into_iter()
                .map(|key| {
                    let encoded = serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_owned());
                    format!("{encoded}:{}", canonical_json(&map[key]))
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
    }
}

fn render_cyclonedx(analysis: &Analysis, scanned_at: &str) -> Result<String> {
    let bom = bom_document(&analysis.lock, &analysis.graph, scanned_at);
    let text = serde_json::to_string_pretty(&bom).map_err(|source| Error::Json {
        path: "bom.cdx.json".to_owned(),
        source,
    })?;
    Ok(format!("{text}\n"))
}

/// CycloneDX 1.6 scope and Lockward properties for one lockfile package.
///
/// `dev` is `excluded` (non-runtime) and records `lockward:dev`. `optional`
/// without `dev` is `optional`. Anything else is `required`. `peer` does not
/// change the scope; it records `lockward:peer`. Property values are strings
/// and the list is sorted by name.
fn scope_and_properties(
    dev: bool,
    optional: bool,
    peer: bool,
) -> (&'static str, Vec<(&'static str, &'static str)>) {
    let mut properties = Vec::new();
    let scope = if dev {
        properties.push(("lockward:dev", "true"));
        "excluded"
    } else if optional {
        "optional"
    } else {
        "required"
    };
    if peer {
        properties.push(("lockward:peer", "true"));
    }
    properties.sort_by_key(|property| property.0);
    (scope, properties)
}

#[cfg(test)]
fn component(package: &Package) -> Value {
    let mut value = json!({
        "type": "library",
        "name": package.name,
        "version": package.version,
        "purl": purl(&package.name, &package.version),
    });
    let (scope, properties) = scope_and_properties(package.dev, package.optional, package.peer);
    value["scope"] = json!(scope);
    if !properties.is_empty() {
        value["properties"] = json!(
            properties
                .iter()
                .map(|(name, property_value)| json!({ "name": name, "value": property_value }))
                .collect::<Vec<_>>()
        );
    }
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

/// JSON document shape. Free-text fields are not part of this contract.
pub const REPORT_VERSION: u32 = 2;

#[derive(Serialize)]
struct JsonReport<'a> {
    lockward_version: &'a str,
    report_version: u32,
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
        // JSON writes one Windows separator as two backslashes. After the root
        // is replaced, that pair must become a single slash or Linux (which
        // never escapes `/`) cannot match a golden produced on Windows.
        text.replace(&escaped, "{root}")
            .replace(&display, "{root}")
            .replace("{root}\\\\", "{root}\\")
            .replace("{root}//", "{root}/")
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
        assert!(parsed["heuristics_version"] == "heuristics-v1.1");

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
        assert_eq!(hook_line.matches('`').count(), 2, "{hook_line}");
        let json = render(&analysis, ReportKind::Json, GOLDEN_TIMESTAMP).unwrap();
        assert!(json.contains("second-line"));
        assert!(json.contains("<script>"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn purl_encodes_a_scope_and_keeps_the_lockfile_case() {
        assert_eq!(purl("@scope/pkg", "1.2.3"), "pkg:npm/%40scope/pkg@1.2.3");
        assert_eq!(purl("Left-Pad", "1.0.0"), "pkg:npm/Left-Pad@1.0.0");
        assert_eq!(purl("left-pad", "1.0.0"), "pkg:npm/left-pad@1.0.0");
    }

    #[test]
    fn sri_hash_accepts_sha256_sha384_sha512_and_url_safe_base64() {
        let cases = [
            (
                "sha256-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=",
                "SHA-256",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                "sha384-ywB1P0WjXou1oD1pmsZQBycsMqsO3tFjGotgWkP/W+2AhgcroefMI1i67KE0yCWn",
                "SHA-384",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                "sha512-3a81oZNherrMQXNJriBBMRLm+k6JqX6iCp7u5ktV05ohkpkqJ0/BqDa6PCOj/uu9RU1EI2Q86A4qmslPpUyknw==",
                "SHA-512",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                "sha256-ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0=",
                "SHA-256",
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
        ];
        for (integrity, alg, hex_digest) in cases {
            let (got_alg, got_hex) = sri_hash(integrity).unwrap_or_else(|| panic!("{integrity}"));
            assert_eq!(got_alg, alg, "{integrity}");
            assert_eq!(got_hex, hex_digest, "{integrity}");
        }
        assert!(sri_hash("sha256-!!!!").is_none());
        assert!(sri_hash("md5-ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=").is_none());
        assert!(sri_hash("not-a-hash").is_none());
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

    fn flagged_package(dev: bool, optional: bool, peer: bool) -> Package {
        Package {
            path: "node_modules/pkg".to_owned(),
            name: "pkg".to_owned(),
            version: "1.0.0".to_owned(),
            resolved: None,
            integrity: None,
            dev,
            optional,
            peer,
            is_root: false,
            has_install_script: false,
            license: None,
            dependencies: std::collections::BTreeMap::new(),
            dev_dependencies: std::collections::BTreeMap::new(),
            optional_dependencies: std::collections::BTreeMap::new(),
            peer_dependencies: std::collections::BTreeMap::new(),
            bins: std::collections::BTreeMap::new(),
        }
    }

    fn property_pairs(component: &Value) -> Vec<(String, String)> {
        component["properties"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .map(|item| {
                        (
                            item["name"].as_str().unwrap_or("").to_owned(),
                            item["value"].as_str().unwrap_or("").to_owned(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    #[test]
    fn required_package_has_no_scope_property() {
        let value = component(&flagged_package(false, false, false));
        assert_eq!(value["scope"], "required");
        assert!(value.get("properties").is_none());
    }

    #[test]
    fn optional_package_is_optional_without_a_dev_property() {
        let value = component(&flagged_package(false, true, false));
        assert_eq!(value["scope"], "optional");
        assert!(property_pairs(&value).is_empty());
    }

    #[test]
    fn dev_package_is_excluded_and_marked() {
        let value = component(&flagged_package(true, false, false));
        assert_eq!(value["scope"], "excluded");
        assert_eq!(
            property_pairs(&value),
            vec![("lockward:dev".to_owned(), "true".to_owned())]
        );
    }

    #[test]
    fn dev_and_optional_stays_excluded() {
        let value = component(&flagged_package(true, true, false));
        assert_eq!(value["scope"], "excluded");
        assert_eq!(
            property_pairs(&value),
            vec![("lockward:dev".to_owned(), "true".to_owned())]
        );
    }

    #[test]
    fn peer_keeps_scope_and_sets_a_string_property() {
        let value = component(&flagged_package(false, false, true));
        assert_eq!(value["scope"], "required");
        assert_eq!(
            property_pairs(&value),
            vec![("lockward:peer".to_owned(), "true".to_owned())]
        );
        let raw = &value["properties"][0]["value"];
        assert!(raw.is_string());
    }

    const LIB_LOCK: &str = r#"{
      "name": "app", "version": "1.0.0", "lockfileVersion": 3,
      "packages": {
        "": { "name": "app", "version": "1.0.0", "dependencies": { "lib": "1.0.0", "other": "1.0.0" } },
        "node_modules/lib": { "version": "1.0.0", "license": "MIT" },
        "node_modules/other": { "version": "1.0.0" }
      }
    }"#;

    #[test]
    fn serial_follows_content_not_path_or_timestamp() {
        let flat = bom_of(LIB_LOCK);
        let nested = bom_of(
            r#"{
              "name": "app", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "lib": "1.0.0", "other": "1.0.0" } },
                "node_modules/lib": { "version": "1.0.0", "license": "MIT" },
                "node_modules/extra/node_modules/lib": { "version": "1.0.0", "license": "MIT" },
                "node_modules/other": { "version": "1.0.0" }
              }
            }"#,
        );
        assert_eq!(flat["serialNumber"], nested["serialNumber"]);
        let lock = crate::ingest::parse_lockfile_str(LIB_LOCK, "bom.json").unwrap();
        let graph = crate::resolve::resolve(&lock);
        let later = bom_document(&lock, &graph, "2030-01-01T00:00:00Z");
        assert_eq!(flat["serialNumber"], later["serialNumber"]);
    }

    #[test]
    fn serial_changes_when_scope_or_edge_changes() {
        let base = bom_of(LIB_LOCK);
        let dev = bom_of(
            r#"{
              "name": "app", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "lib": "1.0.0", "other": "1.0.0" } },
                "node_modules/lib": { "version": "1.0.0", "license": "MIT", "dev": true },
                "node_modules/other": { "version": "1.0.0" }
              }
            }"#,
        );
        let linked = bom_of(
            r#"{
              "name": "app", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "lib": "1.0.0", "other": "1.0.0" } },
                "node_modules/lib": { "version": "1.0.0", "license": "MIT", "dependencies": { "other": "1.0.0" } },
                "node_modules/other": { "version": "1.0.0" }
              }
            }"#,
        );
        assert_ne!(base["serialNumber"], dev["serialNumber"]);
        assert_ne!(base["serialNumber"], linked["serialNumber"]);
    }

    fn bom_of(lock_json: &str) -> Value {
        let lock = crate::ingest::parse_lockfile_str(lock_json, "bom.json").unwrap();
        let graph = crate::resolve::resolve(&lock);
        bom_document(&lock, &graph, GOLDEN_TIMESTAMP)
    }

    fn refs_of(bom: &Value) -> std::collections::BTreeSet<String> {
        let mut refs = std::collections::BTreeSet::new();
        if let Some(component) = bom["metadata"]["component"].as_object() {
            refs.insert(component["bom-ref"].as_str().unwrap_or("").to_owned());
        }
        for component in bom["components"].as_array().unwrap() {
            refs.insert(component["bom-ref"].as_str().unwrap_or("").to_owned());
        }
        refs
    }

    #[test]
    fn dependency_graph_refs_resolve_and_cover_every_component() {
        let bom = bom_of(
            r#"{
              "name": "app", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "left-pad": "1.0.0", "missing": "1.0.0" } },
                "node_modules/left-pad": { "version": "1.0.0" }
              }
            }"#,
        );
        assert_eq!(bom["metadata"]["component"]["bom-ref"], "pkg:npm/app@1.0.0");
        assert_eq!(bom["components"][0]["bom-ref"], "pkg:npm/left-pad@1.0.0");
        let refs = refs_of(&bom);
        let dependencies = bom["dependencies"].as_array().expect("dependencies");
        assert_eq!(dependencies.len(), refs.len());
        for edge in dependencies {
            let source = edge["ref"].as_str().unwrap();
            assert!(refs.contains(source), "{source}");
            for target in edge["dependsOn"].as_array().unwrap() {
                let target = target.as_str().unwrap();
                assert!(refs.contains(target), "{target}");
                assert!(!target.contains("missing"));
            }
        }
        let root = dependencies
            .iter()
            .find(|edge| edge["ref"] == "pkg:npm/app@1.0.0")
            .unwrap();
        assert_eq!(root["dependsOn"], json!(["pkg:npm/left-pad@1.0.0"]));
        assert_eq!(
            bom["metadata"]["component"]["properties"],
            json!([{ "name": "lockward:unresolved-edges", "value": "1" }])
        );
    }

    #[test]
    fn duplicate_name_version_keeps_the_less_restrictive_scope() {
        let bom = bom_of(
            r#"{
              "name": "app", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "lib": "1.0.0" } },
                "node_modules/lib": { "name": "lib", "version": "1.0.0", "dev": true, "license": "MIT" },
                "node_modules/wrapper/node_modules/lib": { "name": "lib", "version": "1.0.0", "license": "ISC" }
              }
            }"#,
        );
        let libs: Vec<_> = bom["components"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|component| component["name"] == "lib")
            .collect();
        assert_eq!(libs.len(), 1);
        assert_eq!(libs[0]["scope"], "required");
        assert!(libs[0].get("properties").is_none());
        assert_eq!(libs[0]["licenses"][0]["license"]["id"], "MIT");
    }

    #[test]
    fn cycles_stay_in_the_dependency_graph() {
        let bom = bom_of(
            r#"{
              "name": "app", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "a": "1.0.0" } },
                "node_modules/a": { "version": "1.0.0", "dependencies": { "b": "1.0.0" } },
                "node_modules/b": { "version": "1.0.0", "dependencies": { "a": "1.0.0" } }
              }
            }"#,
        );
        let depends_on = |name: &str| {
            let purl = format!("pkg:npm/{name}@1.0.0");
            bom["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .find(|edge| edge["ref"] == purl)
                .unwrap()["dependsOn"]
                .clone()
        };
        assert_eq!(depends_on("a"), json!(["pkg:npm/b@1.0.0"]));
        assert_eq!(depends_on("b"), json!(["pkg:npm/a@1.0.0"]));
    }

    #[test]
    fn dev_optional_and_peer_edges_are_all_recorded() {
        let bom = bom_of(
            r#"{
              "name": "app", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "": {
                  "name": "app", "version": "1.0.0",
                  "devDependencies": { "dev-tool": "1.0.0" },
                  "optionalDependencies": { "opt": "1.0.0" },
                  "peerDependencies": { "peer": "1.0.0" }
                },
                "node_modules/dev-tool": { "version": "1.0.0", "dev": true },
                "node_modules/opt": { "version": "1.0.0", "optional": true },
                "node_modules/peer": { "version": "1.0.0", "peer": true }
              }
            }"#,
        );
        let root = bom["dependencies"]
            .as_array()
            .unwrap()
            .iter()
            .find(|edge| edge["ref"] == "pkg:npm/app@1.0.0")
            .unwrap();
        assert_eq!(
            root["dependsOn"],
            json!([
                "pkg:npm/dev-tool@1.0.0",
                "pkg:npm/opt@1.0.0",
                "pkg:npm/peer@1.0.0"
            ])
        );
        let by_name = |name: &str| {
            bom["components"]
                .as_array()
                .unwrap()
                .iter()
                .find(|component| component["name"] == name)
                .unwrap()
                .clone()
        };
        assert_eq!(by_name("dev-tool")["scope"], "excluded");
        assert_eq!(by_name("opt")["scope"], "optional");
        assert_eq!(by_name("peer")["scope"], "required");
        assert_eq!(by_name("peer")["properties"][0]["name"], "lockward:peer");
    }

    #[test]
    fn package_order_does_not_change_the_graph() {
        let first = bom_of(
            r#"{
              "name": "app", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "node_modules/b": { "version": "1.0.0" },
                "": { "name": "app", "version": "1.0.0", "dependencies": { "a": "1.0.0", "b": "1.0.0" } },
                "node_modules/a": { "version": "1.0.0" }
              }
            }"#,
        );
        let second = bom_of(
            r#"{
              "name": "app", "version": "1.0.0", "lockfileVersion": 3,
              "packages": {
                "node_modules/a": { "version": "1.0.0" },
                "": { "name": "app", "version": "1.0.0", "dependencies": { "b": "1.0.0", "a": "1.0.0" } },
                "node_modules/b": { "version": "1.0.0" }
              }
            }"#,
        );
        assert_eq!(first["components"], second["components"]);
        assert_eq!(first["dependencies"], second["dependencies"]);
    }

    #[test]
    fn dev_and_peer_properties_are_sorted() {
        let value = component(&flagged_package(true, false, true));
        assert_eq!(value["scope"], "excluded");
        assert_eq!(
            property_pairs(&value),
            vec![
                ("lockward:dev".to_owned(), "true".to_owned()),
                ("lockward:peer".to_owned(), "true".to_owned()),
            ]
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
