//! Deterministic risk score with a plain-language explanation per finding.
//!
//! Points come only from advisory severity and heuristic rule weights. The
//! same inputs always produce the same numbers.

use crate::advisories::{AdvisoryReport, PackageAdvisories, Severity};
use crate::heuristics::{ENGINE_VERSION, HeuristicFinding};
use crate::ingest::{Lockfile, Package};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Score model version written into reports.
pub const SCORE_VERSION: &str = "score-v1";

/// Upper bound for advisory points on one package.
pub const ADVISORY_CAP: u32 = 70;

/// Upper bound for heuristic points on one package.
pub const HEURISTIC_CAP: u32 = 60;

/// One sentence tied to a rule id or an advisory id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Explanation {
    /// Advisory id or heuristic rule id.
    pub source: String,
    /// German reason.
    pub text: String,
}

/// Score for a single package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageScore {
    /// Lockfile path.
    pub package_path: String,
    /// Package name.
    pub name: String,
    /// Locked version.
    pub version: String,
    /// `advisory_points + heuristic_points`, capped at 100.
    pub score: u32,
    /// Band derived from `score`, not from a single advisory.
    pub severity: Severity,
    /// Advisory contribution after the cap.
    pub advisory_points: u32,
    /// Heuristic contribution after the cap. Each rule counts once.
    pub heuristic_points: u32,
    /// One entry per advisory and per heuristic hit, sorted by source.
    pub explanations: Vec<Explanation>,
}

/// Project score. `project_score` is the maximum package score.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ScoreReport {
    /// [`SCORE_VERSION`].
    pub version: &'static str,
    /// [`ENGINE_VERSION`] of the heuristics that were scored.
    pub heuristics_version: &'static str,
    /// Highest package score, or 0.
    pub project_score: u32,
    /// Band of `project_score`.
    pub project_severity: Severity,
    /// Packages that have at least one finding, sorted by path.
    pub packages: Vec<PackageScore>,
}

/// Points assigned to one advisory before the package cap.
#[must_use]
pub fn advisory_weight(severity: Severity) -> u32 {
    match severity {
        Severity::Critical => 40,
        Severity::High => 25,
        Severity::Medium => 12,
        Severity::Low => 4,
        Severity::Unknown => 6,
    }
}

/// Band for a package or project score.
#[must_use]
pub fn band(score: u32) -> Severity {
    match score {
        75.. => Severity::Critical,
        50.. => Severity::High,
        25.. => Severity::Medium,
        10.. => Severity::Low,
        _ => Severity::Unknown,
    }
}

/// Score a lockfile from advisory matches and heuristic hits.
#[must_use]
pub fn score(
    lock: &Lockfile,
    advisories: &AdvisoryReport,
    heuristics: &[HeuristicFinding],
) -> ScoreReport {
    score_parts(&lock.packages, &advisories.packages, heuristics)
}

/// Score from already sliced inputs. Useful in tests.
#[must_use]
pub fn score_parts(
    packages: &[Package],
    advisories: &[PackageAdvisories],
    heuristics: &[HeuristicFinding],
) -> ScoreReport {
    let mut names: BTreeMap<&str, (&str, &str)> = BTreeMap::new();
    for package in packages {
        names.insert(
            package.path.as_str(),
            (package.name.as_str(), package.version.as_str()),
        );
    }

    let mut advisory_groups: BTreeMap<String, Vec<&crate::advisories::Advisory>> = BTreeMap::new();
    let mut identity: BTreeMap<String, (String, String)> = BTreeMap::new();
    for package in advisories {
        for advisory in &package.advisories {
            advisory_groups
                .entry(package.package_path.clone())
                .or_default()
                .push(advisory);
        }
        identity
            .entry(package.package_path.clone())
            .or_insert_with(|| (package.name.clone(), package.version.clone()));
    }
    let mut heuristic_groups: BTreeMap<String, Vec<&HeuristicFinding>> = BTreeMap::new();
    for finding in heuristics {
        heuristic_groups
            .entry(finding.package_path.clone())
            .or_default()
            .push(finding);
        identity
            .entry(finding.package_path.clone())
            .or_insert_with(|| {
                (
                    finding.package_name.clone(),
                    finding.package_version.clone(),
                )
            });
    }

    let mut scored = Vec::new();
    let mut paths: BTreeSet<String> = BTreeSet::new();
    paths.extend(advisory_groups.keys().cloned());
    paths.extend(heuristic_groups.keys().cloned());

    for path in paths {
        let (name, version) = names
            .get(path.as_str())
            .map(|(name, version)| ((*name).to_owned(), (*version).to_owned()))
            .or_else(|| identity.get(&path).cloned())
            .unwrap_or_else(|| (String::new(), String::new()));

        let mut explanations = Vec::new();
        let mut advisory_points = 0;
        if let Some(advisories) = advisory_groups.get(&path) {
            let mut ordered = advisories.clone();
            ordered.sort_by(|left, right| left.id.cmp(&right.id));
            for advisory in ordered {
                advisory_points += advisory_weight(advisory.severity);
                explanations.push(Explanation {
                    source: advisory.id.clone(),
                    text: advisory_sentence(&name, &version, advisory),
                });
            }
        }
        advisory_points = advisory_points.min(ADVISORY_CAP);

        let mut heuristic_points = 0;
        let mut seen_rules = BTreeSet::new();
        if let Some(findings) = heuristic_groups.get(&path) {
            let mut ordered = findings.clone();
            ordered.sort_by(|left, right| {
                left.rule_id
                    .cmp(right.rule_id)
                    .then(left.hook.cmp(&right.hook))
                    .then(left.evidence.cmp(&right.evidence))
            });
            for finding in ordered {
                if seen_rules.insert(finding.rule_id) {
                    heuristic_points += finding.weight;
                }
                explanations.push(Explanation {
                    source: finding.rule_id.to_owned(),
                    text: finding.explanation.clone(),
                });
            }
        }
        heuristic_points = heuristic_points.min(HEURISTIC_CAP);

        explanations.sort_by(|left, right| {
            left.source
                .cmp(&right.source)
                .then(left.text.cmp(&right.text))
        });
        let total = advisory_points.saturating_add(heuristic_points).min(100);
        scored.push(PackageScore {
            package_path: path,
            name,
            version,
            score: total,
            severity: band(total),
            advisory_points,
            heuristic_points,
            explanations,
        });
    }

    let project_score = scored
        .iter()
        .map(|package| package.score)
        .max()
        .unwrap_or(0);
    ScoreReport {
        version: SCORE_VERSION,
        heuristics_version: ENGINE_VERSION,
        project_score,
        project_severity: band(project_score),
        packages: scored,
    }
}

fn advisory_sentence(name: &str, version: &str, advisory: &crate::advisories::Advisory) -> String {
    let summary = if advisory.summary.is_empty() {
        "keine Kurzbeschreibung"
    } else {
        advisory.summary.as_str()
    };
    format!(
        "Paket {name}@{version} ist von {} betroffen (Schwere {}): {summary}.",
        advisory.id,
        severity_de(advisory.severity)
    )
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
    use crate::advisories::{Advisory, AdvisoryReport, PackageAdvisories, Severity};
    use crate::heuristics::HeuristicFinding;
    use crate::ingest::Package;
    use std::collections::BTreeMap;

    fn package(path: &str, name: &str) -> Package {
        Package {
            path: path.to_owned(),
            name: name.to_owned(),
            version: "1.0.0".to_owned(),
            resolved: None,
            integrity: None,
            dev: false,
            optional: false,
            peer: false,
            is_root: false,
            has_install_script: false,
            license: None,
            dependencies: BTreeMap::new(),
            dev_dependencies: BTreeMap::new(),
            optional_dependencies: BTreeMap::new(),
            peer_dependencies: BTreeMap::new(),
        }
    }

    fn advisory(id: &str, severity: Severity) -> Advisory {
        Advisory {
            id: id.to_owned(),
            aliases: Vec::new(),
            summary: "Fixture".to_owned(),
            severity,
            cvss_score: None,
            url: format!("https://example.invalid/{id}"),
        }
    }

    fn heuristic(path: &str, rule: &'static str, weight: u32, hook: &str) -> HeuristicFinding {
        HeuristicFinding {
            rule_id: rule,
            description: "fixture",
            weight,
            package_name: "pkg".to_owned(),
            package_version: "1.0.0".to_owned(),
            package_path: path.to_owned(),
            hook: hook.to_owned(),
            evidence: hook.to_owned(),
            explanation: format!("Warum {rule} in {hook}."),
        }
    }

    fn report(packages: Vec<PackageAdvisories>) -> AdvisoryReport {
        AdvisoryReport {
            packages,
            cache_hits: 0,
            cache_misses: 0,
            offline: true,
        }
    }

    #[test]
    fn same_input_same_score_and_every_finding_is_explained() {
        let packages = vec![package("node_modules/pkg", "pkg")];
        let advisories = report(vec![PackageAdvisories {
            package_path: "node_modules/pkg".to_owned(),
            name: "pkg".to_owned(),
            version: "1.0.0".to_owned(),
            advisories: vec![advisory("GHSA-1", Severity::High)],
        }]);
        let heuristics = vec![
            heuristic("node_modules/pkg", "LW-H006", 40, "postinstall"),
            heuristic("node_modules/pkg", "LW-H006", 40, "preinstall"),
        ];
        let first = score_parts(&packages, &advisories.packages, &heuristics);
        let second = score_parts(&packages, &advisories.packages, &heuristics);
        assert_eq!(first, second);
        assert_eq!(first.version, SCORE_VERSION);
        assert_eq!(first.project_score, 65);
        assert_eq!(first.project_severity, Severity::High);
        let package = &first.packages[0];
        assert_eq!(package.advisory_points, 25);
        assert_eq!(package.heuristic_points, 40);
        assert_eq!(package.explanations.len(), 3);
        assert!(
            package
                .explanations
                .iter()
                .all(|item| !item.text.is_empty())
        );
        assert!(
            package
                .explanations
                .iter()
                .any(|item| item.source == "GHSA-1")
        );
    }

    #[test]
    fn advisory_points_are_capped() {
        let advisories = report(vec![PackageAdvisories {
            package_path: "node_modules/hot".to_owned(),
            name: "hot".to_owned(),
            version: "1.0.0".to_owned(),
            advisories: vec![
                advisory("GHSA-a", Severity::Critical),
                advisory("GHSA-b", Severity::Critical),
                advisory("GHSA-c", Severity::Critical),
            ],
        }]);
        let scored = score_parts(&[], &advisories.packages, &[]);
        assert_eq!(scored.packages[0].advisory_points, ADVISORY_CAP);
        assert_eq!(scored.packages[0].score, ADVISORY_CAP);
        assert_eq!(scored.packages[0].explanations.len(), 3);
        assert_eq!(scored.project_severity, Severity::High);
    }

    #[test]
    fn empty_input_scores_zero() {
        let scored = score_parts(&[], &[], &[]);
        assert_eq!(scored.project_score, 0);
        assert_eq!(scored.project_severity, Severity::Unknown);
        assert!(scored.packages.is_empty());
    }
}
