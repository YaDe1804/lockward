// SPDX-License-Identifier: AGPL-3.0-only

//! End-to-end static scan. Package code is never executed.

use crate::advisories::{AdvisoryCache, HttpTransport, OsvClient, package_queries};
use crate::heuristics::evaluate;
use crate::hooks::{bin_shadows, detect_hooks};
use crate::ingest::{Lockfile, parse_lockfile};
use crate::policy::{Decision, Evaluation, Policy, decide, known_downloader};
use crate::resolve::{Graph, resolve};
use crate::score::{ScoreReport, score};
use crate::{Error, Result};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::heuristics::HeuristicFinding;
use crate::hooks::HookReport;

/// Knobs for one scan. The caller owns the policy and the baseline.
pub struct AnalyzeOptions {
    /// Skip the network and read only the advisory cache.
    pub offline: bool,
    /// Cache directory. `None` disables the cache.
    pub cache_dir: Option<PathBuf>,
    /// Gate policy.
    pub policy: Policy,
    /// Direct-dependency baseline. `None` leaves that rule inactive.
    pub baseline: Option<BTreeSet<String>>,
}

/// Static analysis result.
pub struct Analysis {
    /// Parsed lockfile.
    pub lock: Lockfile,
    /// Path of the lockfile that was read.
    pub lock_path: PathBuf,
    /// Directory that contains the lockfile.
    pub project_root: PathBuf,
    /// Dependency graph.
    pub graph: Graph,
    /// Install hooks.
    pub hooks: HookReport,
    /// Heuristic hits.
    pub heuristics: Vec<HeuristicFinding>,
    /// Advisory matches.
    pub advisories: crate::advisories::AdvisoryReport,
    /// Score.
    pub score: ScoreReport,
    /// Gate decision.
    pub decision: Decision,
}

/// Locate `package-lock.json` from a directory or a direct file path.
pub fn locate_lockfile(path: &Path) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(path.to_owned());
    }
    let candidate = path.join("package-lock.json");
    if candidate.is_file() {
        Ok(candidate)
    } else {
        Err(Error::io(
            &candidate,
            std::io::Error::new(std::io::ErrorKind::NotFound, "package-lock.json not found"),
        ))
    }
}

/// Run ingest through policy.
///
/// `transport` is not called when `options.offline` is set and every package
/// is either cached or counted as a miss.
pub fn analyze<T: HttpTransport>(
    path: &Path,
    transport: &T,
    options: &AnalyzeOptions,
) -> Result<Analysis> {
    let lock_path = locate_lockfile(path)?;
    let project_root = if path.is_dir() {
        path.to_owned()
    } else {
        lock_path.parent().map(Path::to_path_buf).ok_or_else(|| {
            Error::io(
                &lock_path,
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "lockfile has no parent directory",
                ),
            )
        })?
    };
    let lock = parse_lockfile(&lock_path)?;
    let graph = resolve(&lock);
    let hooks = detect_hooks(&lock, &project_root)?;
    let mut heuristics = evaluate(&hooks.findings);
    heuristics.retain(|finding| {
        !(finding.rule_id == "LW-H003" && known_downloader(&finding.package_name))
    });
    let mut client = OsvClient::new(transport).offline(options.offline);
    if let Some(cache_dir) = &options.cache_dir {
        client = client.with_cache(AdvisoryCache::new(cache_dir));
    }
    let advisories = client.query(&package_queries(&lock))?;
    let score = score(&lock, &advisories, &heuristics);
    let shadows = bin_shadows(&lock.packages);
    let mut decision = decide(
        &options.policy,
        Evaluation {
            graph: &graph,
            hooks: &hooks.findings,
            heuristics: &heuristics,
            advisories: &advisories,
            baseline: options.baseline.as_ref(),
            bin_shadows: &shadows,
        },
    );
    decision.notes.extend(advisories.warnings.iter().cloned());
    decision.notes.sort();
    decision.notes.dedup();
    Ok(Analysis {
        lock,
        lock_path,
        project_root,
        graph,
        hooks,
        heuristics,
        advisories,
        score,
        decision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::HookDisposition;
    use crate::policy::{Mode, Policy};
    use crate::{Error, Result};
    use serde_json::Value;

    struct OfflineOnly;

    impl HttpTransport for OfflineOnly {
        fn post_json(&self, url: &str, _body: &Value) -> Result<Value> {
            Err(Error::Advisory {
                url: url.to_owned(),
                message: "offline test".to_owned(),
            })
        }

        fn get_json(&self, url: &str) -> Result<Value> {
            Err(Error::Advisory {
                url: url.to_owned(),
                message: "offline test".to_owned(),
            })
        }
    }

    #[test]
    fn offline_corpus_warns_without_network() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hooks/corpus");
        let analysis = analyze(
            &root,
            &OfflineOnly,
            &AnalyzeOptions {
                offline: true,
                cache_dir: None,
                policy: Policy::default_policy().unwrap(),
                baseline: None,
            },
        )
        .unwrap();
        assert_eq!(analysis.decision.mode, Mode::Warn);
        assert_eq!(analysis.decision.exit_code, 1);
        assert!(!analysis.hooks.findings.is_empty());
    }

    struct EmptyBatch;

    impl HttpTransport for EmptyBatch {
        fn post_json(&self, url: &str, body: &Value) -> Result<Value> {
            assert!(url.ends_with("/v1/querybatch"), "{url}");
            let queries = body["queries"].as_array().map(Vec::len).unwrap_or(0);
            Ok(serde_json::json!({ "results": vec![serde_json::json!({}); queries] }))
        }

        fn get_json(&self, url: &str) -> Result<Value> {
            Err(Error::Advisory {
                url: url.to_owned(),
                message: "unexpected detail fetch".to_owned(),
            })
        }
    }

    #[test]
    fn cache_write_failure_is_a_note_and_the_scan_stays_valid() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/report/mini");
        let cache = std::env::temp_dir().join(format!("lockward-scan-ro-{}", std::process::id()));
        let _ = std::fs::remove_file(&cache);
        std::fs::write(&cache, b"not a directory").unwrap();
        let analysis = analyze(
            &root,
            &EmptyBatch,
            &AnalyzeOptions {
                offline: false,
                cache_dir: Some(cache.clone()),
                policy: Policy::default_policy().unwrap(),
                baseline: None,
            },
        )
        .expect("a cache write must not fail the scan");
        assert!(
            analysis
                .decision
                .notes
                .iter()
                .any(|note| note.contains("advisory cache write failed")),
            "{:?}",
            analysis.decision.notes
        );
        std::fs::remove_file(&cache).unwrap();
    }

    fn scan_lock(lock: &str, manifests: &[(&str, &str)]) -> Analysis {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lockward-bin-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("package-lock.json"), lock).unwrap();
        for (relative, body) in manifests {
            let path = dir.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, body).unwrap();
        }
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
        .expect("scan");
        let _ = std::fs::remove_dir_all(&dir);
        analysis
    }

    #[test]
    fn foreign_package_bin_shadows_node_gyp() {
        let analysis = scan_lock(
            r#"{
              "name": "app",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/native": { "version": "1.0.0" },
                "node_modules/evil": {
                  "name": "evil",
                  "version": "9.9.9",
                  "bin": { "node-gyp": "bin/node-gyp.js" }
                }
              }
            }"#,
            &[(
                "node_modules/native/package.json",
                r#"{"name":"native","version":"1.0.0","scripts":{"install":"node-gyp rebuild"}}"#,
            )],
        );
        let hook = analysis
            .hooks
            .findings
            .iter()
            .find(|finding| finding.package_name == "native")
            .expect("native hook");
        assert_eq!(hook.disposition, HookDisposition::Unverified);
        assert!(
            analysis
                .decision
                .violations
                .iter()
                .any(|hit| hit.rule == "bin_shadow" && hit.package_name == "evil"),
            "{:?}",
            analysis.decision.violations
        );
    }

    #[test]
    fn publisher_node_gyp_bin_is_not_a_finding() {
        let analysis = scan_lock(
            r#"{
              "name": "app",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/node-gyp": {
                  "version": "10.2.0",
                  "bin": { "node-gyp": "bin/node-gyp.js" }
                }
              }
            }"#,
            &[(
                "node_modules/node-gyp/package.json",
                r#"{"name":"node-gyp","version":"10.2.0","scripts":{"install":"node-gyp rebuild"}}"#,
            )],
        );
        let hook = analysis
            .hooks
            .findings
            .iter()
            .find(|finding| finding.package_name == "node-gyp")
            .expect("node-gyp hook");
        assert_eq!(hook.disposition, HookDisposition::TrustedBuild);
        assert!(
            analysis
                .decision
                .violations
                .iter()
                .all(|hit| hit.rule != "bin_shadow")
        );
    }

    #[test]
    fn missing_bin_field_keeps_trusted_build() {
        let analysis = scan_lock(
            r#"{
              "name": "app",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0" },
                "node_modules/native": { "version": "1.0.0" }
              }
            }"#,
            &[(
                "node_modules/native/package.json",
                r#"{"name":"native","version":"1.0.0","scripts":{"install":"node-gyp rebuild"}}"#,
            )],
        );
        let hook = analysis
            .hooks
            .findings
            .iter()
            .find(|finding| finding.package_name == "native")
            .expect("native hook");
        assert_eq!(hook.disposition, HookDisposition::TrustedBuild);
        assert!(
            analysis
                .decision
                .violations
                .iter()
                .all(|hit| hit.rule != "bin_shadow")
        );
    }
}
