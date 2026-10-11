//! End-to-end static scan. Package code is never executed.

use crate::advisories::{AdvisoryCache, HttpTransport, OsvClient, package_queries};
use crate::heuristics::evaluate;
use crate::hooks::detect_hooks;
use crate::ingest::{Lockfile, parse_lockfile};
use crate::policy::{Decision, Evaluation, Policy, decide};
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
    let heuristics = evaluate(&hooks.findings);
    let mut client = OsvClient::new(transport).offline(options.offline);
    if let Some(cache_dir) = &options.cache_dir {
        client = client.with_cache(AdvisoryCache::new(cache_dir));
    }
    let advisories = client.query(&package_queries(&lock))?;
    let score = score(&lock, &advisories, &heuristics);
    let decision = decide(
        &options.policy,
        Evaluation {
            graph: &graph,
            hooks: &hooks.findings,
            heuristics: &heuristics,
            advisories: &advisories,
            baseline: options.baseline.as_ref(),
        },
    );
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
}
