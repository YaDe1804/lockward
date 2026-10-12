// SPDX-License-Identifier: AGPL-3.0-only

//! Static supply-chain analysis for Lockward.
//!
//! Mode 1 never executes third-party package code. Callers pass already
//! loaded lockfiles and manifests; this crate only parses and classifies them.

#![forbid(unsafe_code)]

pub mod advisories;
pub mod error;
pub mod heuristics;
pub mod hooks;
pub mod ingest;
pub mod policy;
pub mod report;
pub mod resolve;
pub mod scan;
pub mod score;

pub use advisories::{
    Advisory, AdvisoryReport, OsvClient, PackageAdvisories, PackageQuery, ReqwestTransport,
    Severity, package_queries,
};
pub use error::{Error, Result};
pub use heuristics::{ENGINE_VERSION, HeuristicFinding, RuleInfo, evaluate, rules};
pub use hooks::{HookFinding, HookProvenance, HookReport, NPM_INSTALL_HOOKS, detect_hooks};
pub use ingest::{Lockfile, Package, parse_lockfile, parse_lockfile_str};
pub use policy::{Action, Decision, Mode, Outcome, Policy, decide, load_policy, parse_baseline};
pub use resolve::{Cycle, DepKind, Edge, Graph, Node, Unresolved, resolve};
pub use score::{
    ADVISORY_CAP, HEURISTIC_CAP, PackageScore, SCORE_VERSION, ScoreReport, advisory_weight, band,
    score,
};

/// Library version, recorded in machine-readable reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
