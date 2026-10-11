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
pub mod resolve;

pub use advisories::{
    Advisory, AdvisoryReport, OsvClient, PackageAdvisories, PackageQuery, ReqwestTransport,
    Severity, package_queries,
};
pub use error::{Error, Result};
pub use heuristics::{ENGINE_VERSION, HeuristicFinding, RuleInfo, evaluate, rules};
pub use hooks::{HookFinding, HookProvenance, HookReport, NPM_INSTALL_HOOKS, detect_hooks};
pub use ingest::{Lockfile, Package, parse_lockfile, parse_lockfile_str};
pub use resolve::{Cycle, DepKind, Edge, Graph, Node, Unresolved, resolve};

/// Library version, recorded in machine-readable reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
