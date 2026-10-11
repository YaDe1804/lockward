//! Static supply-chain analysis for Lockward.
//!
//! Mode 1 never executes third-party package code. Callers pass already
//! loaded lockfiles and manifests; this crate only parses and classifies them.

#![forbid(unsafe_code)]

pub mod error;

pub use error::{Error, Result};

/// Library version, recorded in machine-readable reports.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
