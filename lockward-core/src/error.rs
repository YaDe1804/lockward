//! Error type for the analysis library.

use std::path::Path;
use thiserror::Error;

/// Recoverable analysis failure.
///
/// Library paths return this type instead of panicking.
#[derive(Debug, Error)]
pub enum Error {
    /// Filesystem read or write failed.
    #[error("I/O error while accessing {path}: {source}")]
    Io {
        /// Path that was being accessed.
        path: String,
        /// Underlying operating-system error.
        #[source]
        source: std::io::Error,
    },

    /// A file was not valid JSON.
    #[error("invalid JSON in {path}: {source}")]
    Json {
        /// File the JSON was read from.
        path: String,
        /// Serde parse error.
        #[source]
        source: serde_json::Error,
    },

    /// `lockfileVersion` was absent.
    #[error("lockfile {path} is missing lockfileVersion")]
    MissingLockfileVersion {
        /// Lockfile path or label.
        path: String,
    },

    /// Only npm lockfile versions 2 and 3 are accepted in phase 1.
    #[error("unsupported lockfileVersion {version} in {path}; expected 2 or 3")]
    UnsupportedLockfile {
        /// Lockfile path or label.
        path: String,
        /// Value found in the file.
        version: u64,
    },

    /// The v2/v3 `packages` map was absent.
    #[error("lockfile {path} is missing the packages map")]
    MissingPackages {
        /// Lockfile path or label.
        path: String,
    },

    /// A package entry could not be named.
    #[error("package `{package_path}` in {path} has no name")]
    MissingPackageName {
        /// Lockfile path or label.
        path: String,
        /// Key inside `packages`.
        package_path: String,
    },

    /// The advisory source rejected a request or returned an unusable body.
    #[error("advisory request to {url} failed: {message}")]
    Advisory {
        /// Request URL.
        url: String,
        /// Transport or protocol detail. Does not include response bodies.
        message: String,
    },

    /// A policy file could not be parsed or used.
    #[error("invalid policy {path}: {message}")]
    Policy {
        /// Policy path or label.
        path: String,
        /// Parser or validation detail.
        message: String,
    },

    /// An untrusted input exceeded a fixed bound. The input was not processed further.
    #[error("input limit exceeded: {message}")]
    Limit {
        /// Which bound was crossed.
        message: String,
    },
}

/// Library result alias.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Build an [`Error::Io`] from a path and the source error.
    pub fn io(path: impl AsRef<Path>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.as_ref().display().to_string(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn io_error_includes_path() {
        let err = Error::io("package-lock.json", io::Error::other("disk"));
        let text = err.to_string();
        assert!(text.contains("package-lock.json"));
        assert!(text.contains("disk"));
    }
}
