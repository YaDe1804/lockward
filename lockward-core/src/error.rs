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
