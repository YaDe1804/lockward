//! Content-addressed file cache for OSV package queries.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

use super::Advisory;

/// JSON files keyed by ecosystem, name, and version.
#[derive(Debug, Clone)]
pub struct FileCache {
    root: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct CacheEntry {
    ecosystem: String,
    name: String,
    version: String,
    advisories: Vec<Advisory>,
}

impl FileCache {
    /// Store cache files under `root`. The directory is created on write.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Directory passed to [`FileCache::new`].
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return a cached advisory list, or `None` when the entry is missing or unreadable.
    pub fn get(&self, name: &str, version: &str) -> Result<Option<Vec<Advisory>>> {
        let path = self.path_for(name, version);
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(Error::io(&path, err)),
        };
        match serde_json::from_str::<CacheEntry>(&text) {
            Ok(entry)
                if entry.name == name && entry.version == version && entry.ecosystem == "npm" =>
            {
                Ok(Some(entry.advisories))
            }
            _ => {
                let _ = fs::remove_file(&path);
                Ok(None)
            }
        }
    }

    /// Write an advisory list for one package version.
    pub fn put(&self, name: &str, version: &str, advisories: &[Advisory]) -> Result<()> {
        fs::create_dir_all(&self.root).map_err(|err| Error::io(&self.root, err))?;
        let path = self.path_for(name, version);
        let entry = CacheEntry {
            ecosystem: "npm".to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
            advisories: advisories.to_vec(),
        };
        let bytes = serde_json::to_vec_pretty(&entry).map_err(|source| Error::Json {
            path: path.display().to_string(),
            source,
        })?;
        let temporary = path.with_extension("json.tmp");
        fs::write(&temporary, bytes).map_err(|err| Error::io(&temporary, err))?;
        if path.exists() {
            fs::remove_file(&path).map_err(|err| Error::io(&path, err))?;
        }
        fs::rename(&temporary, &path).map_err(|err| Error::io(&path, err))?;
        Ok(())
    }

    fn path_for(&self, name: &str, version: &str) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(b"npm\0");
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(version.as_bytes());
        self.root
            .join(format!("{}.json", hex::encode(hasher.finalize())))
    }
}
