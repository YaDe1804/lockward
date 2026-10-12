// SPDX-License-Identifier: AGPL-3.0-only

//! Content-addressed file cache for OSV package queries.
//!
//! Entries older than [`CACHE_TTL_SECS`] are stale. A stale hit is treated as
//! a miss so an online scan refetches it. Files written before `fetched_at`
//! existed still parse, and they are stale as well.

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::Advisory;

/// How long a cached OSV response stays authoritative (24 hours).
pub const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

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
    /// Unix seconds when the entry was written. `0` means the field was absent.
    #[serde(default)]
    fetched_at: u64,
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

    /// Return a fresh cached advisory list.
    ///
    /// `Ok(None)` means missing, unreadable, or stale. Stale entries stay on
    /// disk until a successful refetch overwrites them. A missing `fetched_at`
    /// (legacy files) is stale.
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
                if is_fresh(entry.fetched_at, now_unix()) {
                    Ok(Some(entry.advisories))
                } else {
                    Ok(None)
                }
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
            fetched_at: now_unix(),
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

    /// Write an entry with an explicit timestamp. Tests use this to plant stale files.
    #[cfg(test)]
    pub(crate) fn put_at(
        &self,
        name: &str,
        version: &str,
        advisories: &[Advisory],
        fetched_at: u64,
    ) -> Result<()> {
        fs::create_dir_all(&self.root).map_err(|err| Error::io(&self.root, err))?;
        let path = self.path_for(name, version);
        let entry = CacheEntry {
            ecosystem: "npm".to_owned(),
            name: name.to_owned(),
            version: version.to_owned(),
            advisories: advisories.to_vec(),
            fetched_at,
        };
        let bytes = serde_json::to_vec_pretty(&entry).map_err(|source| Error::Json {
            path: path.display().to_string(),
            source,
        })?;
        fs::write(&path, bytes).map_err(|err| Error::io(&path, err))?;
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

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// `fetched_at == 0` is the serde default for legacy files and is never fresh.
fn is_fresh(fetched_at: u64, now: u64) -> bool {
    fetched_at > 0 && fetched_at <= now && now.saturating_sub(fetched_at) < CACHE_TTL_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cache(label: &str) -> (PathBuf, FileCache) {
        let dir =
            std::env::temp_dir().join(format!("lockward-cache-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cache = FileCache::new(&dir);
        (dir, cache)
    }

    #[test]
    fn legacy_file_without_fetched_at_loads_and_is_stale() {
        let (dir, cache) = temp_cache("legacy");
        let path = cache.path_for("left-pad", "1.0.0");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            &path,
            r#"{"ecosystem":"npm","name":"left-pad","version":"1.0.0","advisories":[]}"#,
        )
        .unwrap();
        let parsed: CacheEntry = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(parsed.fetched_at, 0);
        assert!(cache.get("left-pad", "1.0.0").unwrap().is_none());
        assert!(path.exists(), "a stale legacy file is not deleted");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_fetched_at_is_stale_and_a_fresh_put_hits() {
        let (dir, cache) = temp_cache("ttl");
        cache.put_at("left-pad", "1.0.0", &[], 1).unwrap();
        assert!(cache.get("left-pad", "1.0.0").unwrap().is_none());
        cache.put("left-pad", "1.0.0", &[]).unwrap();
        assert!(cache.get("left-pad", "1.0.0").unwrap().is_some());
        let _ = fs::remove_dir_all(&dir);
    }
}
