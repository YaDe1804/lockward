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
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::Advisory;

/// How long a cached OSV response stays authoritative (24 hours).
pub const CACHE_TTL_SECS: u64 = 24 * 60 * 60;

/// Reads or renames tried while another writer replaces the same file.
const CACHE_CONTENTION_ATTEMPTS: u32 = 8;

/// Pause between those attempts.
const CACHE_CONTENTION_PAUSE: Duration = Duration::from_millis(20);

/// Cap on the pauses: seven intervals of [`CACHE_CONTENTION_PAUSE`].
const CACHE_CONTENTION_BUDGET: Duration = Duration::from_millis(140);

/// A publish marker older than this is a leftover from a crashed writer.
/// It must not turn later misses into waits.
const CACHE_PUBLISH_MARKER_FRESH: Duration = Duration::from_secs(2);

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
    /// `Ok(None)` means missing, stale, or not valid JSON. Stale entries stay
    /// on disk until a successful refetch overwrites them. A missing
    /// `fetched_at` (legacy files) is stale.
    ///
    /// `Err` is a read that failed for a reason other than `NotFound`, for
    /// example `NotADirectory` when the cache path is a file. A
    /// `PermissionDenied` or a Windows sharing violation is tried again a
    /// few times, because a concurrent rename can hide the file for a moment.
    /// A missing name is tried again only while that rename's marker is still
    /// fresh. A miss with no marker returns at once. Callers treat a remaining
    /// error as a miss. They do not abort the scan.
    pub fn get(&self, name: &str, version: &str) -> Result<Option<Vec<Advisory>>> {
        let path = self.path_for(name, version);
        let text = match read_shared(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
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
    ///
    /// The bytes land in a unique temporary file in the same directory and are
    /// renamed onto the target. The previous file is not deleted first, so a
    /// second writer cannot leave the key missing. A fresh marker is created
    /// before the rename and removed after it, so a reader can tell a replace
    /// in progress from a real miss. A `PermissionDenied` or a Windows sharing
    /// violation on the write or the rename is tried again a few times. Any
    /// other error is returned at once. A remaining error is a warning for
    /// the caller.
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
        let temporary = temporary_path(&path);
        let written = write_shared(&temporary, &path, &bytes);
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        written
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

/// A sibling of `target` with a unique name. `suffix` is `tmp` or `lock`.
fn unique_sibling(target: &Path, suffix: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    let file_name = target.file_name().unwrap_or_default().to_string_lossy();
    target.with_file_name(format!(".{file_name}.{}.{n}.{suffix}", std::process::id()))
}

/// A temp file in the same directory as `target`. The name is unique per
/// attempt so two `put` calls cannot truncate each other's bytes.
fn temporary_path(target: &Path) -> PathBuf {
    unique_sibling(target, "tmp")
}

/// `PermissionDenied`, plus the Windows sharing and lock codes that Rust 1.89
/// leaves as `Uncategorized`. Those raw codes are `EPIPE` and `EDOM` on Unix,
/// so they are recognized only on Windows.
fn is_shared_file_contention(err: &std::io::Error) -> bool {
    if err.kind() == ErrorKind::PermissionDenied {
        return true;
    }
    #[cfg(windows)]
    {
        matches!(err.raw_os_error(), Some(32 | 33))
    }
    #[cfg(not(windows))]
    {
        let _ = err;
        false
    }
}

fn retry_shared<T>(mut op: impl FnMut() -> std::io::Result<T>) -> std::io::Result<T> {
    let started = Instant::now();
    let mut attempt = 1;
    loop {
        match op() {
            Ok(value) => return Ok(value),
            Err(err) if is_shared_file_contention(&err) && contention_room(attempt, started) => {
                thread::sleep(CACHE_CONTENTION_PAUSE);
                attempt += 1;
            }
            Err(err) => return Err(err),
        }
    }
}

/// Room remains in the attempt and time caps.
fn contention_room(attempt: u32, started: Instant) -> bool {
    attempt < CACHE_CONTENTION_ATTEMPTS
        && started.elapsed().saturating_add(CACHE_CONTENTION_PAUSE) <= CACHE_CONTENTION_BUDGET
}

/// `PermissionDenied` and Windows sharing errors are always retried.
/// `NotFound` is retried only while a publish marker shows a replace of this
/// key. Every other kind returns at once, so a cold miss does not wait.
fn should_retry_read(path: &Path, err: &std::io::Error, attempt: u32, started: Instant) -> bool {
    if !contention_room(attempt, started) {
        return false;
    }
    if is_shared_file_contention(err) {
        return true;
    }
    err.kind() == ErrorKind::NotFound && publish_in_flight(path)
}

fn read_shared(path: &Path) -> std::io::Result<String> {
    let started = Instant::now();
    let mut attempt = 1;
    loop {
        match fs::read_to_string(path) {
            Ok(text) => return Ok(text),
            Err(err) if should_retry_read(path, &err, attempt, started) => {
                thread::sleep(CACHE_CONTENTION_PAUSE);
                attempt += 1;
            }
            // The marker can disappear as the rename finishes. One more read,
            // with no pause, separates that from a key that was never written.
            Err(err) if err.kind() == ErrorKind::NotFound => match fs::read_to_string(path) {
                Ok(text) => return Ok(text),
                Err(again) if should_retry_read(path, &again, attempt, started) => {
                    thread::sleep(CACHE_CONTENTION_PAUSE);
                    attempt += 1;
                }
                Err(again) => return Err(again),
            },
            Err(err) => return Err(err),
        }
    }
}

/// True while a fresh `.{name}.*.lock` sibling of `target` exists.
fn publish_in_flight(target: &Path) -> bool {
    let Some(parent) = target.parent() else {
        return false;
    };
    let Some(name) = target.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let prefix = format!(".{name}.");
    let Ok(entries) = fs::read_dir(parent) else {
        return false;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(text) = file_name.to_str() else {
            continue;
        };
        if text.starts_with(&prefix) && text.ends_with(".lock") && marker_is_fresh(&entry.path()) {
            return true;
        }
    }
    false
}

fn marker_is_fresh(path: &Path) -> bool {
    fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()
        .and_then(|modified| modified.elapsed().ok())
        .is_some_and(|age| age <= CACHE_PUBLISH_MARKER_FRESH)
}

fn write_shared(temporary: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    retry_shared(|| fs::write(temporary, bytes)).map_err(|err| Error::io(temporary, err))?;
    let marker = unique_sibling(target, "lock");
    // A marker failure must not fail the write. Readers then treat a missing
    // name as a miss, which is the same outcome as before the marker existed.
    let _ = retry_shared(|| fs::write(&marker, b""));
    let renamed = retry_shared(|| fs::rename(temporary, target));
    let _ = fs::remove_file(&marker);
    renamed.map_err(|err| Error::io(target, err))?;
    Ok(())
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
    fn concurrent_puts_and_gets_never_tear_or_drop_the_entry() {
        let (dir, cache) = temp_cache("concurrent");
        let advisory = crate::advisories::Advisory {
            id: "GHSA-lock-ward-test".to_owned(),
            aliases: vec!["CVE-2020-0001".to_owned()],
            summary: "fixture".to_owned(),
            severity: crate::advisories::Severity::Low,
            cvss_score: Some("3.1".to_owned()),
            url: "https://example.invalid/advisory".to_owned(),
        };
        cache
            .put("left-pad", "1.0.0", std::slice::from_ref(&advisory))
            .unwrap();
        // Enough overlapping renames to meet the Windows sharing window.
        const WRITERS: usize = 8;
        const WRITES_PER_WRITER: usize = 200;
        std::thread::scope(|scope| {
            for _ in 0..WRITERS {
                scope.spawn(|| {
                    for _ in 0..WRITES_PER_WRITER {
                        cache
                            .put("left-pad", "1.0.0", std::slice::from_ref(&advisory))
                            .unwrap();
                        let got = cache.get("left-pad", "1.0.0").expect("cache read");
                        assert_eq!(
                            got.as_deref(),
                            Some(std::slice::from_ref(&advisory)),
                            "cache entry was missing or partial"
                        );
                    }
                });
            }
        });
        let got = cache.get("left-pad", "1.0.0").expect("cache read");
        assert_eq!(
            got.as_deref(),
            Some(std::slice::from_ref(&advisory)),
            "cache entry missing after the writers finished"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn contention_retry_stops_at_the_named_budget() {
        assert_eq!(
            CACHE_CONTENTION_PAUSE.saturating_mul(CACHE_CONTENTION_ATTEMPTS - 1),
            CACHE_CONTENTION_BUDGET
        );
        assert!(is_shared_file_contention(&std::io::Error::from(
            ErrorKind::PermissionDenied
        )));
        for kind in [
            ErrorKind::NotFound,
            ErrorKind::AlreadyExists,
            ErrorKind::NotADirectory,
        ] {
            assert!(
                !is_shared_file_contention(&std::io::Error::from(kind)),
                "{kind:?}"
            );
        }
    }

    #[test]
    fn a_missing_name_is_retried_only_while_a_publish_marker_is_fresh() {
        let (dir, cache) = temp_cache("marker");
        fs::create_dir_all(&dir).unwrap();
        let path = cache.path_for("left-pad", "1.0.0");
        assert!(!publish_in_flight(&path));
        assert!(cache.get("left-pad", "1.0.0").unwrap().is_none());
        let marker = unique_sibling(&path, "lock");
        fs::write(&marker, b"").unwrap();
        assert!(publish_in_flight(&path));
        let other = dir.join("unrelated.json.lock");
        fs::write(&other, b"").unwrap();
        let _ = fs::remove_file(&marker);
        assert!(!publish_in_flight(&path));
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
