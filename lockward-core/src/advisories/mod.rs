// SPDX-License-Identifier: AGPL-3.0-only

//! OSV advisory client with a file cache and a mockable HTTP transport.
//!
//! Mode 1 only fetches advisory JSON. Package tarballs and exploit code are
//! never downloaded.

mod cache;
mod cvss;

use crate::ingest::Lockfile;
use crate::{Error, Result};
use cache::FileCache;
use cvss::{cvss31_base_score, format_score, severity_from_score};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

pub use cache::FileCache as AdvisoryCache;

/// Default OSV API origin.
pub const OSV_BASE_URL: &str = "https://api.osv.dev";

const BATCH_LIMIT: usize = 128;

/// Most OSV vulnerability documents fetched in one scan.
///
/// The batch query may name more ids than this. The scan then stops with
/// [`Error::Limit`](crate::Error::Limit) instead of downloading them.
pub const MAX_VULN_DETAIL_GETS: usize = 2_048;

/// Coarse severity used by the policy gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No usable score.
    Unknown,
    /// CVSS below 4.0, or the word `low`.
    Low,
    /// CVSS 4.0–6.9, or `medium` / `moderate`.
    Medium,
    /// CVSS 7.0–8.9, or the word `high`.
    High,
    /// CVSS 9.0–10.0, or the word `critical`.
    Critical,
}

/// One advisory matched to a package version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    /// OSV id, usually a `GHSA-` or `CVE-` identifier.
    pub id: String,
    /// Alias ids, sorted.
    pub aliases: Vec<String>,
    /// Short summary. Empty when OSV omitted it.
    pub summary: String,
    /// Gate severity.
    pub severity: Severity,
    /// CVSS base score rendered with one decimal, when one could be read.
    pub cvss_score: Option<String>,
    /// Human URL for the advisory.
    pub url: String,
}

/// A package version to ask OSV about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageQuery {
    /// Lockfile path, kept so matches can be joined back onto the graph.
    pub package_path: String,
    /// npm package name.
    pub name: String,
    /// Locked version.
    pub version: String,
}

/// Advisories for one queried package. The list is sorted by advisory id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PackageAdvisories {
    /// Lockfile path.
    pub package_path: String,
    /// Package name.
    pub name: String,
    /// Locked version.
    pub version: String,
    /// Matching advisories.
    pub advisories: Vec<Advisory>,
}

/// Outcome of one advisory pass, including cache accounting for offline runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AdvisoryReport {
    /// One entry per input query, same order.
    pub packages: Vec<PackageAdvisories>,
    /// Queries served from the local cache.
    pub cache_hits: usize,
    /// Queries skipped because offline mode had no cache entry.
    pub cache_misses: usize,
    /// True when the network was not used.
    pub offline: bool,
}

/// HTTP surface used by the OSV client. Tests supply a fake.
pub trait HttpTransport {
    /// `POST` a JSON body and parse a JSON object or array.
    fn post_json(&self, url: &str, body: &Value) -> Result<Value>;
    /// `GET` a JSON document.
    fn get_json(&self, url: &str) -> Result<Value>;
}

impl<T: HttpTransport + ?Sized> HttpTransport for &T {
    fn post_json(&self, url: &str, body: &Value) -> Result<Value> {
        (*self).post_json(url, body)
    }

    fn get_json(&self, url: &str) -> Result<Value> {
        (*self).get_json(url)
    }
}

/// Blocking reqwest transport. Rustls, no native OpenSSL.
#[derive(Debug, Clone)]
pub struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    /// Build a client with a 20 second timeout and a Lockward user agent.
    pub fn new() -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .user_agent(format!("lockward/{}", crate::VERSION))
            .timeout(Duration::from_secs(20))
            .build()
            .map_err(|err| Error::Advisory {
                url: OSV_BASE_URL.to_owned(),
                message: err.to_string(),
            })?;
        Ok(Self { client })
    }
}

impl HttpTransport for ReqwestTransport {
    fn post_json(&self, url: &str, body: &Value) -> Result<Value> {
        let response = self
            .client
            .post(url)
            .json(body)
            .send()
            .map_err(|err| Error::Advisory {
                url: url.to_owned(),
                message: err.to_string(),
            })?;
        read_json(url, response)
    }

    fn get_json(&self, url: &str) -> Result<Value> {
        let response = self.client.get(url).send().map_err(|err| Error::Advisory {
            url: url.to_owned(),
            message: err.to_string(),
        })?;
        read_json(url, response)
    }
}

fn read_json(url: &str, response: reqwest::blocking::Response) -> Result<Value> {
    let status = response.status();
    if !status.is_success() {
        return Err(Error::Advisory {
            url: url.to_owned(),
            message: format!("HTTP {status}"),
        });
    }
    response.json().map_err(|err| Error::Advisory {
        url: url.to_owned(),
        message: err.to_string(),
    })
}

/// OSV batch client.
#[derive(Debug, Clone)]
pub struct OsvClient<T> {
    transport: T,
    cache: Option<FileCache>,
    offline: bool,
    base_url: String,
}

impl<T> OsvClient<T> {
    /// Online client without a cache.
    #[must_use]
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            cache: None,
            offline: false,
            base_url: OSV_BASE_URL.to_owned(),
        }
    }

    /// Attach a file cache. Cached versions are not fetched again.
    #[must_use]
    pub fn with_cache(mut self, cache: FileCache) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Never call the network. Missing cache entries count as misses and match nothing.
    #[must_use]
    pub fn offline(mut self, offline: bool) -> Self {
        self.offline = offline;
        self
    }

    /// Override the API origin. Intended for tests and private mirrors.
    #[must_use]
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into().trim_end_matches('/').to_owned();
        self
    }
}

impl<T: HttpTransport> OsvClient<T> {
    /// Match advisories for `packages`.
    ///
    /// Root projects are not queried; use [`package_queries`] to build the list.
    /// Identical name/version pairs share one OSV request.
    pub fn query(&self, packages: &[PackageQuery]) -> Result<AdvisoryReport> {
        let mut resolved: Vec<Option<Vec<Advisory>>> = vec![None; packages.len()];
        let mut pending = Vec::new();
        let mut cache_hits = 0;

        for (index, package) in packages.iter().enumerate() {
            // `FileCache::get` returns `None` for a missing or stale entry
            // (`fetched_at` absent or older than the TTL), so those packages
            // stay pending and are queried again when the client is online.
            if let Some(cache) = &self.cache
                && let Some(advisories) = cache.get(&package.name, &package.version)?
            {
                tracing::debug!(
                    name = %package.name,
                    version = %package.version,
                    "advisory cache hit"
                );
                resolved[index] = Some(advisories);
                cache_hits += 1;
                continue;
            }
            pending.push(index);
        }

        let mut cache_misses = 0;
        if !pending.is_empty() {
            if self.offline {
                cache_misses = pending.len();
                for index in pending {
                    resolved[index] = Some(Vec::new());
                }
            } else {
                let fetched = self.fetch_pending(packages, &pending)?;
                for (index, advisories) in fetched {
                    if let Some(cache) = &self.cache {
                        let package = &packages[index];
                        cache.put(&package.name, &package.version, &advisories)?;
                    }
                    resolved[index] = Some(advisories);
                }
            }
        }

        let packages = packages
            .iter()
            .enumerate()
            .map(|(index, package)| PackageAdvisories {
                package_path: package.package_path.clone(),
                name: package.name.clone(),
                version: package.version.clone(),
                advisories: resolved[index].clone().unwrap_or_default(),
            })
            .collect();

        Ok(AdvisoryReport {
            packages,
            cache_hits,
            cache_misses,
            offline: self.offline,
        })
    }

    fn fetch_pending(
        &self,
        packages: &[PackageQuery],
        pending: &[usize],
    ) -> Result<Vec<(usize, Vec<Advisory>)>> {
        let mut order = Vec::new();
        let mut groups: BTreeMap<(String, String), Vec<usize>> = BTreeMap::new();
        for &index in pending {
            let package = &packages[index];
            let key = (package.name.clone(), package.version.clone());
            if !groups.contains_key(&key) {
                order.push(key.clone());
            }
            groups.entry(key).or_default().push(index);
        }

        let mut ids_for: BTreeMap<(String, String), BTreeSet<String>> = BTreeMap::new();
        for chunk in order.chunks(BATCH_LIMIT) {
            let body = json!({
                "queries": chunk.iter().map(|(name, version)| {
                    json!({
                        "package": { "name": name, "ecosystem": "npm" },
                        "version": version,
                    })
                }).collect::<Vec<_>>()
            });
            let url = format!("{}/v1/querybatch", self.base_url);
            let response = self.transport.post_json(&url, &body)?;
            let results = response
                .get("results")
                .and_then(Value::as_array)
                .ok_or_else(|| Error::Advisory {
                    url: url.clone(),
                    message: "batch response has no results array".to_owned(),
                })?;
            if results.len() != chunk.len() {
                return Err(Error::Advisory {
                    url,
                    message: format!(
                        "batch returned {} results for {} queries",
                        results.len(),
                        chunk.len()
                    ),
                });
            }
            for (query, result) in chunk.iter().zip(results) {
                let mut ids = BTreeSet::new();
                if let Some(vulns) = result.get("vulns").and_then(Value::as_array) {
                    for vuln in vulns {
                        if let Some(id) = vuln.get("id").and_then(Value::as_str) {
                            ids.insert(id.to_owned());
                        }
                    }
                }
                ids_for.insert(query.clone(), ids);
            }
        }

        let mut unique_ids = BTreeSet::new();
        for ids in ids_for.values() {
            unique_ids.extend(ids.iter().cloned());
        }
        if unique_ids.len() > MAX_VULN_DETAIL_GETS {
            return Err(Error::Limit {
                message: format!(
                    "OSV returned {} vulnerability ids; the detail-request limit is {MAX_VULN_DETAIL_GETS}",
                    unique_ids.len()
                ),
            });
        }
        let mut by_id = BTreeMap::new();
        for id in unique_ids {
            let url = format!("{}/v1/vulns/{}", self.base_url, encode_id(&id));
            let document = self.transport.get_json(&url)?;
            if let Some(advisory) = advisory_from_osv(&document) {
                by_id.insert(id, advisory);
            }
        }

        let mut out = Vec::new();
        for (key, indexes) in groups {
            let advisories = ids_for
                .get(&key)
                .into_iter()
                .flatten()
                .filter_map(|id| by_id.get(id).cloned())
                .collect::<Vec<_>>();
            for index in indexes {
                out.push((index, advisories.clone()));
            }
        }
        Ok(out)
    }
}

/// Build OSV queries for every locked dependency. The root project is skipped.
#[must_use]
pub fn package_queries(lock: &Lockfile) -> Vec<PackageQuery> {
    lock.packages
        .iter()
        .filter(|package| {
            !package.is_root && !package.name.is_empty() && !package.version.is_empty()
        })
        .map(|package| PackageQuery {
            package_path: package.path.clone(),
            name: package.name.clone(),
            version: package.version.clone(),
        })
        .collect()
}

pub(crate) fn advisory_from_osv(document: &Value) -> Option<Advisory> {
    let id = document.get("id")?.as_str()?.to_owned();
    let summary = document
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned();
    let mut aliases = document
        .get("aliases")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    aliases.sort();
    aliases.dedup();
    let (severity, cvss_score) = classify(document);
    let url = advisory_url(document, &id);
    Some(Advisory {
        id,
        aliases,
        summary,
        severity,
        cvss_score,
        url,
    })
}

fn classify(document: &Value) -> (Severity, Option<String>) {
    let scored = best_score(document);
    if let Some(word) = document
        .pointer("/database_specific/severity")
        .and_then(Value::as_str)
        .and_then(parse_severity_word)
    {
        return (word, scored.map(|(_, score)| score));
    }
    if let Some((severity, score)) = scored {
        return (severity, Some(score));
    }
    (Severity::Unknown, None)
}

fn best_score(document: &Value) -> Option<(Severity, String)> {
    let entries = document.get("severity")?.as_array()?;
    let mut best: Option<(u8, Severity, String)> = None;
    for entry in entries {
        let kind = entry.get("type").and_then(Value::as_str).unwrap_or("");
        let raw = entry.get("score").and_then(Value::as_str).unwrap_or("");
        let Some((severity, score)) = parse_score_value(raw) else {
            continue;
        };
        let rank = if kind.contains("CVSS_V3") {
            3
        } else if kind.contains("CVSS_V4") {
            2
        } else if kind.contains("CVSS_V2") {
            1
        } else {
            0
        };
        let replace = best.as_ref().is_none_or(|(current, _, _)| rank >= *current);
        if replace {
            best = Some((rank, severity, score));
        }
    }
    best.map(|(_, severity, score)| (severity, score))
}

fn parse_score_value(raw: &str) -> Option<(Severity, String)> {
    let raw = raw.trim();
    if let Ok(value) = raw.parse::<f64>() {
        return Some((severity_from_score(value), format_score(value)));
    }
    if raw.starts_with("CVSS:3.") {
        let value = cvss31_base_score(raw)?;
        return Some((severity_from_score(value), format_score(value)));
    }
    None
}

fn parse_severity_word(word: &str) -> Option<Severity> {
    match word.trim().to_ascii_lowercase().as_str() {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "moderate" | "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        _ => None,
    }
}

fn advisory_url(document: &Value, id: &str) -> String {
    if let Some(references) = document.get("references").and_then(Value::as_array) {
        let preferred = references
            .iter()
            .find(|reference| reference.get("type").and_then(Value::as_str) == Some("ADVISORY"));
        if let Some(url) = preferred
            .or_else(|| references.first())
            .and_then(|reference| reference.get("url"))
            .and_then(Value::as_str)
        {
            return url.to_owned();
        }
    }
    format!("https://osv.dev/vulnerability/{id}")
}

fn encode_id(id: &str) -> String {
    let mut encoded = String::new();
    for byte in id.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::parse_lockfile_str;
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Scripted {
        posts: AtomicUsize,
        gets: AtomicUsize,
    }

    impl HttpTransport for Scripted {
        fn post_json(&self, url: &str, body: &Value) -> Result<Value> {
            assert!(url.ends_with("/v1/querybatch"), "{url}");
            let queries = body["queries"].as_array().unwrap();
            self.posts.fetch_add(1, Ordering::SeqCst);
            let results = queries
                .iter()
                .map(|query| {
                    let name = query["package"]["name"].as_str().unwrap();
                    let version = query["version"].as_str().unwrap();
                    if name == "lodash" && version == "4.17.20" {
                        json!({ "vulns": [{ "id": "GHSA-35jh-r3h4-6jhm" }] })
                    } else if name == "critical-fixture" && version == "1.0.0" {
                        json!({ "vulns": [{ "id": "GHSA-crit-test-0001" }] })
                    } else {
                        json!({})
                    }
                })
                .collect::<Vec<_>>();
            Ok(json!({ "results": results }))
        }

        fn get_json(&self, url: &str) -> Result<Value> {
            self.gets.fetch_add(1, Ordering::SeqCst);
            if url.ends_with("GHSA-35jh-r3h4-6jhm") {
                Ok(json!({
                    "id": "GHSA-35jh-r3h4-6jhm",
                    "summary": "Command Injection in lodash",
                    "aliases": ["CVE-2021-23337"],
                    "severity": [{
                        "type": "CVSS_V3",
                        "score": "7.2"
                    }],
                    "database_specific": { "severity": "HIGH" },
                    "references": [{
                        "type": "ADVISORY",
                        "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm"
                    }]
                }))
            } else if url.ends_with("GHSA-crit-test-0001") {
                Ok(json!({
                    "id": "GHSA-crit-test-0001",
                    "summary": "Fixture critical vector",
                    "severity": [{
                        "type": "CVSS_V3",
                        "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                    }]
                }))
            } else {
                Err(Error::Advisory {
                    url: url.to_owned(),
                    message: "unexpected vuln id".to_owned(),
                })
            }
        }
    }

    struct Failing;

    impl HttpTransport for Failing {
        fn post_json(&self, url: &str, _body: &Value) -> Result<Value> {
            Err(Error::Advisory {
                url: url.to_owned(),
                message: "network down".to_owned(),
            })
        }

        fn get_json(&self, url: &str) -> Result<Value> {
            Err(Error::Advisory {
                url: url.to_owned(),
                message: "network down".to_owned(),
            })
        }
    }

    fn sample() -> Vec<PackageQuery> {
        vec![
            PackageQuery {
                package_path: "node_modules/lodash".to_owned(),
                name: "lodash".to_owned(),
                version: "4.17.20".to_owned(),
            },
            PackageQuery {
                package_path: "node_modules/safe-pkg".to_owned(),
                name: "safe-pkg".to_owned(),
                version: "1.0.0".to_owned(),
            },
            PackageQuery {
                package_path: "node_modules/critical-fixture".to_owned(),
                name: "critical-fixture".to_owned(),
                version: "1.0.0".to_owned(),
            },
        ]
    }

    #[test]
    fn maps_known_high_and_critical_advisories() {
        let transport = Scripted {
            posts: AtomicUsize::new(0),
            gets: AtomicUsize::new(0),
        };
        let report = OsvClient::new(&transport).query(&sample()).unwrap();
        let lodash = &report.packages[0];
        assert_eq!(lodash.advisories.len(), 1);
        assert_eq!(lodash.advisories[0].id, "GHSA-35jh-r3h4-6jhm");
        assert_eq!(
            lodash.advisories[0].aliases,
            vec!["CVE-2021-23337".to_owned()]
        );
        assert_eq!(lodash.advisories[0].severity, Severity::High);
        assert_eq!(lodash.advisories[0].cvss_score.as_deref(), Some("7.2"));
        assert!(report.packages[1].advisories.is_empty());
        assert_eq!(
            report.packages[2].advisories[0].severity,
            Severity::Critical
        );
        assert_eq!(
            report.packages[2].advisories[0].cvss_score.as_deref(),
            Some("9.8")
        );
        assert_eq!(transport.posts.load(Ordering::SeqCst), 1);
        assert_eq!(transport.gets.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn cache_serves_offline_rerun() {
        let dir = std::env::temp_dir().join(format!("lockward-osv-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let transport = Scripted {
            posts: AtomicUsize::new(0),
            gets: AtomicUsize::new(0),
        };
        let cache = FileCache::new(&dir);
        let online = OsvClient::new(&transport).with_cache(cache.clone());
        let first = online.query(&sample()).unwrap();
        assert_eq!(first.cache_hits, 0);
        let second = OsvClient::new(&transport)
            .with_cache(cache)
            .offline(true)
            .query(&sample())
            .unwrap();
        assert!(second.offline);
        assert_eq!(second.cache_hits, 3);
        assert_eq!(second.cache_misses, 0);
        assert_eq!(second.packages, first.packages);
        assert_eq!(transport.posts.load(Ordering::SeqCst), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn stale_cache_entry_is_refetched_online() {
        let dir = std::env::temp_dir().join(format!("lockward-osv-stale-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let cache = FileCache::new(&dir);
        cache.put_at("lodash", "4.17.20", &[], 1).unwrap();
        let transport = Scripted {
            posts: AtomicUsize::new(0),
            gets: AtomicUsize::new(0),
        };
        let report = OsvClient::new(&transport)
            .with_cache(cache)
            .query(std::slice::from_ref(&sample()[0]))
            .unwrap();
        assert_eq!(report.cache_hits, 0);
        assert_eq!(transport.posts.load(Ordering::SeqCst), 1);
        assert_eq!(report.packages[0].advisories[0].id, "GHSA-35jh-r3h4-6jhm");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn vuln_detail_gets_stop_at_the_limit() {
        struct Flood {
            gets: AtomicUsize,
        }
        impl HttpTransport for Flood {
            fn post_json(&self, url: &str, _body: &Value) -> Result<Value> {
                assert!(url.ends_with("/v1/querybatch"));
                let vulns = (0..=MAX_VULN_DETAIL_GETS)
                    .map(|index| json!({ "id": format!("GHSA-{index}") }))
                    .collect::<Vec<_>>();
                Ok(json!({ "results": [{ "vulns": vulns }] }))
            }

            fn get_json(&self, _url: &str) -> Result<Value> {
                self.gets.fetch_add(1, Ordering::SeqCst);
                Ok(json!({ "id": "unused" }))
            }
        }
        let transport = Flood {
            gets: AtomicUsize::new(0),
        };
        let err = OsvClient::new(&transport)
            .query(std::slice::from_ref(&sample()[0]))
            .unwrap_err();
        assert!(matches!(err, Error::Limit { .. }), "{err}");
        assert_eq!(transport.gets.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn offline_miss_is_empty_and_online_failure_is_an_error() {
        let dir = std::env::temp_dir().join(format!("lockward-osv-miss-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let report = OsvClient::new(Failing)
            .with_cache(FileCache::new(&dir))
            .offline(true)
            .query(&sample())
            .unwrap();
        assert_eq!(report.cache_misses, 3);
        assert!(
            report
                .packages
                .iter()
                .all(|package| package.advisories.is_empty())
        );
        let err = OsvClient::new(Failing).query(&sample()).unwrap_err();
        assert!(matches!(err, Error::Advisory { .. }));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn package_queries_skip_the_root() {
        let text = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/ingest/v3-nested.json"),
        )
        .unwrap();
        let lock = parse_lockfile_str(&text, "v3-nested.json").unwrap();
        let queries = package_queries(&lock);
        assert!(queries.iter().all(|query| query.name != "v3-app"));
        assert_eq!(queries.len(), 5);
    }

    #[test]
    fn reqwest_transport_builds() {
        ReqwestTransport::new().unwrap();
    }
}
