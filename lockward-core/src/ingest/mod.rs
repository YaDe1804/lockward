// SPDX-License-Identifier: AGPL-3.0-only

//! Parser for npm `package-lock.json` versions 2 and 3.
//!
//! The legacy `dependencies` tree from lockfile v1/v2 is ignored. The
//! `packages` map is the source of truth, matching npm's own resolver output.

use crate::{Error, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

/// A parsed npm lockfile in Lockward's neutral package list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lockfile {
    /// Project name from the top-level lockfile field, when present.
    pub name: Option<String>,
    /// Project version from the top-level lockfile field, when present.
    pub version: Option<String>,
    /// npm `lockfileVersion` (2 or 3).
    pub lockfile_version: u32,
    /// Packages sorted by lockfile path.
    pub packages: Vec<Package>,
}

impl Lockfile {
    /// The root package (`packages[""]`), when the lockfile contains one.
    #[must_use]
    pub fn root(&self) -> Option<&Package> {
        self.packages.iter().find(|package| package.is_root)
    }
}

/// One installed package, including the root project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    /// Key in the lockfile `packages` map. Empty for the root.
    pub path: String,
    /// Package name. Scoped names keep the `@scope/` prefix.
    pub name: String,
    /// Exact locked version. Empty when the lockfile omitted it.
    pub version: String,
    /// Registry or tarball URL from `resolved`.
    pub resolved: Option<String>,
    /// Subresource-integrity string, usually `sha512-…`.
    pub integrity: Option<String>,
    /// npm's `dev` flag: the package is only reachable through dev edges.
    pub dev: bool,
    /// npm's `optional` flag.
    pub optional: bool,
    /// npm's `peer` flag.
    pub peer: bool,
    /// True for the `""` root entry.
    pub is_root: bool,
    /// Lockfile declared `hasInstallScript`.
    pub has_install_script: bool,
    /// SPDX identifier or the license `type` field, when present.
    pub license: Option<String>,
    /// Production dependency ranges (`name → range`).
    pub dependencies: BTreeMap<String, String>,
    /// Development dependency ranges declared on this package.
    pub dev_dependencies: BTreeMap<String, String>,
    /// Optional dependency ranges.
    pub optional_dependencies: BTreeMap<String, String>,
    /// Peer dependency ranges.
    pub peer_dependencies: BTreeMap<String, String>,
}

/// Largest lockfile that will be read (32 MiB).
pub const MAX_LOCKFILE_BYTES: u64 = 32 * 1024 * 1024;

/// Largest `packages` map that will be normalized.
pub const MAX_PACKAGES: usize = 100_000;

/// Read and parse a `package-lock.json` from disk.
///
/// Files larger than [`MAX_LOCKFILE_BYTES`] are rejected before they are read.
pub fn parse_lockfile(path: &Path) -> Result<Lockfile> {
    let metadata = fs::metadata(path).map_err(|source| Error::io(path, source))?;
    if metadata.len() > MAX_LOCKFILE_BYTES {
        return Err(Error::Limit {
            message: format!(
                "lockfile {} is {} bytes; the limit is {MAX_LOCKFILE_BYTES} bytes",
                path.display(),
                metadata.len()
            ),
        });
    }
    let text = fs::read_to_string(path).map_err(|source| Error::io(path, source))?;
    parse_lockfile_str(&text, &path.display().to_string())
}

/// Parse lockfile JSON from memory.
///
/// `origin` is used in error messages (a path or a fixture name).
/// Strings longer than [`MAX_LOCKFILE_BYTES`] are rejected before parsing.
pub fn parse_lockfile_str(text: &str, origin: &str) -> Result<Lockfile> {
    if text.len() as u64 > MAX_LOCKFILE_BYTES {
        return Err(Error::Limit {
            message: format!(
                "lockfile {origin} is {} bytes; the limit is {MAX_LOCKFILE_BYTES} bytes",
                text.len()
            ),
        });
    }
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let raw: RawLockfile = serde_json::from_str(text).map_err(|source| Error::Json {
        path: origin.to_owned(),
        source,
    })?;
    normalize(raw, origin)
}

fn normalize(raw: RawLockfile, origin: &str) -> Result<Lockfile> {
    let Some(version) = raw.lockfile_version else {
        return Err(Error::MissingLockfileVersion {
            path: origin.to_owned(),
        });
    };
    if version != 2 && version != 3 {
        return Err(Error::UnsupportedLockfile {
            path: origin.to_owned(),
            version,
        });
    }
    let Some(packages) = raw.packages else {
        return Err(Error::MissingPackages {
            path: origin.to_owned(),
        });
    };
    if packages.len() > MAX_PACKAGES {
        return Err(Error::Limit {
            message: format!(
                "lockfile {origin} has {} packages; the limit is {MAX_PACKAGES}",
                packages.len()
            ),
        });
    }

    let lockfile_version = u32::try_from(version).map_err(|_| Error::UnsupportedLockfile {
        path: origin.to_owned(),
        version,
    })?;
    let mut normalized = Vec::with_capacity(packages.len());
    for (path, package) in packages {
        normalized.push(normalize_package(
            &path,
            package,
            origin,
            raw.name.as_deref(),
            raw.version.as_deref(),
        )?);
    }

    Ok(Lockfile {
        name: raw.name,
        version: raw.version,
        lockfile_version,
        packages: normalized,
    })
}

fn normalize_package(
    path: &str,
    package: RawPackage,
    origin: &str,
    top_name: Option<&str>,
    top_version: Option<&str>,
) -> Result<Package> {
    let is_root = path.is_empty();
    let name = if is_root {
        package
            .name
            .or_else(|| top_name.map(str::to_owned))
            .ok_or_else(|| Error::MissingPackageName {
                path: origin.to_owned(),
                package_path: path.to_owned(),
            })?
    } else {
        package
            .name
            .clone()
            .or_else(|| derive_package_name(path))
            .ok_or_else(|| Error::MissingPackageName {
                path: origin.to_owned(),
                package_path: path.to_owned(),
            })?
    };
    let version = package
        .version
        .or_else(|| is_root.then(|| top_version.unwrap_or_default().to_owned()))
        .unwrap_or_default();

    Ok(Package {
        path: path.to_owned(),
        name,
        version,
        resolved: package.resolved,
        integrity: package.integrity,
        dev: package.dev,
        optional: package.optional,
        peer: package.peer,
        is_root,
        has_install_script: package.has_install_script,
        license: package.license.and_then(RawLicense::into_spdx),
        dependencies: package.dependencies.unwrap_or_default(),
        dev_dependencies: package.dev_dependencies.unwrap_or_default(),
        optional_dependencies: package.optional_dependencies.unwrap_or_default(),
        peer_dependencies: package.peer_dependencies.unwrap_or_default(),
    })
}

/// Derive `@scope/name` or `name` from a lockfile package path.
fn derive_package_name(path: &str) -> Option<String> {
    let rest = path
        .rsplit_once("node_modules/")
        .map(|(_, rest)| rest)
        .unwrap_or(path);
    if let Some(scoped) = rest.strip_prefix('@') {
        let mut parts = scoped.split('/');
        let scope = parts.next().unwrap_or("");
        let name = parts.next().unwrap_or("");
        if scope.is_empty() || name.is_empty() {
            return None;
        }
        return Some(format!("@{scope}/{name}"));
    }
    rest.split('/')
        .next()
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
}

#[derive(Debug, Deserialize)]
struct RawLockfile {
    name: Option<String>,
    version: Option<String>,
    #[serde(rename = "lockfileVersion")]
    lockfile_version: Option<u64>,
    packages: Option<BTreeMap<String, RawPackage>>,
}

#[derive(Debug, Deserialize)]
struct RawPackage {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    integrity: Option<String>,
    #[serde(default)]
    dev: bool,
    #[serde(default)]
    optional: bool,
    #[serde(default)]
    peer: bool,
    #[serde(default, rename = "hasInstallScript")]
    has_install_script: bool,
    license: Option<RawLicense>,
    dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "devDependencies")]
    dev_dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "optionalDependencies")]
    optional_dependencies: Option<BTreeMap<String, String>>,
    #[serde(rename = "peerDependencies")]
    peer_dependencies: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawLicense {
    Spdx(String),
    Object {
        #[serde(rename = "type")]
        kind: Option<String>,
    },
}

impl RawLicense {
    fn into_spdx(self) -> Option<String> {
        match self {
            Self::Spdx(value) => Some(value),
            Self::Object { kind } => kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/ingest")
            .join(name);
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
    }

    #[test]
    fn parses_lockfile_v2_and_ignores_legacy_tree() {
        let lock = parse_lockfile_str(&fixture("v2-basic.json"), "v2-basic.json").unwrap();
        assert_eq!(lock.lockfile_version, 2);
        assert_eq!(lock.name.as_deref(), Some("demo-app"));
        assert_eq!(lock.packages.len(), 4);

        let root = lock.root().unwrap();
        assert_eq!(root.name, "demo-app");
        assert_eq!(root.version, "1.2.3");
        assert_eq!(
            root.dependencies.get("lodash").map(String::as_str),
            Some("^4.17.21")
        );
        assert!(root.dev_dependencies.contains_key("typescript"));
        assert_eq!(root.license.as_deref(), Some("MIT"));

        let scoped = lock
            .packages
            .iter()
            .find(|package| package.path == "node_modules/@scope/util")
            .unwrap();
        assert_eq!(scoped.name, "@scope/util");
        assert_eq!(scoped.license.as_deref(), Some("Apache-2.0"));
        assert_eq!(
            scoped.resolved.as_deref(),
            Some("https://registry.npmjs.org/@scope/util/-/util-0.1.0.tgz")
        );
        assert_eq!(scoped.integrity.as_deref(), Some("sha512-abc"));

        let typescript = lock
            .packages
            .iter()
            .find(|package| package.name == "typescript")
            .unwrap();
        assert!(typescript.dev);
        assert!(!typescript.is_root);
    }

    #[test]
    fn parses_lockfile_v3_nested_optional_and_peer() {
        let lock = parse_lockfile_str(&fixture("v3-nested.json"), "v3-nested.json").unwrap();
        assert_eq!(lock.lockfile_version, 3);

        let nested = lock
            .packages
            .iter()
            .find(|package| package.path == "node_modules/foo/node_modules/bar")
            .unwrap();
        assert_eq!(nested.name, "bar");
        assert_eq!(nested.version, "2.0.0");
        assert!(nested.has_install_script);

        let top_bar = lock
            .packages
            .iter()
            .find(|package| package.path == "node_modules/bar")
            .unwrap();
        assert_eq!(top_bar.version, "1.5.0");

        let fsevents = lock
            .packages
            .iter()
            .find(|package| package.name == "fsevents")
            .unwrap();
        assert!(fsevents.optional);

        let react = lock
            .packages
            .iter()
            .find(|package| package.name == "react")
            .unwrap();
        assert!(react.peer);

        let foo = lock
            .packages
            .iter()
            .find(|package| package.path == "node_modules/foo")
            .unwrap();
        assert_eq!(
            foo.peer_dependencies.get("react").map(String::as_str),
            Some("^18.0.0")
        );
        assert_eq!(
            foo.dependencies.get("bar").map(String::as_str),
            Some("^2.0.0")
        );
    }

    #[test]
    fn prefers_explicit_alias_name() {
        let lock = parse_lockfile_str(&fixture("v3-alias.json"), "v3-alias.json").unwrap();
        let alias = lock
            .packages
            .iter()
            .find(|package| package.path == "node_modules/my-lodash")
            .unwrap();
        assert_eq!(alias.name, "lodash");
        assert_eq!(alias.version, "4.17.21");
    }

    #[test]
    fn package_order_follows_path() {
        let lock = parse_lockfile_str(&fixture("v3-nested.json"), "v3-nested.json").unwrap();
        let paths: Vec<_> = lock
            .packages
            .iter()
            .map(|package| package.path.as_str())
            .collect();
        let mut sorted = paths.clone();
        sorted.sort_unstable();
        assert_eq!(paths, sorted);
    }

    #[test]
    fn broken_json_is_an_error() {
        let err = parse_lockfile_str(&fixture("broken.json"), "broken.json").unwrap_err();
        assert!(matches!(err, Error::Json { .. }), "{err}");
    }

    #[test]
    fn rejects_lockfile_v1() {
        let err = parse_lockfile_str(&fixture("v1.json"), "v1.json").unwrap_err();
        assert!(
            matches!(err, Error::UnsupportedLockfile { version: 1, .. }),
            "{err}"
        );
    }

    #[test]
    fn rejects_missing_version_and_packages() {
        let missing_version =
            parse_lockfile_str(r#"{"name":"x","packages":{}}"#, "missing-version").unwrap_err();
        assert!(matches!(
            missing_version,
            Error::MissingLockfileVersion { .. }
        ));

        let missing_packages =
            parse_lockfile_str(r#"{"lockfileVersion":3}"#, "missing-packages").unwrap_err();
        assert!(matches!(missing_packages, Error::MissingPackages { .. }));
    }

    #[test]
    fn strips_bom_and_reads_from_disk() {
        let dir = std::env::temp_dir().join(format!("lockward-ingest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("package-lock.json");
        let body = format!("\u{feff}{}", fixture("v2-basic.json"));
        fs::write(&path, body).unwrap();
        let lock = parse_lockfile(&path).unwrap();
        assert_eq!(lock.lockfile_version, 2);
        let missing = parse_lockfile(&dir.join("nope.json")).unwrap_err();
        assert!(matches!(missing, Error::Io { .. }));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn oversized_lockfile_is_rejected_before_parse() {
        let dir = std::env::temp_dir().join(format!("lockward-ingest-big-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("package-lock.json");
        let file = fs::File::create(&path).unwrap();
        file.set_len(MAX_LOCKFILE_BYTES + 1).unwrap();
        drop(file);
        let err = parse_lockfile(&path).unwrap_err();
        assert!(matches!(err, Error::Limit { .. }), "{err}");
        assert!(err.to_string().contains("limit"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn too_many_packages_is_an_error() {
        let mut body = String::from(
            r#"{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"app","version":"1.0.0"}"#,
        );
        for index in 0..MAX_PACKAGES {
            body.push_str(",\"node_modules/p");
            body.push_str(&index.to_string());
            body.push_str("\":{\"version\":\"1.0.0\"}");
        }
        body.push_str("}}");
        let err = parse_lockfile_str(&body, "too-many.json").unwrap_err();
        assert!(matches!(err, Error::Limit { .. }), "{err}");
        assert!(err.to_string().contains("packages"));
    }

    #[test]
    fn derive_name_handles_nested_scopes() {
        assert_eq!(
            derive_package_name("node_modules/foo/node_modules/@scope/bar").as_deref(),
            Some("@scope/bar")
        );
        assert_eq!(
            derive_package_name("node_modules/lodash").as_deref(),
            Some("lodash")
        );
        assert_eq!(derive_package_name("node_modules/@only").as_deref(), None);
    }
}
