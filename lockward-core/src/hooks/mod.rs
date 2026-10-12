//! Static install-hook detector for npm manifests.
//!
//! Reads `scripts` from `package.json` files that belong to lockfile entries.
//! Script bodies are data. Nothing in this module is executed.

use crate::ingest::Lockfile;
use crate::{Error, Result};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

/// npm lifecycle scripts that run on install. Later ecosystems can add their own list.
pub const NPM_INSTALL_HOOKS: &[&str] = &["preinstall", "install", "postinstall"];

/// Maximum number of characters kept from a hook body.
pub const MAX_HOOK_CHARS: usize = 8_192;

/// Where a hook finding came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HookProvenance {
    /// Body was read from `package.json`.
    Manifest,
    /// The lockfile set `hasInstallScript` and no manifest body was available.
    LockfileFlag,
}

/// One install hook, or a lockfile flag when the body is not on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookFinding {
    /// Package name.
    pub package_name: String,
    /// Locked version.
    pub package_version: String,
    /// Lockfile path. Empty for the root project.
    pub package_path: String,
    /// Script name, or `hasInstallScript` for a body-less lockfile flag.
    pub hook: String,
    /// File location, with the script key when the body was read.
    pub location: String,
    /// Script source, truncated to [`MAX_HOOK_CHARS`]. Empty for a lockfile flag.
    pub raw: String,
    /// How the finding was produced.
    pub provenance: HookProvenance,
}

/// Hook scan output. Invalid manifests are warnings, not scan failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HookReport {
    /// Findings in lockfile order, then `preinstall`, `install`, `postinstall`.
    pub findings: Vec<HookFinding>,
    /// Manifests that could not be parsed, symlink skips, and truncations.
    pub warnings: Vec<String>,
}

/// Detect install hooks for every package in `lock`.
///
/// `project_root` is the directory that contains the lockfile. Manifests are
/// read from `project_root/package.json` and `project_root/<lockfile path>/package.json`.
///
/// A lockfile key that contains `..`, a root, or a Windows prefix is skipped.
/// The resolved manifest path must stay inside the canonical `project_root`,
/// so an intermediate directory symlink cannot point the read outside.
/// A missing in-root manifest stays a non-finding. Symlinks are not followed
/// for the manifest file itself.
pub fn detect_hooks(lock: &Lockfile, project_root: &Path) -> Result<HookReport> {
    if !project_root.is_dir() {
        return Err(Error::io(
            project_root,
            io::Error::new(io::ErrorKind::NotFound, "project root is not a directory"),
        ));
    }
    let canonical_root = project_root
        .canonicalize()
        .map_err(|err| Error::io(project_root, err))?;

    let mut findings = Vec::new();
    let mut warnings = Vec::new();
    for package in &lock.packages {
        let manifest_path = match contained_manifest(&canonical_root, project_root, &package.path) {
            Ok(Some(path)) => path,
            Ok(None) => {
                if package.has_install_script {
                    findings.push(lockfile_flag(package));
                }
                continue;
            }
            Err(warning) => {
                warnings.push(warning);
                if package.has_install_script {
                    findings.push(lockfile_flag(package));
                }
                continue;
            }
        };
        let mut manifest_hooks = false;
        match read_manifest(&manifest_path) {
            Ok(Some(value)) => {
                let found = hooks_from_manifest(
                    &package.name,
                    &package.version,
                    &package.path,
                    &manifest_path,
                    &value,
                    &mut warnings,
                );
                manifest_hooks = !found.is_empty();
                findings.extend(found);
            }
            Ok(None) => {}
            Err(warning) => warnings.push(warning),
        }
        if package.has_install_script && !manifest_hooks {
            findings.push(lockfile_flag(package));
        }
    }

    Ok(HookReport { findings, warnings })
}

fn hooks_from_manifest(
    name: &str,
    version: &str,
    package_path: &str,
    manifest_path: &Path,
    manifest: &Value,
    warnings: &mut Vec<String>,
) -> Vec<HookFinding> {
    let Some(scripts) = manifest.get("scripts").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut found = Vec::new();
    for hook in NPM_INSTALL_HOOKS {
        let Some(value) = scripts.get(*hook) else {
            continue;
        };
        let Some(raw) = value.as_str() else {
            warnings.push(format!(
                "{}: scripts.{hook} is not a string",
                manifest_path.display()
            ));
            continue;
        };
        let (raw, truncated) = cap_raw(raw);
        if truncated {
            warnings.push(format!(
                "{}: scripts.{hook} truncated to {MAX_HOOK_CHARS} characters",
                manifest_path.display()
            ));
        }
        found.push(HookFinding {
            package_name: name.to_owned(),
            package_version: version.to_owned(),
            package_path: package_path.to_owned(),
            hook: (*hook).to_owned(),
            location: format!("{}#scripts.{hook}", manifest_path.display()),
            raw,
            provenance: HookProvenance::Manifest,
        });
    }
    found
}

fn read_manifest(path: &Path) -> std::result::Result<Option<Value>, String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("{}: {err}", path.display())),
    };
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "{}: skipped symlink; hook bodies are only read from regular files",
            path.display()
        ));
    }
    let text = fs::read_to_string(path).map_err(|err| format!("{}: {err}", path.display()))?;
    match serde_json::from_str(&text) {
        Ok(value) => Ok(Some(value)),
        Err(err) => Err(format!("{}: invalid JSON: {err}", path.display())),
    }
}

fn cap_raw(raw: &str) -> (String, bool) {
    let mut chars = raw.chars();
    let mut kept = String::new();
    for _ in 0..MAX_HOOK_CHARS {
        match chars.next() {
            Some(ch) => kept.push(ch),
            None => return (kept, false),
        }
    }
    if chars.next().is_some() {
        kept.push('…');
        (kept, true)
    } else {
        (kept, false)
    }
}

fn json_key(path: &str) -> String {
    serde_json::to_string(path).unwrap_or_else(|_| "\"\"".to_owned())
}

fn lockfile_flag(package: &crate::ingest::Package) -> HookFinding {
    HookFinding {
        package_name: package.name.clone(),
        package_version: package.version.clone(),
        package_path: package.path.clone(),
        hook: "hasInstallScript".to_owned(),
        location: format!(
            "package-lock.json#packages[{}].hasInstallScript",
            json_key(&package.path)
        ),
        raw: String::new(),
        provenance: HookProvenance::LockfileFlag,
    }
}

/// `Ok(None)` is a missing in-root manifest. `Err` is a warning: the key
/// escapes structurally, or the resolved path leaves `canonical_root`.
fn contained_manifest(
    canonical_root: &Path,
    project_root: &Path,
    package_path: &str,
) -> std::result::Result<Option<PathBuf>, String> {
    if let Some(reason) = structural_escape(package_path) {
        return Err(format!("lockfile path `{package_path}` skipped: {reason}"));
    }
    let manifest = manifest_path(project_root, package_path);
    match manifest.canonicalize() {
        Ok(canonical) if canonical.starts_with(canonical_root) => Ok(Some(manifest)),
        Ok(_) => Err(format!(
            "{}: skipped, resolved path leaves the project root",
            manifest.display()
        )),
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if ancestor_leaves_root(&manifest, canonical_root) {
                Err(format!(
                    "{}: skipped, resolved path leaves the project root",
                    manifest.display()
                ))
            } else {
                Ok(None)
            }
        }
        Err(err) => Err(format!("{}: {err}", manifest.display())),
    }
}

fn structural_escape(package_path: &str) -> Option<&'static str> {
    if package_path.is_empty() {
        return None;
    }
    for component in Path::new(package_path).components() {
        match component {
            Component::ParentDir => return Some("parent directory (`..`)"),
            Component::RootDir | Component::Prefix(_) => return Some("absolute path"),
            Component::CurDir | Component::Normal(_) => {}
        }
    }
    None
}

fn ancestor_leaves_root(path: &Path, canonical_root: &Path) -> bool {
    let mut current = path.to_path_buf();
    while current.pop() {
        if !current.exists() {
            continue;
        }
        return match current.canonicalize() {
            Ok(canonical) => !canonical.starts_with(canonical_root),
            Err(_) => true,
        };
    }
    true
}

/// Absolute path helper used by tests and the CLI.
#[must_use]
pub fn manifest_path(project_root: &Path, package_path: &str) -> PathBuf {
    if package_path.is_empty() {
        project_root.join("package.json")
    } else {
        project_root.join(package_path).join("package.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::parse_lockfile;
    use std::collections::BTreeSet;

    fn corpus() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hooks/corpus")
    }

    #[test]
    fn corpus_has_no_false_negatives_and_ignores_benign_scripts() {
        let root = corpus();
        let lock = parse_lockfile(&root.join("package-lock.json")).unwrap();
        let report = detect_hooks(&lock, &root).unwrap();

        let keys: BTreeSet<_> = report
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.package_name.clone(),
                    finding.hook.clone(),
                    finding.raw.clone(),
                    finding.provenance,
                )
            })
            .collect();

        let expected = BTreeSet::from([
            (
                "corpus-app".to_owned(),
                "preinstall".to_owned(),
                "echo root-preinstall".to_owned(),
                HookProvenance::Manifest,
            ),
            (
                "left-pad".to_owned(),
                "postinstall".to_owned(),
                "echo left-pad-postinstall".to_owned(),
                HookProvenance::Manifest,
            ),
            (
                "triple".to_owned(),
                "preinstall".to_owned(),
                "echo pre".to_owned(),
                HookProvenance::Manifest,
            ),
            (
                "triple".to_owned(),
                "install".to_owned(),
                "echo install".to_owned(),
                HookProvenance::Manifest,
            ),
            (
                "triple".to_owned(),
                "postinstall".to_owned(),
                "echo post".to_owned(),
                HookProvenance::Manifest,
            ),
            (
                "@scope/tool".to_owned(),
                "install".to_owned(),
                "echo scoped-install".to_owned(),
                HookProvenance::Manifest,
            ),
            (
                "flagged".to_owned(),
                "hasInstallScript".to_owned(),
                String::new(),
                HookProvenance::LockfileFlag,
            ),
            (
                "broken-manifest".to_owned(),
                "hasInstallScript".to_owned(),
                String::new(),
                HookProvenance::LockfileFlag,
            ),
        ]);
        assert_eq!(keys, expected);
        assert!(report.findings.iter().all(|finding| finding.hook != "test"));
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.package_name != "benign-tool")
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("broken-manifest")
                    && warning.contains("invalid JSON"))
        );
    }

    #[test]
    fn non_string_script_warns_and_does_not_panic() {
        let dir = std::env::temp_dir().join(format!("lockward-hooks-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("package-lock.json"),
            r#"{
              "name": "app",
              "version": "1.0.0",
              "lockfileVersion": 3,
              "packages": {
                "": { "name": "app", "version": "1.0.0" }
              }
            }"#,
        )
        .unwrap();
        fs::write(
            dir.join("package.json"),
            r#"{ "name": "app", "version": "1.0.0", "scripts": { "preinstall": 1, "test": "echo ok" } }"#,
        )
        .unwrap();
        let lock = parse_lockfile(&dir.join("package-lock.json")).unwrap();
        let report = detect_hooks(&lock, &dir).unwrap();
        assert!(report.findings.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("not a string"))
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_project_root_is_an_error() {
        let lock = parse_lockfile(&corpus().join("package-lock.json")).unwrap();
        let err = detect_hooks(&lock, Path::new("J:/lockward-does-not-exist-ap14")).unwrap_err();
        assert!(matches!(err, Error::Io { .. }));
    }

    #[test]
    fn truncates_oversized_hook_body() {
        let long = "a".repeat(MAX_HOOK_CHARS + 10);
        let (kept, truncated) = cap_raw(&long);
        assert!(truncated);
        assert_eq!(kept.chars().count(), MAX_HOOK_CHARS + 1);
        assert!(kept.ends_with('…'));
    }

    fn write_lock(project: &Path, packages_json: &str) {
        fs::create_dir_all(project).unwrap();
        fs::write(
            project.join("package.json"),
            r#"{ "name": "app", "version": "1.0.0" }"#,
        )
        .unwrap();
        fs::write(
            project.join("package-lock.json"),
            format!(
                r#"{{
                  "name": "app",
                  "version": "1.0.0",
                  "lockfileVersion": 3,
                  "packages": {{
                    "": {{ "name": "app", "version": "1.0.0" }},
                    {packages_json}
                  }}
                }}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn parent_dir_key_does_not_read_outside_project_root() {
        let base =
            std::env::temp_dir().join(format!("lockward-hooks-dotdot-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let project = base.join("project");
        let outside = base.join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(
            outside.join("package.json"),
            r#"{ "name": "outside", "version": "1.0.0", "scripts": { "postinstall": "echo SHOULD-NOT-READ" } }"#,
        )
        .unwrap();
        write_lock(
            &project,
            r#""../outside": { "name": "outside", "version": "1.0.0" },
               "node_modules/missing": { "name": "missing", "version": "1.0.0" }"#,
        );
        let lock = parse_lockfile(&project.join("package-lock.json")).unwrap();
        let report = detect_hooks(&lock, &project).unwrap();
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.raw.contains("SHOULD-NOT-READ"))
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("../outside") && warning.contains("skipped"))
        );
        assert!(
            report
                .warnings
                .iter()
                .all(|warning| !warning.contains("missing"))
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn absolute_lockfile_keys_are_skipped() {
        let base = std::env::temp_dir().join(format!("lockward-hooks-abs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let project = base.join("project");
        write_lock(
            &project,
            r#""/etc/passwd": { "name": "unix-abs", "version": "1.0.0" },
               "C:\\Windows\\System32\\drivers\\etc": { "name": "win-abs", "version": "1.0.0" }"#,
        );
        let lock = parse_lockfile(&project.join("package-lock.json")).unwrap();
        let report = detect_hooks(&lock, &project).unwrap();
        assert!(report.findings.is_empty());
        let warnings = report.warnings.join("\n");
        assert!(warnings.contains("/etc/passwd"), "{warnings}");
        assert!(warnings.contains("skipped"), "{warnings}");
        assert!(warnings.contains("absolute path"), "{warnings}");
        assert!(
            report.warnings.len() >= 2,
            "unix and windows keys: {warnings}"
        );
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn intermediate_directory_symlink_does_not_read_outside() {
        let base = std::env::temp_dir().join(format!("lockward-hooks-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let project = base.join("project");
        let outside = base.join("outside");
        fs::create_dir_all(project.join("node_modules")).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(
            outside.join("package.json"),
            r#"{ "name": "evil", "version": "1.0.0", "scripts": { "postinstall": "echo OUTSIDE-HOOK" } }"#,
        )
        .unwrap();
        link_dir(&outside, &project.join("node_modules").join("evil"))
            .expect("create a directory symlink");
        write_lock(
            &project,
            r#""node_modules/evil": { "name": "evil", "version": "1.0.0" }"#,
        );
        let lock = parse_lockfile(&project.join("package-lock.json")).unwrap();
        let report = detect_hooks(&lock, &project).unwrap();
        assert!(
            report
                .findings
                .iter()
                .all(|finding| !finding.raw.contains("OUTSIDE-HOOK"))
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("leaves the project root")),
            "{:?}",
            report.warnings
        );
        fs::remove_dir_all(&base).unwrap();
    }

    fn link_dir(target: &Path, link: &Path) -> io::Result<()> {
        #[cfg(windows)]
        {
            std::os::windows::fs::symlink_dir(target, link)
        }
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, link)
        }
    }
}
