// SPDX-License-Identifier: AGPL-3.0-only

//! Lockward command-line interface.
//!
//! The binary is a thin wrapper. Analysis lives in `lockward-core` and never
//! executes package scripts.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use lockward_core::advisories::ReqwestTransport;
use lockward_core::policy::{
    Mode, Policy, count_label, load_policy, parse_baseline, render_baseline,
};
use lockward_core::report::{ReportKind, render};
use lockward_core::resolve::resolve;
use lockward_core::scan::{Analysis, AnalyzeOptions, analyze, locate_lockfile};
use lockward_core::{VERSION, parse_lockfile};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use time::OffsetDateTime;
use time::macros::format_description;
use tracing_subscriber::EnvFilter;

/// Static supply-chain and backdoor scanner for npm.
#[derive(Debug, Parser)]
#[command(
    name = "lockward",
    version,
    long_version = concat!(
        env!("CARGO_PKG_VERSION"),
        "\nAGPL-3.0, source: https://github.com/YaDe1804/lockward"
    ),
    about = "Static supply-chain and backdoor scanner for npm",
    long_about = "Lockward checks npm lockfiles for known advisories, install hooks, and backdoor-like patterns. Mode 1 is static and does not execute package code.\n\nAGPL-3.0, source: https://github.com/YaDe1804/lockward"
)]
struct Cli {
    /// Raise log verbosity (`-v` info, `-vv` debug, `-vvv` trace).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a repository or a `package-lock.json`.
    Scan {
        /// Path to a project directory or a `package-lock.json`.
        path: PathBuf,
        /// Use only the local advisory cache.
        #[arg(long)]
        offline: bool,
        /// Directory for the OSV cache.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        /// YAML policy. The built-in warn-first policy is used when this is omitted.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Override `mode` from the policy.
        #[arg(long, value_enum)]
        mode: Option<CliMode>,
        /// Baseline file (`name@version` per line) for new dependencies.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Output format. `all` writes four files into `--output`.
        #[arg(long, value_enum, default_value = "text")]
        format: CliFormat,
        /// File or directory for the chosen output.
        #[arg(long)]
        output: Option<PathBuf>,
        /// RFC3339 timestamp. The current UTC time is used when this is omitted.
        #[arg(long)]
        scanned_at: Option<String>,
    },
    /// Write the direct dependencies as a baseline.
    Baseline {
        /// Path to a project directory or a `package-lock.json`.
        path: PathBuf,
        /// Output file. The baseline goes to stdout when this is omitted.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliFormat {
    /// Short summary on stdout.
    Text,
    /// Markdown for a pull-request comment.
    Markdown,
    /// GitHub step summary.
    Summary,
    /// Machine-readable JSON.
    Json,
    /// CycloneDX 1.6 SBOM.
    Cyclonedx,
    /// Write the comment, summary, JSON, and SBOM.
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliMode {
    /// Warn-first: findings become warnings, and the exit code is at most 1.
    Warn,
    /// Configured fail rules exit 2.
    Enforce,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    match run(cli.command) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(command: Command) -> Result<u8> {
    match command {
        Command::Scan {
            path,
            offline,
            cache_dir,
            policy,
            mode,
            baseline,
            format,
            output,
            scanned_at,
        } => scan(ScanArgs {
            path,
            offline,
            cache_dir,
            policy_path: policy,
            mode,
            baseline_path: baseline,
            format,
            output,
            scanned_at,
        }),
        Command::Baseline { path, output } => {
            write_baseline(&path, output.as_deref())?;
            Ok(0)
        }
    }
}

struct ScanArgs {
    path: PathBuf,
    offline: bool,
    cache_dir: Option<PathBuf>,
    policy_path: Option<PathBuf>,
    mode: Option<CliMode>,
    baseline_path: Option<PathBuf>,
    format: CliFormat,
    output: Option<PathBuf>,
    scanned_at: Option<String>,
}

fn scan(args: ScanArgs) -> Result<u8> {
    let ScanArgs {
        path,
        offline,
        cache_dir,
        policy_path,
        mode,
        baseline_path,
        format,
        output,
        scanned_at,
    } = args;
    let mut policy = match policy_path {
        Some(path) => load_policy(&path).context("could not load the policy")?,
        None => Policy::default_policy().context("Standard-Policy fehlt")?,
    };
    if let Some(mode) = mode {
        policy = policy.with_mode(match mode {
            CliMode::Warn => Mode::Warn,
            CliMode::Enforce => Mode::Enforce,
        });
    }
    let baseline = match baseline_path {
        Some(path) => {
            let text = fs::read_to_string(&path)
                .with_context(|| format!("could not read baseline {}", path.display()))?;
            Some(parse_baseline(&text))
        }
        None => None,
    };
    let cache_dir = Some(cache_dir.unwrap_or_else(default_cache_dir));
    let transport = ReqwestTransport::new().context("could not build the HTTP client")?;
    let analysis = analyze(
        &path,
        &transport,
        &AnalyzeOptions {
            offline,
            cache_dir,
            policy,
            baseline,
        },
    )
    .context("Scan fehlgeschlagen")?;
    let scanned_at = scanned_at.unwrap_or_else(utc_now);
    emit_report(&analysis, format, output.as_deref(), &scanned_at)?;
    Ok(analysis.decision.exit_code)
}

fn emit_report(
    analysis: &Analysis,
    format: CliFormat,
    output: Option<&Path>,
    scanned_at: &str,
) -> Result<()> {
    match format {
        CliFormat::Text => print_summary(analysis)?,
        CliFormat::All => {
            let Some(dir) = output else {
                return bail_output();
            };
            fs::create_dir_all(dir)
                .with_context(|| format!("Ausgabeverzeichnis {} fehlt", dir.display()))?;
            write_report(
                analysis,
                ReportKind::Markdown,
                &dir.join("comment.md"),
                scanned_at,
            )?;
            write_report(
                analysis,
                ReportKind::Summary,
                &dir.join("summary.md"),
                scanned_at,
            )?;
            write_report(
                analysis,
                ReportKind::Json,
                &dir.join("report.json"),
                scanned_at,
            )?;
            write_report(
                analysis,
                ReportKind::CycloneDx,
                &dir.join("bom.cdx.json"),
                scanned_at,
            )?;
            print_summary(analysis)?;
        }
        other => {
            let kind = match other {
                CliFormat::Markdown => ReportKind::Markdown,
                CliFormat::Summary => ReportKind::Summary,
                CliFormat::Json => ReportKind::Json,
                CliFormat::Cyclonedx => ReportKind::CycloneDx,
                CliFormat::Text | CliFormat::All => unreachable!(),
            };
            let text = render(analysis, kind, scanned_at).context("could not render the report")?;
            if let Some(path) = output {
                fs::write(path, text)
                    .with_context(|| format!("could not write report {}", path.display()))?;
            } else {
                print!("{text}");
            }
        }
    }
    Ok(())
}

fn write_report(
    analysis: &Analysis,
    kind: ReportKind,
    path: &Path,
    scanned_at: &str,
) -> Result<()> {
    let text = render(analysis, kind, scanned_at).context("could not render the report")?;
    fs::write(path, text).with_context(|| format!("could not write report {}", path.display()))
}

fn bail_output() -> Result<()> {
    anyhow::bail!("--format all braucht --output <verzeichnis>");
}

fn utc_now() -> String {
    let format = format_description!("[year]-[month]-[day]T[hour]:[minute]:[second]Z");
    OffsetDateTime::now_utc()
        .format(&format)
        .expect("RFC3339 UTC timestamp")
}

fn write_baseline(path: &Path, output: Option<&Path>) -> Result<()> {
    let lock_path = locate_lockfile(path).context("package-lock.json was not found")?;
    let lock = parse_lockfile(&lock_path).context("could not read the lockfile")?;
    let text = render_baseline(&resolve(&lock));
    match output {
        Some(path) => {
            fs::write(path, text)
                .with_context(|| format!("could not write baseline {}", path.display()))?;
        }
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(text.as_bytes()).context("stdout")?;
        }
    }
    Ok(())
}

fn print_summary(analysis: &Analysis) -> Result<()> {
    let outcome = analysis.decision.outcome.label();
    let mode = analysis.decision.mode.label();
    println!("Lockward {VERSION}");
    println!("Target: {}", analysis.project_root.display());
    println!(
        "Score: {} ({})",
        analysis.score.project_score,
        analysis.score.project_severity.label()
    );
    println!(
        "Gate: {outcome} (exit {}, mode {mode})",
        analysis.decision.exit_code
    );
    println!(
        "Install hooks: {} · heuristics: {} · advisories: {}",
        analysis.hooks.findings.len(),
        analysis.heuristics.len(),
        analysis
            .advisories
            .packages
            .iter()
            .map(|package| package.advisories.len())
            .sum::<usize>()
    );
    if analysis.advisories.offline && analysis.advisories.cache_misses > 0 {
        let misses = analysis.advisories.cache_misses;
        println!(
            "Advisory coverage: {} (offline, no cache entry or a stale cache).",
            count_label(
                misses,
                "package was not checked against OSV",
                "packages were not checked against OSV",
            )
        );
    }
    for note in &analysis.decision.notes {
        println!("Note: {note}");
    }
    if analysis.decision.violations.is_empty() {
        println!("No policy findings.");
    } else {
        println!("Findings:");
        for violation in &analysis.decision.violations {
            println!("- [{}] {}", violation.rule, violation.message);
        }
    }
    Ok(())
}

fn default_cache_dir() -> PathBuf {
    if let Some(local) = std::env::var_os("LOCALAPPDATA") {
        return PathBuf::from(local).join("lockward").join("osv-cache");
    }
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return PathBuf::from(xdg).join("lockward").join("osv-cache");
    }
    PathBuf::from(".lockward").join("osv-cache")
}

fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init()
        .ok();
}

#[cfg(test)]
mod tests {
    use super::utc_now;

    #[test]
    fn utc_now_is_rfc3339_utc() {
        let text = utc_now();
        assert_eq!(text.len(), 20, "{text}");
        assert!(text.ends_with('Z'), "{text}");
        assert!(!text.contains('.'), "{text}");
        assert_eq!(&text[10..11], "T");
    }
}
