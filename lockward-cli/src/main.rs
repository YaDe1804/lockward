//! Lockward command-line interface.
//!
//! The binary is a thin wrapper. Analysis lives in `lockward-core` and never
//! executes package scripts.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use lockward_core::advisories::ReqwestTransport;
use lockward_core::policy::{Mode, Outcome, Policy, load_policy, parse_baseline, render_baseline};
use lockward_core::report::{ReportKind, render};
use lockward_core::resolve::resolve;
use lockward_core::scan::{Analysis, AnalyzeOptions, analyze, locate_lockfile};
use lockward_core::{VERSION, parse_lockfile};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use tracing_subscriber::EnvFilter;

/// Supply-Chain-Firewall und Backdoor-Risiko-Scanner.
#[derive(Debug, Parser)]
#[command(
    name = "lockward",
    version,
    about = "Supply-Chain-Firewall und Backdoor-Risiko-Scanner",
    long_about = "Lockward prüft npm-Lockfiles auf bekannte Schwachstellen, Install-Hooks und backdoor-ähnliche Muster. Mode 1 ist rein statisch und führt keinen Paketcode aus."
)]
struct Cli {
    /// Erhöht die Log-Ausführlichkeit (`-v` info, `-vv` debug, `-vvv` trace).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scannt ein Repository oder eine `package-lock.json`.
    Scan {
        /// Pfad zu einem Projektverzeichnis oder einer `package-lock.json`.
        path: PathBuf,
        /// Nur den lokalen Advisory-Cache verwenden.
        #[arg(long)]
        offline: bool,
        /// Verzeichnis für den OSV-Cache.
        #[arg(long)]
        cache_dir: Option<PathBuf>,
        /// YAML-Policy. Ohne Angabe gilt die eingebaute Warn-First-Policy.
        #[arg(long)]
        policy: Option<PathBuf>,
        /// Überschreibt `mode` aus der Policy.
        #[arg(long, value_enum)]
        mode: Option<CliMode>,
        /// Baseline-Datei (`name@version` pro Zeile) für neue Abhängigkeiten.
        #[arg(long)]
        baseline: Option<PathBuf>,
        /// Ausgabeformat. `all` schreibt vier Dateien nach `--output`.
        #[arg(long, value_enum, default_value = "text")]
        format: CliFormat,
        /// Datei oder Verzeichnis für die gewählte Ausgabe.
        #[arg(long)]
        output: Option<PathBuf>,
        /// RFC3339-Zeitstempel. Ohne Angabe wird die aktuelle UTC-Zeit verwendet.
        #[arg(long)]
        scanned_at: Option<String>,
    },
    /// Schreibt die direkten Abhängigkeiten als Baseline.
    Baseline {
        /// Pfad zu einem Projektverzeichnis oder einer `package-lock.json`.
        path: PathBuf,
        /// Zieldatei. Ohne Angabe geht die Baseline nach stdout.
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliFormat {
    /// Kurze deutsche Zusammenfassung auf stdout.
    Text,
    /// Markdown für einen PR-Kommentar.
    Markdown,
    /// GitHub Step Summary.
    Summary,
    /// Maschinenlesbares JSON.
    Json,
    /// CycloneDX-1.6-SBOM.
    Cyclonedx,
    /// Schreibt Kommentar, Summary, JSON und SBOM.
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CliMode {
    /// Warn-First: Verstöße werden zu Warnungen, Exit höchstens 1.
    Warn,
    /// Konfigurierte Fail-Regeln beenden den Prozess mit Exit 2.
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
        Some(path) => load_policy(&path).context("Policy konnte nicht geladen werden")?,
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
            let text = fs::read_to_string(&path).with_context(|| {
                format!("Baseline {} konnte nicht gelesen werden", path.display())
            })?;
            Some(parse_baseline(&text))
        }
        None => None,
    };
    let cache_dir = Some(cache_dir.unwrap_or_else(default_cache_dir));
    let transport = ReqwestTransport::new().context("HTTP-Client konnte nicht erzeugt werden")?;
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
            let text =
                render(analysis, kind, scanned_at).context("Report konnte nicht erzeugt werden")?;
            if let Some(path) = output {
                fs::write(path, text).with_context(|| {
                    format!("Report {} konnte nicht geschrieben werden", path.display())
                })?;
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
    let text = render(analysis, kind, scanned_at).context("Report konnte nicht erzeugt werden")?;
    fs::write(path, text)
        .with_context(|| format!("Report {} konnte nicht geschrieben werden", path.display()))
}

fn bail_output() -> Result<()> {
    anyhow::bail!("--format all braucht --output <verzeichnis>");
}

fn utc_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Howard Hinnant's `civil_from_days`, days since Unix epoch.
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    (year, month as u32, day as u32)
}

fn write_baseline(path: &Path, output: Option<&Path>) -> Result<()> {
    let lock_path = locate_lockfile(path).context("package-lock.json nicht gefunden")?;
    let lock = parse_lockfile(&lock_path).context("Lockfile konnte nicht gelesen werden")?;
    let text = render_baseline(&resolve(&lock));
    match output {
        Some(path) => {
            fs::write(path, text).with_context(|| {
                format!(
                    "Baseline {} konnte nicht geschrieben werden",
                    path.display()
                )
            })?;
        }
        None => {
            let mut stdout = io::stdout().lock();
            stdout.write_all(text.as_bytes()).context("stdout")?;
        }
    }
    Ok(())
}

fn print_summary(analysis: &Analysis) -> Result<()> {
    let outcome = match analysis.decision.outcome {
        Outcome::Ok => "OK",
        Outcome::Warn => "Warnung",
        Outcome::Fail => "Block",
    };
    let mode = match analysis.decision.mode {
        Mode::Warn => "warn",
        Mode::Enforce => "enforce",
    };
    println!("Lockward {VERSION}");
    println!("Ziel: {}", analysis.project_root.display());
    println!(
        "Score: {} ({})",
        analysis.score.project_score,
        severity_de(analysis.score.project_severity)
    );
    println!(
        "Gate: {outcome} (Exit {}, Modus {mode})",
        analysis.decision.exit_code
    );
    println!(
        "Hooks: {} · Heuristiken: {} · Advisories: {}",
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
        println!(
            "Advisory-Abdeckung: {} Pakete nicht gegen OSV geprüft (offline, kein/stale Cache).",
            analysis.advisories.cache_misses
        );
    }
    for note in &analysis.decision.notes {
        println!("Hinweis: {note}");
    }
    if analysis.decision.violations.is_empty() {
        println!("Keine Policy-Verstöße.");
    } else {
        println!("Verstöße:");
        for violation in &analysis.decision.violations {
            println!("- [{}] {}", violation.rule, violation.message);
        }
    }
    Ok(())
}

fn severity_de(severity: lockward_core::Severity) -> &'static str {
    match severity {
        lockward_core::Severity::Critical => "kritisch",
        lockward_core::Severity::High => "hoch",
        lockward_core::Severity::Medium => "mittel",
        lockward_core::Severity::Low => "niedrig",
        lockward_core::Severity::Unknown => "unbekannt",
    }
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
