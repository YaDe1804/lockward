//! Lockward command-line interface.
//!
//! The binary is a thin wrapper. Analysis lives in `lockward-core` and never
//! executes package scripts.

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
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
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::Scan { path } => {
            let path_text = path.display().to_string();
            println!("lockward: Platzhalter-Scan von {path_text} (noch keine Analyse)");
            tracing::info!(path = %path_text, "scan scaffold");
            Ok(())
        }
    }
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
