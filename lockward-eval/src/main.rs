// SPDX-License-Identifier: AGPL-3.0-only

//! `lockward-eval` command line.
//!
//! Prints the confusion matrix and writes `corpus-report.json`. Exit 0 means
//! the measurement finished. It does not mean the detector passed a threshold.

#![forbid(unsafe_code)]

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("lockward-eval: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut corpus = PathBuf::from("corpus");
    let mut policy = PathBuf::from("corpus/eval-policy.yaml");
    let mut output = PathBuf::from("corpus-report.json");
    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!(
                    "lockward-eval [--corpus DIR] [--policy FILE] [--output FILE]\n\n\
Scannt corpus/malicious und corpus/benign offline über lockward-core.\n\
Schwellwerte werden nicht geprüft."
                );
                return Ok(());
            }
            "--corpus" => corpus = PathBuf::from(next_value(&mut args, "--corpus")?),
            "--policy" => policy = PathBuf::from(next_value(&mut args, "--policy")?),
            "--output" => output = PathBuf::from(next_value(&mut args, "--output")?),
            other => return Err(format!("unbekanntes Argument: {other}")),
        }
    }
    lockward_eval::run(&corpus, &policy, &output).map_err(|err| err.to_string())
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    args.next()
        .ok_or_else(|| format!("{flag} braucht einen Wert"))
}
