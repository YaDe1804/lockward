# Development

Internal build and quality notes. The public project description is in the README.

## Layout

| Path | Role |
| --- | --- |
| `lockward-core` | Library: ingest, resolve, advisories, hooks, heuristics, score, policy, report |
| `lockward-cli` | Binary `lockward` |
| `.github/workflows` | CI and the signed release |
| `docs/adr` | Architecture decisions |

Data flow: `repo/lockfile → ingest → resolve → (advisories | hooks | heuristics) → score → policy → report/CI gate`.

## Requirements

- Rust stable (edition 2024, `rustfmt`, `clippy`)
- optional: `cargo-nextest`, `cargo-audit`

## Build and scan

```powershell
cargo build --release -p lockward-cli
cargo run -p lockward-cli -- --help
cargo run -p lockward-cli -- scan . --offline
cargo run -p lockward-cli -- scan . --format json --output report.json
cargo run -p lockward-cli -- scan . --format all --output .\out
cargo run -p lockward-cli -- baseline . -o baseline.txt
```

Exit codes: `0` with no finding, `1` warning or review, `2` fail (only in mode `enforce`) or a runtime error. The default mode is `warn`.

## Limits

Untrusted input is bounded: a lockfile is at most 32 MiB and 100,000 packages, a `package.json` is at most 1 MiB (above that, warn and skip), and at most 2048 OSV detail queries per scan. Crossing a limit is an error or a warning, not a silent read-on.

## Quality gate

```powershell
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo nextest run
cargo audit
```
