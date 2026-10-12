# Entwicklung

Interne Bau- und Qualitätsnotizen. Die öffentliche Projektbeschreibung steht in der README.

## Layout

| Pfad | Rolle |
| --- | --- |
| `lockward-core` | Bibliothek: ingest, resolve, advisories, hooks, heuristics, score, policy, report |
| `lockward-cli` | Binary `lockward` |
| `.github/workflows` | CI und signierter Release |
| `docs/adr` | Architekturentscheidungen |

Datenfluss: `Repo/Lockfile → ingest → resolve → (advisories | hooks | heuristics) → score → policy → report/CI-Gate`.

## Voraussetzungen

- Rust stable (Edition 2024, `rustfmt`, `clippy`)
- optional: `cargo-nextest`, `cargo-audit`

## Bauen und scannen

```powershell
cargo build --release -p lockward-cli
cargo run -p lockward-cli -- --help
cargo run -p lockward-cli -- scan . --offline
cargo run -p lockward-cli -- scan . --format json --output report.json
cargo run -p lockward-cli -- scan . --format all --output .\out
cargo run -p lockward-cli -- baseline . -o baseline.txt
```

Exit-Codes: `0` ohne Verstoß, `1` Warnung oder Review, `2` Fail (nur im Modus `enforce`) oder Laufzeitfehler. Der Default-Modus ist `warn`.

## Grenzen

Untrusted Input ist begrenzt: Lockfile höchstens 32 MiB und 100 000 Pakete, `package.json` höchstens 1 MiB (darüber Warnung und Skip), höchstens 2048 OSV-Detailabfragen pro Scan. Ein Überschreiten ist ein Fehler oder eine Warnung, kein stilles Weiterlesen.

## Qualitätstor

```powershell
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo nextest run
cargo audit
```
