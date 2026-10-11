# Lockward

Supply-Chain Firewall und Backdoor-Risk-Scanner (Codename „Rat der Weisen“).

Phase 1 ist eine einzelne statische CLI. Sie liest ein npm-Repository, bewertet Lockfile und Install-Hooks und setzt ein CI-Gate. **Mode 1 führt keinen Paketcode aus.**

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
cargo run -p lockward-cli -- scan .
cargo run -p lockward-cli -- --help
```

`scan` ist im Gerüst von AP1.0 noch ein Platzhalter. Die Analyse folgt in den Modulen danach.

## Qualitätstor

```powershell
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo nextest run
cargo audit
```

## Lizenz

Open-Core ist vorgesehen (CLI und CI-Gate frei, späteres Dashboard separat). Eine konkrete Lizenz ist noch nicht gewählt und wird nicht stillschweigend angenommen.

## Referenzen

Die Dateien `Cursor-Arbeitsanweisung_Phase1_MVP-CLI.md`, `supply_chain_scanner_roadmap_v1.html` und `supply_chain_scanner_roadmap_v2.html` sind Vorgaben und werden von diesem Baum nicht fortgeschrieben.
