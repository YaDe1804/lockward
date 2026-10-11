# Nightly Log — Phase 1

Lauf auf Branch `night/phase1`. Fortschritt nur hier und in `docs/MORNING_REPORT.md`. Die Roadmap-HTML-Dateien bleiben unangetastet.

## 2026-10-12 00:27 +02:00 — AP1.0 Projekt-Setup & CI

- Ergebnis: fertig (DoD erfüllt).
- Workspace `lockward-core` + `lockward-cli` (Binary `lockward`), Edition 2024, `unsafe` verboten.
- CLI: `--help`, `--version`, `scan <pfad>` als Platzhalter.
- CI: fmt, clippy `-D warnings`, nextest, cargo-audit. Release: drei Targets, SHA256SUMS, keyless cosign.
- Gate: `cargo fmt --all`, `cargo clippy --all-targets -- -D warnings`, `cargo nextest run --locked`, `cargo audit` grün. `lockward scan .` druckt den Platzhalter.
- ADR: [001](adr/001-workspace-und-sprache.md).
- Offen: `Lockward_Spezifikation_v1.docx` lag nicht im Workspace. Maßgeblich war die Arbeitsanweisung plus Roadmap v2.
- Nächster Schritt: AP1.1 ingest.

## 2026-10-12 00:40 +02:00 — AP1.1 ingest

- Ergebnis: fertig (DoD erfüllt).
- Parser für `package-lock.json` v2 und v3 über die `packages`-Map. Legacy-Baum wird ignoriert.
- Neutrale Felder: Name, Version, Resolved-URL, dev/optional/peer, Integrity, Lizenz, Dependency-Ranges, `hasInstallScript`.
- Fehlerfälle als `Result`: kaputtes JSON, fehlende Version, fehlende `packages`, lockfileVersion ≠ 2/3, fehlender Name.
- Fixtures: `v2-basic`, `v3-nested`, `v3-alias`, `broken`, `v1`. 13 Tests grün.
- Gate: fmt, clippy `-D warnings`, nextest, audit grün.
- ADR: [002](adr/002-npm-lockfile-modell.md).
- Nächster Schritt: AP1.2 resolve, danach AP1.4 hooks.

## 2026-10-12 00:50 +02:00 — AP1.2 resolve

- Ergebnis: fertig (DoD erfüllt).
- Graph über Node-`node_modules`-Walk. Direkt vs. erreichbar vs. unerreichbar getrennt.
- Zyklen werden aufgezeichnet und brechen den Aufbau nicht ab. Fehlende Ziele landen in `unresolved`.
- Fixtures: `nested` (verschachtelte Kopie, Peer, Optional, Orphan), `cycle`.
- Gate: fmt, clippy `-D warnings`, nextest (17), audit grün.
- ADR: [003](adr/003-dependency-graph.md).
- Nächster Schritt: AP1.4 hooks (parallel vorgesehen, nach AP1.2 committet).
