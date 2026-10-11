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
