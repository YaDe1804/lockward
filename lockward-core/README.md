# lockward-core

Bibliothek für die statische Supply-Chain-Analyse von Lockward.

Öffentliche APIs bleiben frei von Panics. Fehler laufen über [`Error`](src/error.rs) und `Result`. Mode 1 liest nur Textdateien (Lockfiles, `package.json`) und ruft keinen Paketcode auf.

Module: `ingest`, `resolve`, `hooks`, `advisories`, `heuristics` (`heuristics-v1`), `score` (`score-v1`), `policy`, `scan`, `report` (Markdown, CI-Summary, JSON, CycloneDX 1.6).
