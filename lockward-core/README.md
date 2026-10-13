# lockward-core

Bibliothek für die statische Supply-Chain-Analyse von Lockward.

Öffentliche APIs bleiben frei von Panics. Fehler laufen über [`Error`](src/error.rs) und `Result`. Mode 1 liest nur Textdateien (Lockfiles, `package.json`) und ruft keinen Paketcode auf.

Grenzen für untrusted Input: Lockfiles über 32 MiB und mehr als 100 000 Pakete werden mit `Error::Limit` abgelehnt, bevor sie ausgewertet werden. Eine `package.json` über 1 MiB wird übersprungen und als Warnung gemeldet. Pro Scan werden höchstens 2048 OSV-Vulnerability-Detailabfragen gestellt; darüber bricht der Lauf ab, statt Treffer still zu verwerfen.

Module: `ingest`, `resolve`, `hooks`, `advisories`, `heuristics` (`heuristics-v1.1`), `score` (`score-v1`), `policy`, `scan`, `report` (Markdown, CI-Summary, JSON, CycloneDX 1.6).
