# lockward-core

Bibliothek für die statische Supply-Chain-Analyse von Lockward.

Öffentliche APIs bleiben frei von Panics. Fehler laufen über [`Error`](src/error.rs) und `Result`. Mode 1 liest nur Textdateien (Lockfiles, `package.json`) und ruft keinen Paketcode auf.

Module: `ingest` (npm-Lockfile v2/v3), `resolve` (Graph), `hooks` (Install-Skripte, statisch), `advisories` (OSV plus Datei-Cache). Heuristik, Score, Policy und Report folgen.
