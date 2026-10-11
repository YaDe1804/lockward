# lockward-core

Bibliothek für die statische Supply-Chain-Analyse von Lockward.

Öffentliche APIs bleiben frei von Panics. Fehler laufen über [`Error`](src/error.rs) und `Result`. Mode 1 liest nur Textdateien (Lockfiles, `package.json`) und ruft keinen Paketcode auf.

Die Module `ingest`, `resolve`, `advisories`, `hooks`, `heuristics`, `score`, `policy` und `report` kommen mit den Arbeitspaketen AP1.1–AP1.8 dazu.
