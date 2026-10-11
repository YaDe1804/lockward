# lockward-core

Bibliothek für die statische Supply-Chain-Analyse von Lockward.

Öffentliche APIs bleiben frei von Panics. Fehler laufen über [`Error`](src/error.rs) und `Result`. Mode 1 liest nur Textdateien (Lockfiles, `package.json`) und ruft keinen Paketcode auf.

Modul `ingest` parst npm-`package-lock.json` v2 und v3. Modul `resolve` baut den Dependency-Graphen. Modul `hooks` liest Install-Skripte statisch. Die übrigen Module folgen in AP1.3 und AP1.5–AP1.8.
