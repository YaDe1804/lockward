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

## 2026-10-12 01:05 +02:00 — AP1.4 hooks

- Ergebnis: fertig (DoD erfüllt).
- Liest `preinstall`/`install`/`postinstall` aus `package.json` der Lockfile-Pfade. Keine Ausführung, keine Symlinks.
- `hasInstallScript` ohne Körper bleibt ein Fund (keine False Negatives auf dem Korpus).
- Benigne `test`/`build`-Skripte erzeugen keinen Fund. Kaputtes JSON wird zur Warnung.
- Korpus: Root, left-pad, triple (alle drei Hooks), `@scope/tool`, flagged, broken-manifest, benign-tool.
- Gate: fmt, clippy `-D warnings`, nextest (21), audit grün.
- ADR: [004](adr/004-hooks-statisch.md). `prepare` bewusst nicht enthalten.
- Nächster Schritt: AP1.3 advisories.

## 2026-10-12 01:25 +02:00 — AP1.3 advisories

- Ergebnis: fertig (DoD erfüllt).
- OSV-Batch plus Vuln-Detail, mockbarer `HttpTransport`, Datei-Cache, Offline-Lauf.
- Fixture mappt `lodash@4.17.20` auf `GHSA-35jh-r3h4-6jhm` / `CVE-2021-23337` mit Schwere high, plus einen Critical-CVSS-Vektor (9.8). Kein Live-Netz im Test.
- Gate: fmt, clippy `-D warnings`, nextest, audit (208 Crates) grün.
- ADR: [005](adr/005-osv-cache.md).
- Nächster Schritt: AP1.5 heuristics.

## 2026-10-12 01:40 +02:00 — AP1.5 heuristics

- Ergebnis: fertig (DoD erfüllt).
- Engine `heuristics-v1` mit LW-H001 bis LW-H006. Pro Regel ein Test plus inertes Beispiel. Benigne Hooks (`node-gyp`, `echo`, `tsconfig`) bleiben ohne Fund.
- Erklärung ist ein deutscher Satz mit Paket, Hook und Beleg.
- Gate: fmt, clippy `-D warnings`, nextest (39), audit grün.
- ADR: [006](adr/006-heuristik-v1.md).
- Nächster Schritt: AP1.6 score.
