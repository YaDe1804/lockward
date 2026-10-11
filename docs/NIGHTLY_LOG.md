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

## 2026-10-12 01:55 +02:00 — AP1.6 score

- Ergebnis: fertig (DoD erfüllt).
- `score-v1`: Advisory-Punkte gedeckelt bei 70, Heuristik pro Regel einmal gedeckelt bei 60, Paket max 100, Projekt = Maximum.
- Jeder Advisory- und Heuristik-Fund hat einen deutschen Satz. Zweiter Lauf ist identisch.
- Gate: fmt, clippy `-D warnings`, Score-Tests grün. Voller nextest folgt mit dem Commit-Gate.
- ADR: [007](adr/007-score-formel.md).
- Nächster Schritt: AP1.7 policy.

## 2026-10-12 02:20 +02:00 — AP1.7 policy

- Ergebnis: fertig (DoD erfüllt).
- Default-Policy YAML, eigene Policy ladbar, Warn-First senkt Fail/Review auf Warn (Exit 1). Enforce: Fail → Exit 2.
- Allowlist für Install-Hooks, Domain-Allowlist für Outbound, Baseline für neue direkte Abhängigkeiten, High-Advisories, Secret-Pfade.
- `lockward scan --offline` und `lockward baseline`. CLI-Tests: sauberes Projekt Exit 0, Korpus Exit 1, Enforce-Fail Exit 2.
- Gate: fmt, clippy `-D warnings`, nextest (51), audit (215 Crates) grün.
- ADR: [008](adr/008-policy-warn-first.md). MSRV auf 1.86 wegen `noyalib` 0.0.57.
- Nächster Schritt: AP1.8 report.

## 2026-10-12 02:45 +02:00 — AP1.8 report

- Ergebnis: fertig (DoD erfüllt).
- Vier Formate: PR-Markdown, Step Summary, JSON, CycloneDX 1.6. Golden-Files unter `lockward-core/tests/fixtures/report/golden`.
- CLI: `--format text|markdown|summary|json|cyclonedx|all` und `--output`. JSON-Test prüft Score 50 und Exit 1 am Mini-Fixture.
- CycloneDX: `bomFormat`, `specVersion` 1.6, purl, SHA-512 aus der Fixture-Integrity. Seriennummer ist UUID v5.
- Gate: fmt, clippy `-D warnings`, nextest (53), audit (217 Crates) grün.
- ADR: [009](adr/009-reports-und-cyclonedx.md). MSRV auf 1.89, weil `uuid` 1.28 das verlangt.
- Nächster Schritt: AP1.9 GitHub Action, lokal vorbereiten.

## 2026-10-12 03:05 +02:00 — AP1.9 GitHub Action

- Ergebnis: vorbereitet, nicht auf einem echten PR gelaufen.
- Composite Action `.github/actions/lockward` (action.yml ist das Marketplace-Manifest), Beispiel-Workflow, README.
- Die Action schreibt `comment.md` / `summary.md` / `report.json` / `bom.cdx.json`, hängt die Summary an `GITHUB_STEP_SUMMARY` und kommentiert einen PR nur, wenn `comment=true` und das Event `pull_request` ist.
- Lokaler Smoke `scripts/smoke-action.ps1`: action.yml enthält die Pflichtfelder, Mini-Fixture endet mit Exit 1. Kein Remote, kein echter PR.
- Der Beispiel-Workflow scannt das saubere `v2-basic.json` mit `comment: false`, damit ein späterer Lauf nicht rot wird.
- Nächster Schritt: Morning Report.

## 2026-10-12 03:20 +02:00 — Abschluss

- `docs/MORNING_REPORT.md` geschrieben.
- Finaler Gate nach AP1.9: fmt, clippy `-D warnings`, nextest 53, audit 217 Crates, Smoke Exit 1. Alles grün.
- Phase 1 bis auf den echten PR-Lauf vorbereitet. Kein Push.
