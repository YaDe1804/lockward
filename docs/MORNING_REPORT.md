# Morning Report — Lockward Phase 1

Branch: `night/phase1`. Kein Push, kein Force, keine Roadmap-Änderung. Referenzdateien (`Cursor-Arbeitsanweisung_Phase1_MVP-CLI.md`, `Lockward_Spezifikation_v1.docx`, beide Roadmap-HTMLs) sind nur mitcommittet, nicht bearbeitet.

## Stand der Arbeitspakete

| AP | Status | DoD |
| --- | --- | --- |
| AP1.0 Setup & CI | fertig | `cargo build`, `--help`/`--version`, `scan` läuft. CI- und Release-Workflow liegen im Repo, sind nachts nicht auf GitHub gelaufen. |
| AP1.1 ingest | fertig | Lockfile v2 und v3, Fixture-Tests, kaputtes JSON als `Result`. |
| AP1.2 resolve | fertig | Graph mit direkten/transitiven Kanten, Zyklen werden aufgezeichnet. |
| AP1.3 advisories | fertig | OSV-Batch über mockbares HTTP, Datei-Cache, Offline-Lauf. Bekannter Treffer `lodash@4.17.20` → `GHSA-35jh-r3h4-6jhm` / `CVE-2021-23337` im Fixture, nicht live. |
| AP1.4 hooks | fertig | `preinstall`/`install`/`postinstall` plus `hasInstallScript` ohne Körper. Korpus ohne False Negatives. Kein Ausführen. |
| AP1.5 heuristics | fertig | `heuristics-v1`, sechs Regeln, Test je Regel, Version im Output. |
| AP1.6 score | fertig | `score-v1`, gleicher Input → gleicher Score, jeder Fund hat einen deutschen Satz. |
| AP1.7 policy | fertig | Default-YAML und eigene Datei, Warn-First, Exit 0/1/2. |
| AP1.8 report | fertig | Markdown, Step Summary, JSON, CycloneDX 1.6. Golden-Tests grün. |
| AP1.9 Action | vorbereitet | `action.yml`, Beispiel-Workflow, lokaler Smoke. Kein echter PR. |

Phase-1-Exit „CI-Gate in einem echten Test-Repo“ ist offen, weil das einen Remote und einen PR braucht.

## Entscheidungen

| ADR | Inhalt |
| --- | --- |
| [001](adr/001-workspace-und-sprache.md) | Rust, Workspace, deutsch für Menschen, englische JSON-Schlüssel, keine Lizenz gewählt, cosign keyless im Release-Workflow. |
| [002](adr/002-npm-lockfile-modell.md) | Nur die `packages`-Map, Identität ist der Lockfile-Pfad. |
| [003](adr/003-dependency-graph.md) | Node-`node_modules`-Walk, Zyklen sind Daten. |
| [004](adr/004-hooks-statisch.md) | Nur Lockfile-Pfade, keine Symlinks, `prepare` nicht enthalten. |
| [005](adr/005-osv-cache.md) | Cache-first online, Offline zählt Fehltreffer und matcht dann nichts. |
| [006](adr/006-heuristik-v1.md) | Regelkatalog LW-H001–H006. |
| [007](adr/007-score-formel.md) | Gedeckelte Punkte, Projekt = Maximum. |
| [008](adr/008-policy-warn-first.md) | Warn senkt Fail/Review auf Warn. Ohne Baseline feuert `new_dependencies` nicht. |
| [009](adr/009-reports-und-cyclonedx.md) | Zeitstempel wird injiziert, SBOM-UUID v5, purl. |

Weitere Festlegungen: MSRV 1.89 (wegen `uuid` 1.28 und `noyalib` 0.0.57). YAML über `noyalib`, nicht `serde_yaml`. HTTP über reqwest/rustls.

## Bekannte Lücken, FP und FN

- Es gibt keinen kuratierten Malware-Korpus. Die Hook- und Heuristik-Fixtures sind inert und selbst geschrieben. Eine FP-Rate gegen echte benign/malicious Pakete ist nicht gemessen.
- `prepare` und `prepublish` laufen bei npm install oft mit, sind aber bewusst keine Hooks. Das kann ein False Negative sein, wenn Schadcode nur dort steht.
- `build.rs` und `setup.py` sind nicht implementiert. Das ist Phase 2.
- LW-H002 trifft jeden base64-ähnlichen Block ab 80 Zeichen. Lange harmlose Tokens können falsch positiv sein.
- `curl \| sh` zählt als Netzwerk und als Pipe (H003 und H004). Das ist gewollt und steht im ADR.
- Offline ohne Cache meldet keine Advisories (`cache_misses`), statt zu scheitern. Ein erster Lauf ohne Netz sieht also „keine CVEs“. Online scheitert der Scan, wenn OSV nicht erreichbar ist.
- Ohne `--baseline` ist die Regel für neue Abhängigkeiten stumm und schreibt nur einen Hinweis.
- CycloneDX ist strukturell getestet (Format, Version, purl, Hash), nicht gegen das offizielle JSON-Schema validiert.
- Die Release-Signatur und die Action sind nicht auf GitHub ausgeführt.

## Finaler Gate-Status

Nach AP1.9, vor diesem Bericht:

- `cargo fmt --all -- --check` grün
- `cargo clippy --all-targets -- -D warnings` grün
- `cargo nextest run --locked` grün, 53 Tests
- `cargo audit` grün, 217 Crates, Advisory-DB 1296 Einträge
- `scripts/smoke-action.ps1` grün (Mini-Fixture Exit 1)

## Commits auf `night/phase1`

```
02d9294 feat(setup): scaffold the Lockward workspace and CI
b9c9b8c feat(ingest): parse npm lockfile versions 2 and 3
7a26b06 feat(resolve): build a cycle-safe npm dependency graph
84b76ec feat(hooks): detect npm install scripts without executing them
00950ee feat(advisories): match npm packages against OSV with a file cache
9715060 feat(heuristics): add versioned rules for install-hook risk
305f11c feat(score): add a deterministic explainable risk score
550e523 feat(policy): gate scans with warn-first YAML rules
988badd feat(report): emit markdown, CI summary, JSON, and CycloneDX
baa8f06 feat(action): add a composite GitHub Action and a local smoke test
```

Der Commit dieses Berichts kommt direkt danach.

## Was Deniz morgens prüft und wie es weitergeht

1. Branch ansehen, nicht die Roadmap-HTMLs anfassen. Fortschritt steht nur in `docs/NIGHTLY_LOG.md` und hier.
2. Lokal wiederholen:
   ```powershell
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo nextest run --locked
   cargo audit
   powershell -File .\scripts\smoke-action.ps1
   cargo run -p lockward-cli -- scan .\lockward-core\tests\fixtures\report\mini --offline --format all --output .\out --scanned-at 2026-10-12T00:00:00Z
   ```
   Erwartung für das Mini-Fixture: Exit 1, in `out\` liegen `comment.md`, `summary.md`, `report.json`, `bom.cdx.json`.
3. Einmal online ohne `--offline` gegen ein echtes kleines Repo laufen lassen und prüfen, ob der OSV-Cache unter `%LOCALAPPDATA%\lockward\osv-cache` gefüllt wird und ein zweiter Lauf mit `--offline` dieselben Advisories zeigt.
4. Lizenz entscheiden (Open-Core ist nur vorgemerkt) und erst dann `publish = false` bzw. eine `LICENSE` anfassen.
5. Remote anlegen und `night/phase1` normal pushen. Kein Force. CI-Workflow und Release-Workflow dort zum ersten Mal ansehen.
6. Action in einem Test-Repo: Binary bauen, `comment: "true"` auf einem PR, prüfen ob der Kommentar erscheint und Exit 1/2 das Check rot macht. Der mitgelieferte Beispiel-Workflow scannt absichtlich das saubere `v2-basic.json` mit `comment: "false"`.
7. Marketplace-Eintrag erst nach öffentlichem Repo und Tag. `action.yml` ist das Manifest.
8. Optional: CycloneDX-Datei gegen das Schema 1.6 prüfen. Optional: `prepare` als Hook nachziehen, wenn der Korpus das verlangt.
9. Phase 2 nicht anfangen, bevor das echte PR-Gate einmal grün beobachtet wurde. Kein pip, cargo-Ökosystem, GitLab oder Sandbox in diesem Baum.

## Nicht angefasst

`supply_chain_scanner_roadmap_v1.html` und `supply_chain_scanner_roadmap_v2.html` sind unverändert. Eine neue Roadmap-Version bleibt bei Deniz.
