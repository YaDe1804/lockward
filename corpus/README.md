# Lockward Eval-Korpus

Gelabelte, **inerte** npm-Fixtures für die offline Eval-Harness (`lockward-eval`).
Der Korpus misst Install-Hooks und Heuristiken. Er ist keine OSV-Messung:
ohne Advisory-Cache bleibt `known_vulnerable` leer.

## Sicherheits-Leitplanke

- Kein echter Schadcode, keine Malware-Tarballs, kein Download, keine Ausführung.
- Lockward liest die Dateien nur statisch (Mode 1).
- Install-Hooks sind entweder `node -e "console.log('LOCKWARD_EVAL_FIXTURE …')"`
  (Muster im String) oder ein literales Build-Kommando bzw. `node <datei>`.
  Weder `sh` noch `cmd` starten `curl`, `wget` oder eine Pipe.
- Zusätzliche `.js`-Dateien enthalten nur Kommentare und
  `console.log("LOCKWARD_EVAL_FIXTURE")`. Lockward liest sie, führt sie nicht aus.
- Die Fälle sind **rekonstruierte Muster** öffentlich dokumentierter Vorfälle,
  keine kopierten Originale.

Ein versehentliches `npm install` in einem Fallverzeichnis gibt den Marker aus
und holt nichts.

## Layout

```text
corpus/
  eval-policy.yaml
  malicious/<fall>/
  benign/<fall>/
```

Jeder Fall hat `package-lock.json` (lockfileVersion 3), bei Bedarf
`package.json` unter `node_modules/…`, und `label.yaml`.

## Label

```yaml
expected: malicious            # malicious | benign
expected_rules: [no_outbound_build]
cohort: trusted_build             # optional, nur bei benign: trusted_build | inspected_clean | known_downloader | residual_downloader | clean | heuristic_probe
source: "Vorfall — rekonstruiertes Muster, inerter Payload"
notes: "optional"
```

`expected_rules` nennt die Regeln, die feuern **sollen** (Policy-Name oder
`LW-H00x`). Bei gutartigen Fällen ist die Liste leer. `advisory_coverage` und
`new_dependencies` gehören nicht dazu.

`cohort` trennt die gutartigen Fälle für die ehrliche FP-Rate:

- `trusted_build`: der Hook besteht nur aus einem vertrauten Build-Kommando
- `inspected_clean`: eine lokale Skriptdatei wurde gelesen und ist sauber
- `known_downloader`: Paket steht auf der endlichen Downloader-Liste
- `residual_downloader`: Netzwerk im Skript, Paket steht nicht auf dieser Liste
- `clean`: kein Install-Hook
- `heuristic_probe`: Hook nur, um eine Heuristik zu provozieren

Neue Held-out-Namen werden nicht auf die Downloader-Liste gesetzt. Ein unbekannter
Downloader bleibt ein Fund.

## Bekannte Grenze

`malicious/node-ipc-protestware` bleibt ein False Negative. Die Protestware lag
im Bibliothekscode, nicht in einem Install-Hook. Mode 1 liest `index.js` nicht.
Das ist keine offene Heuristik-Lücke für diesen Schritt: eine Suche über
beliebige Quelldateien würde neue Fehlalarme erzeugen. Kandidat für eine spätere
Content-Heuristik oder Mode 2.

`corpus/eval-policy.yaml` setzt `advisory_coverage` auf `allow`, damit der
Offline-Lauf die Hook- und Heuristik-Erkennung misst. `known_vulnerable`
bleibt ohne Cache leer.

## Harness

```bash
cargo run --locked -p lockward-eval -- --output corpus-report.json
```

Die Ausgabe ist die Confusion-Matrix, Precision, FP-Rate, Recall und F1, die
Listen jedes FN und FP, und die FP-Rate nach Kohorte. Der Korpus ist
gutartig-lastig. Schwellen werden hier nicht an den Held-out-Fällen nachgezogen.
