# Lockward Eval-Korpus

Gelabelte, **inerte** npm-Fixtures für die offline Eval-Harness (`lockward-eval`).
Der Korpus misst Install-Hooks und Heuristiken. Er ist keine OSV-Messung:
ohne Advisory-Cache bleibt `known_vulnerable` leer.

## Sicherheits-Leitplanke

- Kein echter Schadcode, keine Malware-Tarballs, kein Download, keine Ausführung.
- Lockward liest die Dateien nur statisch (Mode 1).
- Jeder Install-Hook ist `node -e "console.log('LOCKWARD_EVAL_FIXTURE …')"`.
  Angriffsmuster stehen **innerhalb** dieses Strings. Weder `sh` noch `cmd`
  starten `curl`, `wget` oder eine Pipe.
- Zusätzliche `.js`-Dateien enthalten nur Kommentare und
  `console.log("LOCKWARD_EVAL_FIXTURE")`.
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
expected_rules: [install_scripts, no_outbound_build]
source: "Vorfall — rekonstruiertes Muster, inerter Payload"
notes: "optional"
```

`expected_rules` nennt die Regeln, die feuern **sollen** (Policy-Name oder
`LW-H00x`). Bei gutartigen Fällen ist die Liste leer. `advisory_coverage` und
`new_dependencies` gehören nicht dazu.

`corpus/eval-policy.yaml` setzt `advisory_coverage` auf `allow`, damit der
Offline-Lauf die Hook- und Heuristik-Erkennung isoliert.

## Harness

```bash
cargo run --locked -p lockward-eval -- --output corpus-report.json
```

Die Ausgabe ist die Confusion-Matrix, Precision/Recall/F1 und die Liste jedes
FN und FP. Schwellen werden hier nicht geändert.
