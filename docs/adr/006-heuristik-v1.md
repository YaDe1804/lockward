# ADR 006 — Heuristik-Regelset v1

## Kontext

AP1.5 braucht eine versionierte, regelbasierte Engine über Hook-Inhalt und Paket-Metadaten. Startregeln: Obfuskation, große Base64-Blobs, Netzwerk, `curl|sh`, Shell-outs, Secret-Pfade. Jede Regel hat ID, Beschreibung, Gewicht und Beispiel. Mode 1 führt die Funde nicht aus. Die Testkörper sind inert und selbst geschrieben.

## Entscheidung

Engine-Version: `heuristics-v1`.

| ID | Gewicht | Erkennt |
| --- | --- | --- |
| LW-H001 | 25 | `eval`, `Function`, `fromCharCode`, `atob`, `unescape`, mindestens vier `\xNN`-Escapes |
| LW-H002 | 20 | Base64-ähnlicher Block ab 80 Zeichen |
| LW-H003 | 15 | `curl`, `wget`, `fetch(`, `axios`, `net.connect`, `http(s).get/request`, `require("http")` |
| LW-H004 | 35 | `curl` oder `wget` per Pipe nach `sh`/`bash` |
| LW-H005 | 20 | `child_process`, `exec`/`spawn`, `sh -c`, `bash -c`, `cmd.exe`, `powershell` |
| LW-H006 | 40 | `~/.ssh`, `.npmrc`, `.aws`, `/.config/`, `NPM_TOKEN`, `AWS_SECRET`, `id_rsa` |

- Pro Hook und Regel höchstens ein Fund. `curl \| sh` trifft H003 und H004, weil die Pipe zusätzlich zum bloßen Netzwerkzugriff zählt.
- Leere Körper (`hasInstallScript` ohne Manifest) erzeugen keine Heuristik.
- `tsconfig` trifft H006 nicht. `.config` braucht einen Pfadtrenner.
- Die Erklärung ist ein deutscher Satz mit Paket, Hook und kurzem Beleg (max. 120 Zeichen).
- Metadaten (Name, Version, Hook) stehen im Fund. Es gibt in v1 keine reine Metadaten-Regel, weil Download-Zahlen und Paketalter nicht im Lockfile stehen.

## Begründung

Feste IDs und Gewichte machen den späteren Score nachrechenbar. Eine Regel pro Signal hält False Positives erklärbar: `node-gyp rebuild` und `echo` bleiben ohne Fund.

## Alternativen

- Eine Sammelregel „irgendwie verdächtig“: nicht testbar und nicht erklärbar.
- `prepare`/`prepublish` mitbewerten: außerhalb des Hook-DoD aus AP1.4.
- ML-Score: widerspricht der geforderten regelbasierten Engine.
