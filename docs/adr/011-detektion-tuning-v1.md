# ADR 011 — Detektion-Tuning v1

## Kontext

Die Korpusmessung aus PR #15 hat Recall 0.93 und eine FP-Rate von 0.50. Alle acht Fehlalarme feuerten `install_scripts`. Sechs davon sind gängige native oder Binary-Pakete, zwei zusätzlich `LW-H001` (`fromCharCode` in minifiziertem Text) und `LW-H002` (Base64 ohne zweites Signal).

## Entscheidung

- Die Default-Policy füllt `install_scripts.allow` mit einer kuratierten Namensliste (native Builds und Binary-Fetcher). Ein Treffer unterdrückt die `install_scripts`-Violation. Unbekannte Namen, inklusive Typosquats, bleiben ein Fund.
- `puppeteer`, `playwright`, `cypress` und `electron` sind zusätzlich als Binary-Fetcher markiert. Für diese Namen ist `LW-H003` erwarteter Download und erzeugt keine `no_outbound_build`-Violation. `LW-H004` (Pipe in eine Shell) bleibt ein Verstoß, auch unter einem erlaubten Namen.
- Ein nicht gelistetes Install-Script ist `review`, nicht `fail`. Liegt auf demselben Paket ein Heuristik-Fund, wird `install_scripts` auf `fail` angehoben. Im Warn-Modus bleibt die effektive Aktion eine Warnung.
- `LW-H001` erkennt `fromCharCode` nicht mehr allein. `eval`, `new Function`, `atob`, `unescape` und Hex-Escapes bleiben. Engine-Version `heuristics-v1.1`.
- `LW-H002` fällt weg, wenn auf demselben Hook kein anderes Signal liegt. Base64 zusammen mit Netzwerk, Obfuskation, Shell-out oder Secret-Zugriff bleibt ein Fund. Die Mindestlänge bleibt 80, weil die bösartigen Fixtures knapp darüber liegen und sich von reinen Daten nur durch das zweite Signal unterscheiden.
- `node-ipc`-Protestware ohne Install-Hook bleibt für Mode 1 unsichtbar. Das ist eine bekannte Grenze, kein offener Fehlalarm, der durch eine breitere Dateisuche geschlossen wird.

## Begründung

Die Allowlist beschreibt Pakete, deren Install-Script zum normalen Build gehört, nicht die sechs Namen, die in der ersten Messung auffielen. Held-out-Fälle mit Install-Script und anderem Namen dürfen nicht nachgetragen werden: daran zeigt sich, dass die Liste nicht generalisiert. Ein Install-Script ohne zweites Signal muss sichtbar bleiben, sonst wird ein gestagter Downloader (`node build.js`, Payload in einer anderen Datei) zum False Negative.

## Alternativen

- Jedes Install-Script ohne zweites Signal stillschweigend als gutartig werten: senkt die FP-Rate auf Held-out-Paketen und verliert `ua-parser-js-staged`.
- `fromCharCode` und lone Base64 abschalten, auch wenn ein zweites Signal daneben liegt: verliert bestätigte bösartige Fälle.
- Namen per Präfix vergleichen: `puppeteer-core` und `esbudld` wären fälschlich vertraut.
