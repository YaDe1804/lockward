# ADR 012 — Hook-Inhalt statt Hook-Existenz

## Kontext

Die Messung nach ADR 011 hat die kuratierte Paket-Allowlist auf 0 % FP gebracht und den Held-out-Long-Tail bei 12/12 FP gelassen. Jeder dieser Fälle feuerte nur `install_scripts`. `node build.js` und `node-gyp rebuild` sehen gleich aus, solange die referenzierte Datei nicht gelesen wird. Dadurch blieb `ua-parser-js-staged` nur über die bloße Hook-Existenz ein Fund.

## Entscheidung

- Ein Install-Hook wird in Befehle zerlegt. `node-gyp`, `node-gyp-build`, `node-pre-gyp`, `@mapbox/node-pre-gyp`, `prebuild-install`, `prebuildify`, `cmake-js`, `husky`, `patch-package` und `napi-build` (derselbe native Build-Treiber wie `node-gyp-build`) sind vertraute Kommandos. Besteht der Hook nur daraus, ist das eine Info, kein Fund. Die Liste hängt am Programmnamen, nicht am Paketnamen.
- `node <datei>`, `sh`/`bash <datei>`, `./<datei>` und eine Ebene `npm run <script>` werden statisch gelesen: höchstens acht Dateien, höchstens 1 MiB, kein Symlink, kein `..`, kein absoluter Pfad, Pfad muss im Projektwurzelverzeichnis liegen. `require()` wird nicht verfolgt. Nichts wird ausgeführt.
- Gelesener oder inline sichtbarer Inhalt läuft durch die bestehenden Heuristiken. Sauberer Inhalt ist Info. `curl|sh`, Obfuskation, Secret-Pfade und Netzwerk bleiben die Funde.
- `install_scripts` ist kein Gate-Fail mehr. Eine Violation gibt es nur noch, wenn ein referenziertes Ziel nicht lesbar ist; die Aktion ist Review.
- Bekannte Downloader (`puppeteer`, `puppeteer-core`, `playwright`, `playwright-core`, `cypress`, `electron`, `chromedriver`, `geckodriver`, `node-sass`, `sass-embedded`) unterdrücken `LW-H003`. `LW-H004` bleibt ein Fund. Die Liste ist eine endliche Kategorie, kein Ablageort für Korpus-Treffer. Ein unbekannter Downloader bleibt geflaggt.

## Begründung

Der Long Tail nativer Module ruft dieselben Build-Tools auf. Das Kommando generalisiert, der Paketname nicht. Ein gestagter Downloader wird erkennbar, sobald `build.js` gelesen wird. Netzwerk ohne Eintrag auf der Downloader-Liste bleibt ein Fund, weil ein legitimer und ein bösartiger Download am Text nicht zuverlässig zu trennen sind.

## Alternativen

- Jedes unbekannte Install-Script weiter als Fund werten: hält `ua-parser-js-staged` nur über die Hook-Existenz und lässt den Held-out-Long-Tail rot.
- Unbekanntes Netzwerk bei Downloadern stillschweigend erlauben: senkt die Residual-FP und verliert bösartige Downloads unter unbekanntem Namen.
- `require()`-Graphen folgen: verlässt die begrenzte, statische Lesetiefe und vergrößert die FP-Fläche.
