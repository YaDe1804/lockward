# ADR 004 — Hooks nur statisch lesen

## Kontext

AP1.4 muss `preinstall`, `install` und `postinstall` finden und Fundstelle plus Rohinhalt liefern. Die Skriptkörper stehen nicht im Lockfile, sondern in `package.json`. Mode 1 darf keinen Paketcode ausführen. `build.rs` und `setup.py` gehören zu anderen Ökosystemen; Phase 1 bleibt bei npm.

## Entscheidung

- Es werden nur `package.json`-Dateien gelesen, deren Pfad aus dem Lockfile stammt (`<root>/<packages-key>/package.json` und die Root-`package.json`).
- Symlinks werden nicht gefolgt.
- Nur die drei npm-Install-Hooks zählen. `test`, `build`, `prepare` und `prepublish` sind keine Treffer.
- Liegt ein Körper vor, ist die Provenienz `manifest`. `hasInstallScript` ohne lesbaren Körper wird als eigener Fund `hasInstallScript` gemeldet, damit das Lockfile-Flag kein False Negative ist.
- Kaputtes JSON wird zur Warnung, nicht zum Abbruch. Gibt es zusätzlich `hasInstallScript`, bleibt der Flag-Fund erhalten.
- Rohinhalt wird bei 8192 Zeichen abgeschnitten.
- `build.rs` und `setup.py` sind nicht implementiert. Die Hook-Liste ist eine Konstante, damit Phase 2 sie erweitern kann.

## Begründung

Der Lockfile-Pfad ist die Inventarliste. Ein Verzeichniswalk über ganz `node_modules` würde mehr Dateien lesen, ohne die Frage „welches Paket“ sicherer zu beantworten. Nicht ausführen und keine Symlinks folgen hält Mode 1 beim Lesen von Textdateien.

## Alternativen

- Hooks nur über `hasInstallScript`: verliert den Rohinhalt, den Heuristiken brauchen.
- Jede `package.json` unter `node_modules` rekursiv: findet Pakete außerhalb des Lockfiles, liest aber mehr und folgt leichter Pfadtricks.
- `prepare` mit aufnehmen: npm führt es bei `npm install` ebenfalls aus, gehört aber nicht zu den drei Install-Hooks. Bewusst nicht im v1-Korpus, sonst entstehen False Positives gegen das DoD.
