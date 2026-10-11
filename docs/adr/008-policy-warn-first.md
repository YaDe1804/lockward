# ADR 008 — Policy, Warn-First und Exit-Codes

## Kontext

AP1.7 braucht die fünf Default-Regeln aus der Spezifikation, eine ladbare YAML-Policy, Warn-First als Baseline und Exit-Codes 0/1/2. Der Scanner darf das Repository nicht verändern.

## Entscheidung

- Policy-Version 1, Parser `noyalib` (nicht das archivierte `serde_yaml`). Unbekannte Felder sind Fehler. MSRV dafür ist 1.86.
- Modus `warn`: Fail und Review werden zu Warn. Exit ist 0 oder 1. Es werden keine Dateien geschrieben.
- Modus `enforce`: Fail → Exit 2, Warn oder Review → Exit 1, sonst 0. Ein Fail schlägt Warnungen.
- Regeln: `install_scripts` (Allowlist, Default warn), `no_outbound_build` (Fail, Domains allowlistbar), `new_dependencies` (Review), `known_vulnerable` (Fail ab high), `secret_path_access` (Fail).
- Ohne Baseline bleibt `new_dependencies` inaktiv und erzeugt nur einen Hinweis. `lockward baseline` schreibt `name@version` der direkten Abhängigkeiten.
- Eine Domain-Allowlist unterdrückt Netzwerk-Funde nur, wenn der Beleg Hosts enthält und jeder Host gelistet ist. Ein nacktes `curl` ohne URL bleibt ein Verstoß.
- Die CLI führt den Scan aus und setzt den Exit-Code. `--offline` erzwingt den Cache.

## Begründung

Warn-First entspricht dem spezifizierten Onboarding. Fail-closed bei Advisories und Secret-Pfaden bleibt in der Policy sichtbar, blockiert den ersten Lauf aber nicht. Eine fehlende Baseline soll nicht jedes Projekt sofort mit Review-Warnungen fluten.

## Alternativen

- Ersten Lauf ohne Baseline als Review aller direkten Abhängigkeiten: laut, widerspricht „verändert nichts außer Warnungen“ im Sinne eines brauchbaren Erstlaufs.
- `serde_yaml` 0.9: unmaintained.
- Exit 1 für Review auch im Warn-Modus getrennt von Warn: die CLI kennt nur 0/1/2, Review ist im Warn-Modus eine Warnung.
