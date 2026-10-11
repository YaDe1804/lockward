# ADR 003 — Dependency-Graph und Zyklen

## Kontext

AP1.2 baut aus der Paketliste den Graphen inklusive transitiver Kanten. npm-Lockfiles enthalten verschachtelte Kopien und echte Zyklen (`a → b → a`).

## Entscheidung

- Knotenidentität ist der Lockfile-Pfad, Reihenfolge die Pfadsortierung aus dem Ingest.
- Eine Kante wird über den Node-`node_modules`-Walk aufgelöst: zuerst `<paket>/node_modules/<name>`, dann jedes Elternverzeichnis.
- Direkt ist nur, wer eine Kante vom Root-Eintrag (`""`) hat. Erreichbarkeit ist eine eigene Markierung; nicht verlinkte Einträge bleiben im Graph, gelten aber als unerreichbar.
- Fehlende Ziele (optionale Plattformpakete, die nicht installiert sind) landen in `unresolved` und brechen den Lauf nicht ab.
- Zyklen werden per DFS an der Rückkante aufgezeichnet. Der Pfad wiederholt den Startknoten am Ende. Der Aufbau liefert trotzdem den vollständigen Graphen.

## Begründung

Der Walk entspricht dem Verhalten von Node und unterscheidet eine verschachtelte Kopie von der Top-Level-Kopie. Zyklen sind in npm legal; ein Abbruch wäre ein False-Fail des Scanners.

## Alternativen

- Semver-Range gegen alle Kandidaten matchen: ignoriert die physische Verschachtelung und wählt bei zwei `bar`-Versionen die falsche.
- Zyklen als harten Fehler: widerspricht dem DoD.
- `petgraph`: zusätzliche Abhängigkeit für einen kleinen, testbaren Walk.
