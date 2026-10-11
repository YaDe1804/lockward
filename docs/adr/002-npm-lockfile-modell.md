# ADR 002 — npm-Lockfile-Modell

## Kontext

AP1.1 muss `package-lock.json` v2 und v3 in eine neutrale Paketliste überführen. v2 enthält zusätzlich den alten `dependencies`-Baum. Paketnamen stehen nicht immer im Eintrag, Aliase schon.

## Entscheidung

- Quelle ist ausschließlich die `packages`-Map. Der Legacy-Baum wird nicht interpretiert.
- `lockfileVersion` 2 und 3 werden akzeptiert. Alles andere, inklusive v1, ist ein `Result`-Fehler.
- Identität eines Eintrags ist der Lockfile-Pfad (`node_modules/…`), nicht `name@version`. So bleiben verschachtelte Duplikate unterscheidbar.
- Fehlt `name`, wird er aus dem letzten `node_modules/`-Segment abgeleitet (`@scope/name` inklusive). Ein explizites `name` gewinnt (npm-Aliase).
- Fehlende Version wird zum leeren String, fehlender Name ist ein Fehler.
- Lizenzen dürfen ein SPDX-String oder `{ "type": "…" }` sein. Es wird nur der SPDX- bzw. `type`-Text behalten.
- Die Ausgabeliste ist nach Pfad sortiert (`BTreeMap`).

## Begründung

npm selbst behandelt `packages` seit v2 als maßgeblich. Ein Pfad-Schlüssel bildet die physische Installationslage ab, die der Resolver später für Node-Modulauflösung braucht. Harte Fehler bei kaputtem JSON und unbekannter Version verhindern stilles Teilparsen.

## Alternativen

- Beide Bäume mergen: doppelte Wahrheit, Abweichungen zwischen Baum und `packages` wären eigene Fehlerklassen ohne Mehrwert für v2/v3.
- Schlüssel `name@version`: verschachtelte Kopien derselben Version kollidieren.
- v1 mitparsen: außerhalb des MVP, anderes Schema.
