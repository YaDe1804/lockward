# ADR 007 — Score-Formel

## Kontext

AP1.6 aggregiert Advisories und Heuristiken zu einem Risk-Score pro Paket und für das Projekt. Gleicher Input muss denselben Score liefern. Jeder Fund braucht einen Klartext-Satz.

## Entscheidung

Modell `score-v1`.

- Advisory-Punkte vor dem Deckel: kritisch 40, hoch 25, mittel 12, niedrig 4, unbekannt 6. Deckel 70.
- Heuristik-Punkte: Summe der Regelgewichte, jede Regel-ID pro Paket nur einmal, auch wenn mehrere Hooks treffen. Deckel 60.
- Paket-Score: `min(100, Advisory-Punkte + Heuristik-Punkte)`.
- Projekt-Score: Maximum der Paket-Scores. Kein Mittelwert, damit ein kritisches Paket nicht in der Masse untergeht.
- Bänder über den Zahlenwert: ≥75 kritisch, ≥50 hoch, ≥25 mittel, ≥10 niedrig, sonst unbekannt. Das Band ist die Anzeige des Scores, nicht die Advisory-Schwere. Die Policy „known-vulnerable high“ schaut weiter auf die Advisory-Schwere.
- Erklärungen: ein deutscher Satz pro Advisory und pro Heuristik-Fund, sortiert nach Quelle. Die Heuristik bringt ihren Satz aus der Engine mit.

## Begründung

Gedeckelte, additive Punkte sind von Hand nachrechenbar. Das Maximum als Projektwert verhindert, dass viele harmlose Pakete einen einzelnen Backdoor-Verdacht verdünnen.

## Alternativen

- Gewichteter Durchschnitt: ein kritisches Paket kann unter der Fail-Schwelle bleiben.
- Undurchsichtiges ML-Scoring: widerspricht Explainability.
- Heuristik-Punkte pro Hook statt pro Regel: doppelte Hooks würden den Score ohne neues Signal hochtreiben.
