# ADR 013 — Ausgeführt ist Fail, nur geladen ist Review

## Kontext

Nach ADR 012 bleiben zwei gutartige Downloader (`edgedriver`, `prisma`) geflaggt. Ihr Install-Skript lädt eine Binary, führt den Inhalt aber nicht aus. Dasselbe Textmuster hat ein bösartiger Download. Die Detektion soll sichtbar bleiben. Der Build soll daran nicht scheitern.

## Entscheidung

- `curl`/`wget` in eine Shell, Obfuskation (`LW-H001`, `LW-H002`) und Shell-out (`LW-H005`) sind Fail (Exit 2 in enforce). Secret-Zugriff und bekannte High-Vulns bleiben Fail.
- Reines Netzwerk-Laden (`LW-H003`) ohne dieses Ausführungssignal ist Review (Exit 1, auch in enforce). Ein nicht lesbarer Install-Hook bleibt Review.
- Die Grenze hängt am Muster, nicht am Paketnamen. `edgedriver` und `prisma` stehen nicht auf der Downloader-Liste.
- Im Korpus zählt Review weiter als Fund. Precision, Recall und FP-Rate ändern sich durch die Härte nicht.

## Begründung

Ob ein unbekannter Download legitim ist, sieht Mode 1 dem Text nicht an. „Bitte prüfen“ ist die ehrliche Antwort. Sobald der Inhalt in eine Shell, einen Interpreter oder einen Kindprozess geht, ist das Muster kategorisch gefährlich und bricht den Build.

## Alternativen

- Jedes Netzwerk-Signal weiter als Fail: die beiden Residual-Downloader brechen saubere Builds.
- Reines Laden stillschweigend erlauben: der bösartige Download ohne Pipe verschwindet mit den legitimen Downloadern.
