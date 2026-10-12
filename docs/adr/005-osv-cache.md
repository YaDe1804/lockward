# ADR 005 — OSV-Cache und Offline-Lauf

## Kontext

AP1.3 gleicht npm-Pakete gegen die OSV-API ab. Der Scan muss offline wiederholbar sein, und Tests dürfen das Netz nicht brauchen. Die Batch-Antwort enthält nur IDs; Schwere steht im Vuln-Dokument.

## Entscheidung

- Abfrage ist `POST /v1/querybatch` in Blöcken von 128, danach `GET /v1/vulns/{id}`.
- HTTP steckt hinter `HttpTransport`. Tests nutzen einen Fake. `ReqwestTransport` spricht mit rustls, Timeout 20 Sekunden, User-Agent `lockward/<version>`.
- Das Root-Projekt wird nicht abgefragt. Gleiche `name@version`-Paare teilen sich eine Anfrage.
- Cache-Dateien liegen unter einem Verzeichnis, der Dateiname ist SHA-256 von `npm`, Name und Version. Inhalt ist die gemappte Advisory-Liste.
- Online: Cache-Treffer überspringen das Netz, Fehltreffer werden geholt und geschrieben. HTTP-Fehler brechen den Scan ab.
- Offline (`--offline` später in der CLI): nur der Cache. Fehltreffer zählen als `cache_misses` und liefern keine Advisories, statt zu scheitern.
- Schwere: `database_specific.severity` gewinnt (GitHub-Wording, `moderate` = medium). Der CVSS-Score wird zusätzlich berechnet. Fehlt das Wort, mappt der CVSS-v3-Base-Score: ≥9 critical, ≥7 high, ≥4 medium, >0 low.
- Es werden keine Tarballs und kein Exploit-Code geladen.

## Begründung

Fail-closed online verhindert ein stilles „keine CVEs“, wenn die API fehlt. Offline muss für CI ohne Netz trotzdem durchlaufen, sobald der Cache warm ist. Die Wort-Schwere von GitHub trifft die Policy-Grenze „high“ zuverlässiger als ein selbst berechneter Score allein.

## Alternativen

- Nur die Batch-IDs speichern und Details jedes Mal nachladen: Offline-Lauf hätte keine Schwere.
- Netzwerkfehler als leeres Ergebnis: False Negative bei known-vulnerable.
- Eigene CVE-Datenbank: Lockward kuratiert keine eigenen Advisories und bleibt bei OSV.
