# ADR 009 — Reports und CycloneDX

## Kontext

AP1.8 braucht vier Ausgaben: PR-Kommentar, GitHub Step Summary, JSON und CycloneDX. Golden-Tests dürfen nicht von der Uhr oder vom absoluten Pfad abhängen.

## Entscheidung

- Menschenlesbare Reports sind Deutsch. JSON-Feldnamen bleiben Englisch.
- Der Zeitstempel wird hineingereicht. Die Bibliothek liest keine Uhr. Die CLI setzt UTC, `--scanned-at` überschreibt ihn.
- CycloneDX 1.6 JSON. `serialNumber` ist eine UUID v5 über die sortierten purls (Namespace OID), damit derselbe Graph dieselbe Nummer ergibt.
- Komponenten sind die Lockfile-Pakete ohne das Root-Projekt. Das Root-Projekt steht in `metadata.component`. `purl` folgt `pkg:npm/…`, Scopes als `%40`.
- SRI `sha256`/`sha384`/`sha512` wird nach Hex übersetzt. Ungültige Integrity-Felder lassen den Hash weg und brechen den Export nicht.
- Golden-Files normalisieren den absoluten Pfad auf `{root}`.
- `--format all --output <dir>` schreibt `comment.md`, `summary.md`, `report.json` und `bom.cdx.json`.

## Begründung

Deterministische Nummern und Pfade machen Snapshot-Tests möglich. Deutsch in den beiden Markdown-Formaten trifft die DACH-Reports aus der Spezifikation, ohne den JSON-Vertrag zu übersetzen.

## Alternativen

- Zufällige UUID: bricht Golden-Files.
- Offizielles CycloneDX-Schema als Crate zur Validierung: zusätzliche Abhängigkeit. Die Tests prüfen die Pflichtfelder; ein Schema-Check gegen die Spezifikation bleibt eine manuelle Ergänzung.
- SPDX statt CycloneDX: die Spezifikation bevorzugt CycloneDX.
