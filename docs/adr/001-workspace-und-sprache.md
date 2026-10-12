# ADR 001 — Sprache, Workspace und CLI-Sprache

## Kontext

Phase 1 braucht eine einzelne Binary, die in CI deterministisch läuft. Gewählt sind Rust, ein offener Core und npm zuerst.

## Entscheidung

- Implementierungssprache ist Rust (Edition 2024, Toolchain stable).
- Cargo-Workspace mit `lockward-core` (Bibliothek) und `lockward-cli` (Binary `lockward`).
- `unsafe` ist workspace-weit verboten.
- Menschenlesbare Oberflächen (CLI-Hilfe, PR-Kommentar, CI-Summary, Explain-Sätze) sind Deutsch, für eine deutschsprachige Zielgruppe im DACH-Raum. JSON-Feldnamen und Regel-IDs bleiben Englisch, damit Golden-Files und CI-Parser stabil sind. Interne Tracing-Logs sind Englisch.
- Es wird keine Lizenzdatei angelegt, bis Open-Core rechtlich festgelegt ist. `publish = false`.
- Releases werden keyless mit cosign (`sigstore/cosign-installer@v4.1.2`) über die GitHub-OIDC-Identität signiert. Signiert wird die `SHA256SUMS`-Datei, nicht jeder Blob einzeln.

## Begründung

Rust liefert eine einzelne Binary ohne Runtime und passt zu einem Security-Tool. Deutsch in Reports trifft die DACH-Differenzierung; englische JSON-Schlüssel bleiben ein stabiler Maschinenvertrag.

## Alternativen

- Go: schnellere Erstentwicklung, aber andere Toolchain und keine bessere Passung zum geforderten Single-Binary-Security-Profil.
- Durchgängig Englisch: widerspricht der spezifizierten deutschsprachigen Report-Differenzierung.
- Durchgängig Deutsch inklusive JSON-Schlüssel: bricht stabile Maschinenfelder.
- GPG-Signatur mit langem Schlüssel im Repo: Schlüsselverwaltung nachts nicht lösbar. Keyless-Sigstore nutzt die CI-Identität.
