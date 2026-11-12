# ADR 009 — Reports and CycloneDX

## Context

AP1.8 needs four outputs: a pull-request comment, a GitHub step summary, JSON, and CycloneDX. Golden tests must not depend on the clock or on an absolute path.

## Decision

- Human-readable reports are German. JSON field names stay English. ADR 016 supersedes the language of the reports. The split between display text and JSON field names still stands.
- The timestamp is passed in. The library does not read a clock. The CLI sets UTC. `--scanned-at` overrides it.
- CycloneDX 1.6 JSON. `serialNumber` is a UUID v5 over the sorted purls (namespace OID), so the same graph yields the same number.
- Components are the lockfile packages without the root project. The root project is in `metadata.component`. `purl` follows `pkg:npm/…`, with scopes as `%40`.
- SRI `sha256`/`sha384`/`sha512` is translated to hex. Invalid integrity fields omit the hash and do not break the export.
- Golden files normalize the absolute path to `{root}`.
- `--format all --output <dir>` writes `comment.md`, `summary.md`, `report.json`, and `bom.cdx.json`.

## Rationale

Deterministic numbers and paths make snapshot tests possible. German in the two Markdown formats keeps the reports for the DACH region without translating the JSON contract.

## Alternatives

- A random UUID: breaks golden files.
- The official CycloneDX schema as a crate for validation: an extra dependency. The tests check the required fields. A schema check against the CycloneDX schema stays a manual addition.
- SPDX instead of CycloneDX: the output format is CycloneDX.
