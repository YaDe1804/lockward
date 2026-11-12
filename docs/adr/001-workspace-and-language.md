# ADR 001 — Language, workspace, and CLI language

> **Superseded in part by [ADR 016](016-english-only-output.md).** The decision that human-readable output is German no longer applies. The workspace, Rust toolchain, `unsafe` ban, and release-signing decisions in this ADR still stand.

## Context

Phase 1 needs a single binary that runs deterministically in CI. The choices are Rust, an open core, and npm first.

## Decision

- The implementation language is Rust (edition 2024, stable toolchain).
- Cargo workspace with `lockward-core` (library) and `lockward-cli` (binary `lockward`).
- `unsafe` is forbidden across the workspace.
- Human-readable surfaces (CLI help, pull-request comment, CI summary, explanation sentences) are German, for a German-speaking audience in the DACH region. JSON field names and rule ids stay English, so golden files and CI parsers stay stable. Internal tracing logs are English.
- No license file is added until open-core licensing is settled. `publish = false`.
- Releases are signed keyless with cosign (`sigstore/cosign-installer@v4.1.2`) through the GitHub OIDC identity. The signed file is `SHA256SUMS`, not each blob on its own.

## Rationale

Rust produces a single binary without a runtime and fits a security tool. German in reports matches the DACH positioning; English JSON keys stay a stable machine contract.

## Alternatives

- Go: faster first development, but a different toolchain and no better fit for the required single-binary security profile.
- English throughout: conflicts with the specified German report positioning.
- German throughout, including JSON keys: breaks stable machine fields.
- A GPG signature with a long-lived key in the repo: key management cannot be solved overnight. Keyless Sigstore uses the CI identity.
