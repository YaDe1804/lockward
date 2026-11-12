# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Updated `rustls` to 0.23.46, `rustls-webpki` to 0.103.16,
  `webpki-root-certs` to 1.0.12, and `tokio` to 1.54.1
  (RUSTSEC-2026-0346, RUSTSEC-2026-0347, RUSTSEC-2026-0348,
  RUSTSEC-2026-0349, RUSTSEC-2026-0382, RUSTSEC-2026-0383,
  RUSTSEC-2026-0386).

### Added

- Offline corpus and `lockward-eval` measure hook and heuristic detection.
  CI publishes the numbers and does not gate on them.
- Known install tools and known downloaders are expected. A download that
  is not piped into a shell is review. The eval report separates fail and
  review.
- ADR 014 and `docs/LIMITS.md` describe the hook argument model, the shell
  parser's limits, and why `edgedriver` is not a known downloader.
- `SECURITY.md`, this changelog, `deny.toml`, and a pull request template.
  `cargo deny check` runs in the existing CI job. Push builds run on `main`
  only.

### Fixed

- A path-form command is read as a local script. A bare trusted name is
  still trusted. Node preloads are read with the entry script, `sh -c` and
  `bash -c` are walked again, and `bun`, `deno`, `tsx`, `ts-node`, `python`,
  `python3`, `zsh`, and `dash` are interpreters. An unknown command is
  `Unverified`. An empty hook body is `Empty`.
- Advisory cache writes use a unique temporary file and replace the target
  directly. A write failure is a report note. The scan result stays valid.
- A release tag that is not `v` plus the workspace version stops the release
  workflow before the build.
- A package that declares a trusted build command's `bin` name, and is not
  that command's publisher, is reported as `bin_shadow`. Hooks that call the
  bare name are `unverified` in that project.

### Changed

- CVSS boundary cases from the FIRST v3.1 specification and examples are
  locked in tests. The formula is unchanged.
- `KNOWN_DOWNLOADERS` and `TRUSTED_COMMANDS` are checked to stay strictly
  sorted and unique.

## [0.1.1] - 2026-10-12

### Added

- The composite action verifies the release checksum signature before use.

### Changed

- Release verification steps are written in English.
- The action description names the supply-chain scanner.

## [0.1.0] - 2026-10-12

### Added

- npm lockfile versions 2 and 3, a cycle-safe dependency graph, and install
  hook detection that does not execute package code.
- OSV advisory matching with a file cache, versioned install-hook heuristics,
  an explainable score, and a warn-first YAML policy gate.
- Markdown, CI summary, JSON, and CycloneDX 1.6 reports.
- A composite GitHub Action that downloads the signed release.
- Release builds attested with Sigstore, plus a CycloneDX SBOM on the release.
- AGPL-3.0-only, with the commercial dual-license noted by the rightsholder.
- The Rust toolchain is pinned to 1.89.0. Third-party Actions are pinned to
  commit SHAs.

### Fixed

- Missing OSV coverage is a gate violation. Manifest reads stay inside the
  project root, including Windows drive prefixes. Untrusted text stays inside
  markdown codespans. CycloneDX licenses are an id, an expression, or a name.
  Oversized lockfiles, manifests, and advisory bursts are rejected.
- JSON paths are normalized the same way on Windows and Linux. Base64 and
  `Function` heuristics match more tightly. UTC timestamps use the `time` crate.

[Unreleased]: https://github.com/YaDe1804/lockward/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/YaDe1804/lockward/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/YaDe1804/lockward/releases/tag/v0.1.0
