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
- Four inert regression cases cover `./husky`, `node --require`, `sh -c`,
  and `bun`. They are reported separately and must fail. Recall, precision,
  F1, and the false-positive rate stay on the 72-case corpus: recall 0.9375,
  precision 0.8824, false-positive rate 0.0357.
- `napi-build` is not a trusted command. Published `unrs-resolver` 1.13.0
  has no install script, so the corpus case is a clean package. The
  `napi-postinstall` command downloads a native binding and is not trusted.
- Known install tools and known downloaders are expected. A download that
  is not piped into a shell is review. The eval report separates fail and
  review.
- ADR 014 and `docs/LIMITS.md` describe the hook argument model, the shell
  parser's limits, and why `edgedriver` is not a known downloader.
- `SECURITY.md`, this changelog, `deny.toml`, and a pull request template.
  `cargo deny check` runs in the existing CI job. Push builds run on `main`
  only. The test suite also runs on Windows and macOS.

### Fixed

- A path-form command is read as a local script. A bare trusted name is
  still trusted. Node preloads are read with the entry script, `sh -c` and
  `bash -c` are walked again, and `bun`, `deno`, `tsx`, `ts-node`, `python`,
  `python3`, `zsh`, and `dash` are interpreters. An unknown command is
  `Unverified`. An empty hook body is `Empty`.
- Advisory cache writes use a unique temporary file and replace the target
  directly. A write failure is a report note. The scan result stays valid.
- An advisory cache read that fails for a reason other than a missing file
  is one note for the run and counts as a miss. Offline mode still reports
  the coverage gap.
- A backslash in a hook script path is read as `/`, so the same path has the
  same disposition on Linux, macOS, and Windows. `..\outside.js` stays blocked.
- A release tag that is not `v` plus the workspace version stops the release
  workflow before the build.
- A package that declares a trusted build command's `bin` name, and is not
  that command's publisher, is reported as `bin_shadow`. Hooks that call the
  bare name are `unverified` in that project.
- A trusted bin is compared with the same normalization as the hook command:
  ASCII lower case, then one trailing `.cmd`, `.exe`, or `.bat`. `Husky`,
  `husky.cmd`, and `HUSKY.EXE` shadow `husky`. The finding quotes the
  lockfile spelling. One inert regression case covers `husky.cmd` and stays
  outside the 72-case metrics.
- A trusted command is not a trusted build when its arguments run shell
  syntax. `$(...)` and backticks are walked like `sh -c`, including inside
  double quotes. Process substitution, subshells, brace groups,
  here-documents, and `eval` / `source` / `.` are `unverified`. Plain
  `$NAME`, `${NAME}`, and output redirections such as `2>&1` stay trusted.
  The same text inside single quotes stays literal. Four inert regression
  cases cover the substitution bypass and stay outside the 72-case metrics.

### Changed

- The CycloneDX document changed. A document from 0.1.1 does not compare
  field-for-field with a document from this release:
  - A dev dependency is `scope` `excluded` and has the property
    `lockward:dev` set to `true`. It used to be `optional`. An optional
    dependency that is not a dev dependency is `scope` `optional`.
  - Every component, including the root, has a `bom-ref`. The same
    `name@version` at more than one path is one component.
  - `dependencies` lists the root and every component. `dependsOn` is sorted.
    A component with no dependencies has an empty list. Unresolved edges are
    not listed; their count is `lockward:unresolved-edges` on the root.
  - `serialNumber` is derived from the document without `serialNumber` and
    without `metadata.timestamp`. A different timestamp does not change it.
    A different component, scope, license, hash, edge, or Lockward version
    does.
- CVSS boundary cases from the FIRST v3.1 specification and examples are
  locked in tests. The formula is unchanged.
- `KNOWN_DOWNLOADERS` and `TRUSTED_COMMANDS` are checked to stay strictly
  sorted and unique.
- `@mapbox/node-pre-gyp` is no longer a trusted command name. The token
  contains `/`, so it was already a path. `node-pre-gyp install` stays a
  trusted build.

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
