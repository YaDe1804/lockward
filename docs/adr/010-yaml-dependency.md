# ADR 010 — YAML dependency (`noyalib`)

## Context

The policy is read from YAML. `serde_yaml` is unmaintained. `serde_yml` is a deprecated shim. Phase 1 uses `noyalib` for this. The version is in `0.0.x`. Such a dependency must not be pulled along by a caret range without a review.

## Decision

`noyalib` stays the YAML parser and is pinned exactly to `0.0.57` (`version = "=0.0.57"`, feature `compat-serde-yaml`). The only call is `noyalib::from_str`. Switching to another YAML crate is not a gain while there is no established 1.x alternative with the same Serde contract.

## Vendor review (0.0.57, crates.io, 2026-10-12)

- License: MIT OR Apache-2.0. Repository: `https://github.com/sebastienrousseau/noyalib`. Pure Rust, MSRV 1.86.
- `src/lib.rs` sets `#![forbid(unsafe_code)]`. The source tree has no `unsafe` block. Hits on the word are comments (YAML "unsafe scalar", not Rust `unsafe`).
- `build.rs` only checks `rustc --version` and an environment variable, declares two `cfg`s, and has no build dependencies. No network, no file access, no code generation.
- Feature `compat-serde-yaml` enables `lossless-u64`. Lockward only needs it to read the policy file.

A later update is its own review, not a silent `cargo update`.

## Rationale

The parser is already integrated, forbids `unsafe`, and replaces the archived YAML crate. An exact pin holds the `0.0.x` supply chain without changing the policy API.

## Alternatives

- `serde_yaml` 0.9: unmaintained.
- `serde_yml`: a deprecated shim on the same line.
- Another `0.x` parser only to avoid `0.0.x`: a new review surface, and no more mature contract.
