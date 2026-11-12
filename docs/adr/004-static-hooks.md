# ADR 004 — Read hooks statically only

## Context

AP1.4 must find `preinstall`, `install`, and `postinstall` and return the location plus the raw body. Script bodies are not in the lockfile. They are in `package.json`. Mode 1 must not execute package code. `build.rs` and `setup.py` belong to other ecosystems. Phase 1 stays with npm.

## Decision

- Only `package.json` files whose path comes from the lockfile are read (`<root>/<packages-key>/package.json` and the root `package.json`).
- Symlinks are not followed.
- Only the three npm install hooks count. `test`, `build`, `prepare`, and `prepublish` are not hits.
- When a body is present, provenance is `manifest`. `hasInstallScript` without a readable body is reported as its own finding `hasInstallScript`, so the lockfile flag is not a false negative.
- Broken JSON becomes a warning, not an abort. If `hasInstallScript` is also set, the flag finding is kept.
- Raw content is cut at 8192 characters.
- `build.rs` and `setup.py` are not implemented. The hook list is a constant so phase 2 can extend it.

## Rationale

The lockfile path is the inventory. A directory walk over all of `node_modules` would read more files without answering "which package" more safely. Not executing, and not following symlinks, keeps Mode 1 on reading text files.

## Alternatives

- Hooks only through `hasInstallScript`: loses the raw body that the heuristics need.
- Every `package.json` under `node_modules`, recursively: finds packages outside the lockfile, but reads more and follows path tricks more easily.
- Include `prepare`: npm also runs it on `npm install`, but it is not one of the three install hooks. Left out of the v1 corpus on purpose, otherwise false positives appear against the definition of done.
