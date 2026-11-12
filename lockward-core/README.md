# lockward-core

Library for Lockward's static supply-chain analysis.

Public APIs do not panic. Errors go through [`Error`](src/error.rs) and `Result`. Mode 1 reads only text files (lockfiles, `package.json`) and does not call package code.

Limits for untrusted input: lockfiles over 32 MiB and more than 100,000 packages are rejected with `Error::Limit` before they are evaluated. A `package.json` over 1 MiB is skipped and reported as a warning. At most 2048 OSV vulnerability detail queries are made per scan. Above that the run stops, instead of dropping hits silently.

Modules: `ingest`, `resolve`, `hooks`, `advisories`, `heuristics` (`heuristics-v1.1`), `score` (`score-v1`), `policy`, `scan`, `report` (Markdown, CI summary, JSON, CycloneDX 1.6).
