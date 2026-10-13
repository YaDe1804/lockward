# Lockward detection benchmark

An honest, reproducible measurement of Lockward's static detection quality on a
labeled corpus. We publish this because a scanner's only real value is its
detection quality — and because a local-first, auditable tool should show its
numbers, including the uncomfortable ones.

## Method

- **Corpus:** 72 cases under [`corpus/`](../corpus) — 16 malicious, 56 benign.
  - **Malicious** cases are *patterns reconstructed* from publicly documented npm
    supply-chain incidents (event-stream, ua-parser-js, crossenv-style
    typosquats, eslint-scope, node-ipc, staged `postinstall` downloaders).
    **No live malware:** every payload is an inert marker — nothing executes,
    even on an accidental `npm install`.
  - **Benign** cases are popular clean packages *plus* the hard cases that cause
    false positives: native-build packages (`node-gyp`, `bcrypt`, `sharp`,
    `keccak`, `ssh2`, …), legitimate binary/browser downloaders (`puppeteer`,
    `chromedriver`, …), and packages with embedded base64 / minified assets.
- **Harness:** `lockward-eval` runs each case through the `lockward-core` API,
  offline and deterministic, with a fixed timestamp.
- **Scope:** this measures **install-hook + heuristic** detection. The
  `advisory_coverage` rule is disabled via the eval policy to isolate it, and
  OSV / `known_vulnerable` matching is **not** measured here (the offline cache
  is empty) — a separate benchmark with a seeded cache is planned.

## Results

Confusion matrix (corpus of 72):

|                 | flagged | not flagged |
|-----------------|--------:|------------:|
| malicious (16)  | TP 15   | FN 1        |
| benign (56)     | FP 2    | TN 54       |

| Metric    | Value |
|-----------|------:|
| Recall    | 0.94  |
| Precision | 0.88  |
| F1        | 0.91  |
| FP-rate   | 0.036 |

False-positive rate by cohort:

| Cohort               | Cases | FP-rate |
|----------------------|------:|--------:|
| trusted_build        | 19    | 0.00    |
| inspected_clean      | 5     | 0.00    |
| known_downloader     | 4     | 0.00    |
| clean                | 24    | 0.00    |
| heuristic_probe      | 2     | 0.00    |
| residual_downloader  | 2     | 1.00    |

## How detection works (why the numbers look like this)

A bare install hook is **not** treated as malicious just because it exists.
Lockward judges what the hook *does*:

1. **Trusted build commands** (`node-gyp`, `prebuild-install`, `husky`, …) → info only.
2. **Referenced local scripts are read** (statically, bounded, path-contained,
   never executed) and the hook/heuristic rules run against their contents — so
   a staged `postinstall → node build.js` downloader is caught by the real
   signal inside `build.js`, not by the mere presence of a hook.
3. **Known binary/browser downloaders** (`puppeteer`, `chromedriver`, …) have
   their expected install-time network access suppressed.

## Honest limitations

- **False negative (1):** protestware whose payload lives in ordinary library
  code with no install hook (`node-ipc`-style). Mode 1 is static and scans
  install hooks and the scripts they reference, not arbitrary library source —
  so this class is out of scope by design (a candidate for a future content
  heuristic or a behavioral Mode 2).
- **Residual false positives (2):** a legitimate package that fetches a binary
  from the network at install time (`edgedriver`, `prisma`) is **statically
  indistinguishable** from a malicious staged downloader. Lockward surfaces
  these as **review** (not a build-breaking failure) rather than silently
  trusting them — conservative by design. Narrowing this further needs
  download-domain / reputation data or a behavioral sandbox (Mode 2).
- **Not measured here:** OSV / known-vulnerability matching (offline cache is
  empty in the harness).
- **Prevalence:** the corpus is roughly balanced; in the real world benign
  packages vastly outnumber malicious ones, so treat the headline FP-rate as a
  property of *this* corpus, not of a production dependency tree.
- The corpus is reconstructed patterns, not a live-malware feed.

## Reproduce

```bash
cargo run -p lockward-eval -- --output corpus-report.json
```

The `corpus` CI job runs this on every pull request and uploads
`corpus-report.json` as a build artifact.
