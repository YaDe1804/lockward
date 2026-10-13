# lockward-eval

Offline harness for the labeled corpus in `corpus/`. It scans each case through
`lockward-core` (no shell, no network, fixed `scanned_at`) and writes a
confusion matrix plus every false negative and false positive.

```bash
cargo run --locked -p lockward-eval -- --output corpus-report.json
```

`advisory_coverage` and the inactive `new_dependencies` note are not detections.
`LW-H003` on a curated binary fetcher (`puppeteer`, `playwright`, `cypress`,
`electron`) is an expected download and is not a detection. The corpus measures
install hooks and heuristics. `known_vulnerable` stays empty without a seeded
advisory cache. The summary splits the false-positive rate for allowlisted and
held-out install scripts.

The process exits 0 after a successful measurement, including when precision or
recall are low. It exits 1 when a case cannot be scanned or a label is invalid.
