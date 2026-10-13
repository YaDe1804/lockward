# lockward-eval

Offline harness for the labeled corpus in `corpus/`. It scans each case through
`lockward-core` (no shell, no network, fixed `scanned_at`) and writes a
confusion matrix plus every false negative and false positive.

```bash
cargo run --locked -p lockward-eval -- --output corpus-report.json
```

`advisory_coverage` and the inactive `new_dependencies` note are not detections.
`LW-H003` on a known binary fetcher is an expected download and is not a detection.
A trusted build command and a clean local script are notes, not detections.
`install_scripts` counts only when the referenced target could not be read.
A download that does not execute is `review`. Pipe-to-shell, obfuscation,
shell-out, and secret access are `fail`. Review stays in the detection set, so
precision and recall do not move when only the hardness changes. The summary
prints the fail/review/info counts.
The summary splits the false-positive rate by cohort (`trusted_build`,
`inspected_clean`, `known_downloader`, `residual_downloader`, `clean`,
`heuristic_probe`).

The process exits 0 after a successful measurement, including when precision or
recall are low. It exits 1 when a case cannot be scanned or a label is invalid.
