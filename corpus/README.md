# Lockward evaluation corpus

Labeled, **inert** npm fixtures for the offline evaluation harness (`lockward-eval`).
The corpus measures install hooks and heuristics. It is not an OSV measurement:
without an advisory cache, `known_vulnerable` stays empty.

## Safety rail

- No real malicious code, no malware tarballs, no download, no execution.
- Lockward reads the files only statically (Mode 1).
- Install hooks are either `node -e "console.log('LOCKWARD_EVAL_FIXTURE …')"`,
  a literal build command, `node <file>`,
  `node --require <file> <file>`, `./<file>`, `sh -c 'node <file>'`,
  or `bun <file>`. The hook string itself contains no `curl`, no `wget`,
  and no pipe.
- Extra files contain only comments (`//` or `#`) and
  `console.log("LOCKWARD_EVAL_FIXTURE")`. Lockward reads them and does not execute them.
- The cases are **reconstructed patterns** of publicly documented incidents,
  not copied originals.

An accidental `npm install` in a case directory prints the marker
and fetches nothing.

## Layout

```text
corpus/
  eval-policy.yaml
  malicious/<case>/
  benign/<case>/
  regression/<case>/
```

`regression/` holds the fixed hook forms (`./husky`, `node --require`,
`sh -c`, `bun`, a trusted command with `$(...)`, backticks,
a doubled `$(...)` or `<(...)`, and a foreign bin `husky.cmd`). The
harness measures them and requires `fail`.
Precision, recall, F1, and the false-positive rate count only `malicious/` and `benign/`
(72 cases).

Every case has `package-lock.json` (lockfileVersion 3), a `package.json`
under `node_modules/…` when needed, and `label.yaml`.

## Label

```yaml
expected: malicious            # malicious | benign
expected_rules: [no_outbound_build]
cohort: trusted_build             # optional, benign only: trusted_build | inspected_clean | known_downloader | residual_downloader | clean | heuristic_probe
source: "incident — reconstructed pattern, inert payload"
notes: "optional"
```

`expected_rules` names the rules that **should** fire (a policy name or
`LW-H00x`). For benign cases the list is empty. `advisory_coverage` and
`new_dependencies` are not included.

`cohort` splits the benign cases for an honest false-positive rate:

- `trusted_build`: the hook consists only of a trusted build command
- `inspected_clean`: a local script file was read and is clean
- `known_downloader`: the package is on the finite downloader list
- `residual_downloader`: network access in the script, and the package is not on that list
- `clean`: no install hook
- `heuristic_probe`: a hook only to provoke a heuristic

New held-out names are not added to the downloader list. An unknown
downloader stays a finding.

## Known limit

`malicious/node-ipc-protestware` stays a false negative. The protestware lived
in library code, not in an install hook. Mode 1 does not read `index.js`.
That is not an open heuristic gap for this step: a search over
arbitrary source files would create new false positives. It is a candidate for a later
content heuristic or for Mode 2.

`corpus/eval-policy.yaml` sets `advisory_coverage` to `allow`, so the
offline run measures hook and heuristic detection. `known_vulnerable`
stays empty without a cache.

## Harness

```bash
cargo run --locked -p lockward-eval -- --output corpus-report.json
```

The output is the confusion matrix, precision, the false-positive rate, recall, and F1, the
lists of every false negative and false positive, and the false-positive rate by cohort. The corpus is
weighted toward benign cases. Thresholds are not tuned on the held-out cases here.
