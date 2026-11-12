# ADR 011 — Detection tuning v1

## Context

The corpus measurement from PR #15 had recall 0.93 and a false-positive rate of 0.50. All eight false positives fired `install_scripts`. Six of them are common native or binary packages. Two also fired `LW-H001` (`fromCharCode` in minified text) and `LW-H002` (base64 without a second signal).

## Decision

- The default policy fills `install_scripts.allow` with a curated name list (native builds and binary fetchers). A hit suppresses the `install_scripts` violation. Unknown names, including typosquats, stay a finding.
- `puppeteer`, `playwright`, `cypress`, and `electron` are also marked as binary fetchers. For these names, `LW-H003` is an expected download and produces no `no_outbound_build` violation. `LW-H004` (a pipe into a shell) stays a finding, even under an allowed name.
- An install script that is not listed is `review`, not `fail`. When the same package also has a heuristic finding, `install_scripts` is raised to `fail`. In warn mode the effective action stays a warning.
- `LW-H001` no longer matches `fromCharCode` on its own. `eval`, `new Function`, `atob`, `unescape`, and hex escapes remain. Engine version `heuristics-v1.1`.
- `LW-H002` is dropped when the same hook has no other signal. Base64 together with network, obfuscation, shell-out, or secret access stays a finding. The minimum length stays 80, because the malicious fixtures sit just above it and differ from plain data only by the second signal.
- `node-ipc` protestware without an install hook stays invisible to Mode 1. That is a known limit, not an open false positive to be closed by a broader file search.

## Rationale

The allowlist describes packages whose install script belongs to a normal build, not the six names that showed up in the first measurement. Held-out cases with an install script and a different name must not be added afterwards: that is how the list shows it does not generalize. An install script without a second signal must stay visible, otherwise a staged downloader (`node build.js`, payload in another file) becomes a false negative.

## Alternatives

- Silently treat every install script without a second signal as benign: lowers the false-positive rate on held-out packages and loses `ua-parser-js-staged`.
- Turn off `fromCharCode` and lone base64 even when a second signal sits beside them: loses confirmed malicious cases.
- Compare names by prefix: `puppeteer-core` and `esbudld` would be trusted by mistake.
