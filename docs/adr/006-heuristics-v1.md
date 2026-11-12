# ADR 006 — Heuristic rule set v1

## Context

AP1.5 needs a versioned, rule-based engine over hook content and package metadata. The starting rules are obfuscation, large base64 blobs, network, `curl|sh`, shell-outs, and secret paths. Each rule has an id, a description, a weight, and an example. Mode 1 does not execute the findings. The test bodies are inert and written for this project.

## Decision

Engine version: `heuristics-v1`.

| ID | Weight | Detects |
| --- | --- | --- |
| LW-H001 | 25 | `eval`, `Function`, `fromCharCode`, `atob`, `unescape`, at least four `\xNN` escapes |
| LW-H002 | 20 | A base64-like block of 80 characters or more |
| LW-H003 | 15 | `curl`, `wget`, `fetch(`, `axios`, `net.connect`, `http(s).get/request`, `require("http")` |
| LW-H004 | 35 | `curl` or `wget` piped to `sh`/`bash` |
| LW-H005 | 20 | `child_process`, `exec`/`spawn`, `sh -c`, `bash -c`, `cmd.exe`, `powershell` |
| LW-H006 | 40 | `~/.ssh`, `.npmrc`, `.aws`, `/.config/`, `NPM_TOKEN`, `AWS_SECRET`, `id_rsa` |

- At most one finding per hook and rule. `curl \| sh` hits H003 and H004, because the pipe counts in addition to bare network access.
- Empty bodies (`hasInstallScript` without a manifest) produce no heuristic.
- `tsconfig` does not hit H006. `.config` needs a path separator.
- The explanation is a German sentence with the package, the hook, and a short piece of evidence (at most 120 characters). ADR 016 supersedes the language of that sentence. The shape still stands.
- Metadata (name, version, hook) is on the finding. v1 has no metadata-only rule, because download counts and package age are not in the lockfile.

## Rationale

Fixed ids and weights make the later score reproducible by hand. One rule per signal keeps false positives explainable: `node-gyp rebuild` and `echo` stay without a finding.

## Alternatives

- One bucket rule "somehow suspicious": not testable and not explainable.
- Also score `prepare`/`prepublish`: outside the hook definition of done from AP1.4.
- An ML score: conflicts with the required rule-based engine.
