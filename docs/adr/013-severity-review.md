# ADR 013 — Execution is fail, a download alone is review

## Context

After ADR 012, two benign downloaders (`edgedriver`, `prisma`) stay flagged. Their install script downloads a binary and does not execute the content. A malicious download has the same text pattern. The detection should stay visible. The build should not fail on it.

## Decision

- `curl`/`wget` into a shell, obfuscation (`LW-H001`, `LW-H002`), and shell-out (`LW-H005`) are fail (exit 2 in enforce). Secret access and known high vulnerabilities stay fail.
- A bare network download (`LW-H003`) without that execution signal is review (exit 1, including in enforce). An unreadable install hook stays review.
- The boundary is the pattern, not the package name. `edgedriver` and `prisma` are not on the downloader list.
- In the corpus, review still counts as a finding. Precision, recall, and the false-positive rate do not change with the hardness.

## Rationale

Mode 1 cannot tell from the text whether an unknown download is legitimate. "Please review" is the honest answer. Once the content goes into a shell, an interpreter, or a child process, the pattern is categorically dangerous and fails the build.

## Alternatives

- Keep every network signal as fail: the two residual downloaders break clean builds.
- Silently allow a bare download: the malicious download without a pipe disappears together with the legitimate downloaders.
