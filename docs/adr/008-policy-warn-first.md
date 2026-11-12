# ADR 008 — Policy, warn-first, and exit codes

## Context

AP1.7 needs five default rules, a loadable YAML policy, warn-first as the baseline, and exit codes 0/1/2. The scanner must not modify the repository.

## Decision

- Policy version 1, parser `noyalib` (not the archived `serde_yaml`). Unknown fields are errors. The MSRV for that is 1.86.
- Mode `warn`: fail and review become warn. The exit code is 0 or 1. No files are written.
- Mode `enforce`: fail → exit 2, warn or review → exit 1, otherwise 0. A fail outranks warnings.
- Rules: `install_scripts` (allowlist, default warn), `no_outbound_build` (fail, domains can be allowlisted), `new_dependencies` (review), `known_vulnerable` (fail from high), `secret_path_access` (fail).
- Without a baseline, `new_dependencies` stays inactive and only produces a note. `lockward baseline` writes `name@version` of the direct dependencies.
- A domain allowlist suppresses network findings only when the evidence contains hosts and every host is listed. A bare `curl` without a URL stays a finding.
- The CLI runs the scan and sets the exit code. `--offline` forces the cache.

## Rationale

Warn-first matches the specified onboarding. Fail-closed for advisories and secret paths stays visible in the policy, but it does not block the first run. A missing baseline must not flood every project with review warnings at once.

## Alternatives

- Treat the first run without a baseline as a review of every direct dependency: noisy, and it conflicts with "changes nothing except warnings" for a usable first run.
- `serde_yaml` 0.9: unmaintained.
- Exit 1 for review in warn mode, separate from warn: the CLI only knows 0/1/2. Review is a warning in warn mode.
