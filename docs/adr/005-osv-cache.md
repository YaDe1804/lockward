# ADR 005 — OSV cache and offline runs

## Context

AP1.3 matches npm packages against the OSV API. A scan must be repeatable offline, and tests must not need the network. The batch response contains only ids. Severity is in the vulnerability document.

## Decision

- The query is `POST /v1/querybatch` in blocks of 128, then `GET /v1/vulns/{id}`.
- HTTP sits behind `HttpTransport`. Tests use a fake. `ReqwestTransport` speaks rustls, with a timeout of 20 seconds and user agent `lockward/<version>`.
- The root project is not queried. Identical `name@version` pairs share one request.
- Cache files live under one directory. The file name is the SHA-256 of `npm`, the name, and the version. The content is the mapped advisory list.
- Online: a cache hit skips the network. A miss is fetched and written. An HTTP error aborts the scan.
- Offline (`--offline` later in the CLI): the cache only. Misses count as `cache_misses` and return no advisories, instead of failing.
- Severity: `database_specific.severity` wins (GitHub wording, `moderate` = medium). The CVSS score is also computed. When the word is missing, the CVSS v3 base score maps as: ≥9 critical, ≥7 high, ≥4 medium, >0 low.
- No tarballs and no exploit code are downloaded.

## Rationale

Fail-closed online prevents a silent "no CVEs" when the API is missing. Offline must still complete for CI without a network once the cache is warm. GitHub's severity word hits the policy threshold "high" more reliably than a self-computed score alone.

## Alternatives

- Store only the batch ids and reload details every time: an offline run would have no severity.
- Treat a network error as an empty result: a false negative for known-vulnerable.
- A private CVE database: Lockward does not curate its own advisories and stays with OSV.
