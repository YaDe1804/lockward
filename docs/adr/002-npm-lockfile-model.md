# ADR 002 — npm lockfile model

## Context

AP1.1 must turn `package-lock.json` v2 and v3 into a neutral package list. v2 also contains the old `dependencies` tree. Package names are not always on the entry; aliases are.

## Decision

- The only source is the `packages` map. The legacy tree is not interpreted.
- `lockfileVersion` 2 and 3 are accepted. Anything else, including v1, is a `Result` error.
- The identity of an entry is the lockfile path (`node_modules/…`), not `name@version`. Nested duplicates stay distinguishable.
- When `name` is missing, it is derived from the last `node_modules/` segment (`@scope/name` included). An explicit `name` wins (npm aliases).
- A missing version becomes the empty string. A missing name is an error.
- Licenses may be an SPDX string or `{ "type": "…" }`. Only the SPDX or `type` text is kept.
- The output list is sorted by path (`BTreeMap`).

## Rationale

npm itself treats `packages` as authoritative since v2. A path key records the physical install layout that the resolver later needs for Node module resolution. Hard errors on broken JSON and an unknown version prevent a silent partial parse.

## Alternatives

- Merge both trees: two sources of truth. Differences between the tree and `packages` would be their own error class, with no benefit for v2/v3.
- Key by `name@version`: nested copies of the same version collide.
- Parse v1 as well: outside the MVP, and a different schema.
