# ADR 003 — Dependency graph and cycles

## Context

AP1.2 builds the graph, including transitive edges, from the package list. npm lockfiles contain nested copies and real cycles (`a → b → a`).

## Decision

- Node identity is the lockfile path. Order is the path sort from ingest.
- An edge is resolved with the Node `node_modules` walk: first `<package>/node_modules/<name>`, then each parent directory.
- Only a package with an edge from the root entry (`""`) is direct. Reachability is a separate mark. Unlinked entries stay in the graph and count as unreachable.
- Missing targets (optional platform packages that are not installed) go into `unresolved` and do not abort the run.
- Cycles are recorded by DFS at the back edge. The path repeats the start node at the end. The build still returns the complete graph.

## Rationale

The walk matches Node and distinguishes a nested copy from the top-level copy. Cycles are legal in npm. Aborting would be a false fail of the scanner.

## Alternatives

- Match a semver range against every candidate: ignores the physical nesting and picks the wrong `bar` when two versions exist.
- Treat cycles as a hard error: conflicts with the definition of done.
- `petgraph`: an extra dependency for a small, testable walk.
