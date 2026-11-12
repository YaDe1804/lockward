# ADR 015 — CycloneDX SBOM mapping

## Context

ADR 009 chose CycloneDX 1.6 and a UUID v5 `serialNumber` over the component purls. That document listed every `node_modules` path as its own component, mapped every `dev` dependency to `scope: optional`, ignored the lockfile `optional` flag, and had no `bom-ref` and no `dependencies` array. The resolver already has the graph.

The mapping below was checked against the CycloneDX 1.6 JSON reference (<https://cyclonedx.org/docs/1.6/json/>, retrieved 2026-11-12) and the Package URL npm type definition (`types/npm-definition.json` on `package-url/purl-spec` `master`, retrieved 2026-11-12).

## Decision

### Scope and properties

CycloneDX defines three scopes. The reference says: if scope is omitted, "'required' scope SHOULD be assumed by the consumer of the BOM." The descriptions are:

- `required`: "The component is required for runtime."
- `optional`: "The component is optional at runtime. Optional components are components that are not capable of being called due to them not being installed or otherwise accessible by any means."
- `excluded`: "Components that are excluded provide the ability to document component usage for test and other non-runtime purposes. Excluded components are not reachable within a call graph at runtime."

Lockward maps the lockfile flags as follows.

| Lockfile | `scope` | Property |
| --- | --- | --- |
| neither `dev` nor `optional` | `required` | none |
| `optional`, not `dev` | `optional` | none |
| `dev`, including `dev` together with `optional` | `excluded` | `lockward:dev` = `true` |

`peer` does not change the scope. It adds `lockward:peer` = `true`. A dev peer stays `excluded` and carries both properties.

Properties use the form the specification requires: an object with `name` and `value`, and `value` is a string. They are sorted by `name`.

### One component per `name@version`

The same `name@version` installed at several `node_modules` paths is one component. The identity is the purl, which is built from the lockfile spelling of the name and the version. Paths are merged in lexicographic order.

- Scope uses the less restrictive result. `required` wins over `optional`, and both win over `excluded`. `lockward:dev` is set only when the merged scope is still `excluded`.
- `lockward:peer` is set when any path is a peer.
- License and integrity keep the first non-empty value. Because paths are sorted, that is the lexicographically smallest path that had a value.
- A name that differs only by case is a different component. See the purl note below.

### `bom-ref` and `dependencies`

Every component, including `metadata.component`, has `bom-ref` set to its purl. The purl is unique inside one document because components are deduplicated on it. The root uses the same purl function. A dependency whose purl equals the root purl is not given a distinct ref; that collision is not rewritten.

The reference describes `dependencies` as: "Defines the direct dependencies of a component, service, or the components provided/implemented by a given component. Components or services that do not have their own dependencies must be declared as empty elements within the graph. Components or services that are not represented in the dependency graph may have unknown dependencies. It is recommended that implementations assume this to be opaque and not an indicator of an object being dependency-free."

Lockward therefore writes one entry for the root and one entry for every component, including a component with no dependencies. `dependsOn` is present and is an empty array in that case, so a consumer does not have to treat a missing entry as an unknown graph. Entries are sorted by `ref`. Each `dependsOn` list is sorted and has no duplicates. Every `ref` and every `dependsOn` target is a `bom-ref` in the same document.

All resolved edges are included: prod, dev, optional, and peer. The target component's scope and properties carry the classification. Cycles are written as they are. An edge in `Graph::unresolved` is not a `dependsOn` target, because there is no component to point at. The count of those edges is the property `lockward:unresolved-edges` on `metadata.component`, including `"0"`.

The same reference says excluded components "are not reachable within a call graph at runtime." Lockward still lists edges to `excluded` components. The array is the lockfile graph, not a claim that a dev dependency is reachable at runtime. The scope says it is not.

### `serialNumber`

The reference says: "Every BOM generated SHOULD have a unique serial number, even if the contents of the BOM have not changed over time. If specified, the serial number must conform to RFC 4122. Use of serial numbers is recommended." The value must match `^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`.

Lockward does not follow the "unique even if the contents have not changed" recommendation. Reproducible output is a core promise: the same lockfile must produce the same document apart from `metadata.timestamp`. `serialNumber` is a UUID v5 (RFC 4122, namespace OID, the same namespace as ADR 009) of the canonical JSON of the BOM with `serialNumber` and `metadata.timestamp` removed. Object keys are sorted. Arrays keep their already-sorted order. A change to a component, a scope, a license, a hash, an edge, or the Lockward version changes the number. A different timestamp does not. Two lockfiles with the same packages and the same edges produce the same number even when the `node_modules` paths differ.

### Package URLs

The current npm purl type definition sets `case_sensitive: true` on both the namespace and the name, and notes that npm has required lowercase names for new packages since 2015 while older mixed-case names were grandfathered. The documented scoped example is `pkg:npm/%40angular/animation@12.3.1`. Lockward percent-encodes the leading `@` as `%40` and otherwise copies the lockfile name and version. It does not lowercase them. `Left-Pad` and `left-pad` stay two purls. That matches the current type definition. Older guidance that required a lowercase name is not applied.

`integrity` values `sha256`, `sha384`, and `sha512` become CycloneDX `SHA-256`, `SHA-384`, and `SHA-512` hashes. The payload is standard or URL-safe Base64. Anything else is omitted.

## Alternatives

- Keep one component per install path. The same package would appear several times, and `bom-ref` would need a path suffix that is not stable across installs that hoist differently.
- Drop dev edges from `dependencies` because the scope text says excluded components are not in the runtime call graph. That hides the lockfile graph the SBOM is there to show.
- Omit entries whose `dependsOn` is empty. The specification says those components must be declared as empty elements, and a missing entry may be read as an unknown graph.
- Mint a fresh UUID per render, as the serial-number recommendation prefers. Two scans of one lockfile would no longer compare equal.
- Lowercase purl names. That would match older npm purl notes and would merge grandfathered mixed-case names. The current type definition says the name is case-sensitive, so the lockfile spelling is kept.

## Consequences

Documents produced before this mapping do not compare field-for-field with documents produced after it. Dev dependencies change from `optional` to `excluded`, `bom-ref` and `dependencies` are new, and `serialNumber` is no longer a hash of the purl list. `metadata.timestamp` remains the only field that changes when the content does not.

What the SBOM does not contain is listed in `docs/LIMITS.md`.
