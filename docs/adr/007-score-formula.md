# ADR 007 — Score formula

## Context

AP1.6 aggregates advisories and heuristics into a risk score per package and for the project. The same input must produce the same score. Every finding needs a plain-language sentence.

## Decision

Model `score-v1`.

- Advisory points before the cap: critical 40, high 25, medium 12, low 4, unknown 6. Cap 70.
- Heuristic points: the sum of the rule weights. Each rule id counts once per package, even when several hooks hit. Cap 60.
- Package score: `min(100, advisory points + heuristic points)`.
- Project score: the maximum of the package scores. Not a mean, so one critical package is not lost in the crowd.
- Bands over the numeric value: ≥75 critical, ≥50 high, ≥25 medium, ≥10 low, otherwise unknown. The band is the display of the score, not the advisory severity. The policy "known-vulnerable high" still looks at the advisory severity.
- Explanations: one German sentence per advisory and per heuristic finding, sorted by source. The heuristic brings its sentence from the engine. ADR 016 supersedes the language of those sentences. The count and the sort still stand.

## Rationale

Capped, additive points can be checked by hand. The maximum as the project value stops many harmless packages from diluting a single backdoor suspicion.

## Alternatives

- A weighted average: one critical package can stay under the fail threshold.
- Opaque ML scoring: conflicts with explainability.
- Heuristic points per hook instead of per rule: duplicate hooks would raise the score without a new signal.
