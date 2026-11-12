# ADR 016 — English as the only output language

## Status

Accepted, 2026-11-12. Supersedes the language decision in ADR 001. The workspace, toolchain, `unsafe` ban, and release-signing decisions in ADR 001 still stand.

## Context

ADR 001 made human-readable output German for a DACH audience: CLI help, the pull-request comment, the CI summary, and the explanation sentences. JSON field names and rule ids stayed English. The README and the GitHub Marketplace listing were already English, so one product spoke two languages.

Lockward is one of the YaDe Labs supply-chain tools. Those tools share readers: CI jobs, review comments, and people who compare reports across projects. A second language, or a switch between languages, would make those reports harder to compare.

## Decision

English is the only language of the product. That covers program output, reports, error messages, documentation, ADRs, corpus notes, and project rules.

There is no localization layer and no `--lang` flag. One string is stored for each sentence. Display labels (`OK`, `Warning`, `Fail`, and the severity words) live in one place, on the type that owns the value. Machine-readable JSON uses stable lowercase identifiers (`gate.outcome`: `ok`, `warn`, `fail`). Free-text fields are English and are not a stable contract. The JSON document records `report_version`, starting at `2`, so a consumer can tell this shape from the 0.1.2 document.

Rule ids (`LW-H001` and the rest) and rule names (`install_scripts`, `bin_shadow`, and the rest) do not change. Detection, scores, policy decisions, and exit codes do not change.

## Alternatives

- A localization layer with a catalog per language. Every sentence, golden file, and plural form would exist twice. The catalogs would drift, and CI would have to prove both.
- A `--lang` flag with German kept as the default. That keeps the split this ADR is closing: marketplace text in English, reports in German, and a second code path that must stay behavior-identical.
- German JSON values as well as German sentences. ADR 001 already rejected that. `gate.outcome` was the remaining leak (`"Warnung"`). It becomes `warn`.

## Consequences

Report prose changes. Anyone who matches German words in a comment, a summary, or a JSON `message` has to match English words instead. `gate.outcome` changes from `Warnung` / `Block` to `warn` / `fail` (`OK` was already `OK` and becomes `ok`). `report_version` is new. The README states which JSON fields are stable and which are display text.

Sort order of findings must not depend on the wording of a message. That is a separate change, recorded with the code that drops the message from the sort key.
