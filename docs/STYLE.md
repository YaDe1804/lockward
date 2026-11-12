# Output style

English is the only language. ADR 016 records that decision. Write the sentence a reviewer can check, then stop.

## Sentences

- Plain and specific. No exclamation marks. No slang.
- Sentence case in headings: "Install hook", not "Install Hook".
- One term for one thing. Use the glossary below. Do not alternate synonyms.
- A message names the package, then what the hook does, then the evidence.

```
Package left-pad@1.0.0 hook `postinstall` downloads during install. Evidence: `curl https://example.invalid/x`.
```

## Glossary

| Term | Use it for |
| --- | --- |
| install hook | A `preinstall`, `install`, or `postinstall` script, or a lockfile `hasInstallScript` flag. Not "lifecycle script" and not "postinstall hook" as a general name. |
| lockfile | `package-lock.json`. Not "lock file" as two words. |
| package | One name and version from the lockfile. |
| advisory | One OSV record matched to a package. Not "vulnerability" in prose when the record is what you mean. The word vulnerability stays in the rule name `known_vulnerable`. |
| finding | One policy hit or one heuristic hit shown to a person. The JSON array is still named `violations`. That field name is the stable identifier; the sentence says "finding". |
| evidence | The short excerpt that shows why a rule matched. |
| baseline | The snapshot of direct dependencies a later scan compares against. |
| policy | The YAML document that maps rules to actions. |
| gate | The pass or block decision after the policy is applied. |
| review | The action that asks a person to look. Exit code 1 in enforce mode. Not "needs review" as a second action name. |
| trusted build command | A bare command name in `TRUSTED_COMMANDS`, such as `node-gyp` or `husky`. |
| unverified | The hook disposition when the analyzer did not fully understand the command. Not "unknown" and not "inspected". |

## Labels and identifiers

Display labels and JSON identifiers are different.

| Value | JSON identifier | Display label |
| --- | --- | --- |
| Gate outcome ok | `ok` | `OK` |
| Gate outcome warn | `warn` | `Warning` |
| Gate outcome fail | `fail` | `Fail` |
| Severity | `critical`, `high`, `medium`, `low`, `info`, `unknown` | the same words |

`info` is an evaluation label for a case that did not trip the gate. It is not a score band. Score bands are `critical`, `high`, `medium`, `low`, and `unknown`.

Mode stays `warn` or `enforce` in both places. Actions stay `allow`, `warn`, `review`, and `fail`.

Free-text fields (`message`, `explanation`, `description`, `notes`) are English. They are not a stable contract. Rule ids (`LW-H001`) and rule names (`install_scripts`, `bin_shadow`) do not change.

## Plurals

A count of zero or of two or more uses the plural. A count of one uses the singular. Write both forms. Do not emit "1 packages".

```
0 packages were not checked against OSV.
1 package was not checked against OSV.
2 packages were not checked against OSV.
```

## What not to add

No localization catalog. No `--lang`. No second copy of a sentence.
