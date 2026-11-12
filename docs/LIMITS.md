# Limits of the hook command parser

Mode 1 does not execute hook text. `lockward-core` splits a hook body into commands and, where the rules in ADR 014 match, reads local files. The splitter is a lexical scan, not a shell.

## What the splitter handles

- Whitespace separates words. A newline, `;`, `&`, `&&`, `|`, and `||` start a new command.
- `&>` stays inside the current command. It is not treated as a separator.
- Single and double quotes group words. Separators inside quotes are literal text.
- An empty or whitespace-only body has no commands. Its disposition is `empty`.

## What the splitter does not understand

These constructs are not interpreted:

- Backslash escapes, including `\"`, `\'`, and a trailing `\` used as a line continuation.
- Command substitution: `$(...)` and backticks.
- Here-documents (`<<` and `<<-`).
- Shell comments (`# ...`).
- Parameter expansion, globbing, and `PATH` lookup.

A backslash does not protect the next character. In particular, `\"` inside a double-quoted word ends the quote, because `"` is still the quote marker.

A newline is always a command separator. A trailing `\` does not join the next line.

## How those inputs are classified

The splitter keeps the characters it does not understand as literal token text, then the normal rules from ADR 014 are applied to whatever argv that produces:

- A bare name in `TRUSTED_COMMANDS` is a trusted build command.
- Recognized inline source (`node -e`, `python -c`, `bun -e`, `deno eval`, and the other inline forms in ADR 014) stays in the hook body.
- A path, or an interpreter plus a script path, is read as a local file when the read is allowed.
- Anything else is `unverified`, and the report carries a warning. It is not `inspected`.

The original hook string is still handed to the heuristics unchanged. A `curl | sh` that the splitter divides into two commands can still match `LW-H004`, because that rule scans the raw text.

A payload that appears only after the shell expands `$(...)`, a here-document, or a backslash continuation is not recovered. Mode 1 will not run the hook to find it. If the literal command is not trusted, not inline, and not a readable script, the disposition is `unverified`.

`sh -c` / `bash -c` / `zsh -c` / `dash -c` are walked again, up to three levels. A fourth level is `unverified` even when the inner text is a script path. File reads still stop at eight referenced scripts.

## Trust and `PATH`

A bare trusted name is not resolved through `PATH`. A package can shadow that name with a dependency bin in `node_modules/.bin`, or with its own `bin` field once npm has linked it into the parent `node_modules/.bin`. Dependency entries are symlinks, which Mode 1 does not follow. Own-`bin` shadowing is a residual risk. See ADR 014.

A `--require` / `--import` value that is a bare module name is not resolved. Only a path-like preload is read.
