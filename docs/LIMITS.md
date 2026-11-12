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
- A path, or an interpreter plus a script path, is read as a local file when the read is allowed. `\` in a script path is rewritten to `/` before the escape, symlink, and canonicalize checks.
- Anything else is `unverified`, and the report carries a warning. It is not `inspected`.

The original hook string is still handed to the heuristics unchanged. A `curl | sh` that the splitter divides into two commands can still match `LW-H004`, because that rule scans the raw text.

A payload that appears only after the shell expands `$(...)`, a here-document, or a backslash continuation is not recovered. Mode 1 will not run the hook to find it. If the literal command is not trusted, not inline, and not a readable script, the disposition is `unverified`.

`sh -c` / `bash -c` / `zsh -c` / `dash -c` are walked again, up to three levels. A fourth level is `unverified` even when the inner text is a script path. File reads still stop at eight referenced scripts.

## Trust and `PATH`

A bare trusted name is not resolved through `PATH`, and Mode 1 does not follow `node_modules/.bin` symlinks. Shadowing of a trusted command is read from the lockfile `bin` field instead. A package that is not an allowed publisher of that command produces `bin_shadow`, and hooks that call the bare name are `unverified`. A `bin` npm installs without writing it into `packages[].bin` is not visible. See ADR 014.

A `--require` / `--import` value that is a bare module name is not resolved. Only a path-like preload is read.

`napi-build` is not a trusted command. Published `unrs-resolver` 1.13.0 has no install script. Its native-binding fallback runs when the package is loaded, from `index.js`, and Mode 1 does not read that file. `napi-postinstall` downloads a platform binary, so it is not treated as a trusted build step either. See ADR 014.

## `edgedriver` is not a known downloader

`KNOWN_DOWNLOADERS` includes `chromedriver` and `geckodriver`. It does not include `edgedriver`. The list is a closed set of packages whose install-time download is expected (browsers, drivers, and the native stylesheet binaries). `edgedriver` fetches a driver the same way, and that text is the same shape as a malicious download. ADR 013 leaves `edgedriver` and `prisma` as residual findings: a download that is not piped into a shell stays a review, and the name is not added to hide a corpus hit. Putting `edgedriver` on the list would also hide that pattern under any other name that copied the same script.
