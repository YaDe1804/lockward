# Limits of the hook command parser

Mode 1 does not execute hook text. `lockward-core` splits a hook body into commands and, where the rules in ADR 014 match, reads local files. The splitter is a lexical scan, not a shell.

## What the splitter handles

- Whitespace separates words. A newline, `;`, `&`, `&&`, `|`, and `||` start a new command.
- `&>` stays inside the current command. It is not treated as a separator.
- Single and double quotes group words. Separators inside quotes are literal text.
- An empty or whitespace-only body has no commands. Its disposition is `empty`.

## What is evaluated

The scan is still lexical. It does not execute the hook. These forms are walked again with the same rules as the outer hook, up to three levels, and they share the eight-file script budget with `sh -c`:

- Command substitution `$(...)` and backticks, including inside double quotes.
- The command inside process substitution `<(...)` and `>(...)`. The segment itself stays `unverified`, because the pipe is not modeled. The body is still read.
- `sh -c`, `bash -c`, `zsh -c`, and `dash -c`.
- The text after `eval`, and the path operand of `source` and `.`.

A fourth nested level is `unverified` and is not read. A substitution that is not balanced is not walked. That segment is `unverified`, with a warning.

Single quotes hide the text inside them. `husky '$(echo ok)'` is the literal argument `$(echo ok)` and stays a trusted build. Double quotes do not hide `$` or backticks.

## What stays allowed on a trusted command

A bare name in `TRUSTED_COMMANDS` stays a trusted build when the only extra shell syntax is one of these:

- Output redirection: `> file`, `>> file`, `>/dev/null`, and `&>`.
- A file-descriptor duplicate with digits on the right, such as `2>&1`.
- A plain parameter `$NAME` or `${NAME}`, where `NAME` is an identifier (`[A-Za-z_][A-Za-z0-9_]*`).

The 56 benign corpus hooks contain none of these forms. The allow list is the redirection and parameter syntax a build command actually uses, not a pattern copied from the corpus. See ADR 014.

## What is not evaluated

Anything else in the raw segment makes that segment `unverified`. It is not a trusted build, and it is not `inspected`. The report carries a warning. This includes:

- Parameter forms other than a plain name: `${NAME:-default}`, `$?`, `$$`, and a dangling `$`.
- A subshell `(...)`. A balanced body is walked, and the segment is still `unverified`.
- A brace group `{ ...; }`.
- A here-document (`<<` or `<<-`) or a here-string. The newline already starts a new command, so the here-document body is not recovered as data.
- Input redirection (`< file`).
- `eval`, `source`, or `.` as the command.
- Backslash escapes, including `\"`, `\'`, and a trailing `\` used as a line continuation.
- Shell comments (`# ...`), globbing, and `PATH` lookup.

A backslash does not protect the next character. In particular, `\"` inside a double-quoted word ends the quote, because `"` is still the quote marker.

A newline is always a command separator. A trailing `\` does not join the next line.

## How a command is classified

After the expansions above are walked:

- A bare name in `TRUSTED_COMMANDS` is a trusted build command only when the segment has no unevaluated shell syntax.
- Recognized inline source (`node -e`, `python -c`, `bun -e`, `deno eval`, and the other inline forms in ADR 014) stays in the hook body.
- A path, or an interpreter plus a script path, is read as a local file when the read is allowed. `\` in a script path is rewritten to `/` before the escape, symlink, and canonicalize checks.
- Anything else is `unverified`, and the report carries a warning. It is not `inspected`.

The original hook string is still handed to the heuristics unchanged. A `curl | sh` that the splitter divides into two commands can still match `LW-H004`, because that rule scans the raw text.

A payload that appears only inside a here-document body, or only after a backslash continuation, is not recovered. Mode 1 will not run the hook to find it.

## Trust and `PATH`

A bare trusted name is not resolved through `PATH`, and Mode 1 does not follow `node_modules/.bin` symlinks. Shadowing of a trusted command is read from the lockfile `bin` field instead. A package that is not an allowed publisher of that command produces `bin_shadow`, and hooks that call the bare name are `unverified`. A `bin` npm installs without writing it into `packages[].bin` is not visible. See ADR 014.

A `--require` / `--import` value that is a bare module name is not resolved. Only a path-like preload is read.

`napi-build` is not a trusted command. Published `unrs-resolver` 1.13.0 has no install script. Its native-binding fallback runs when the package is loaded, from `index.js`, and Mode 1 does not read that file. `napi-postinstall` downloads a platform binary, so it is not treated as a trusted build step either. See ADR 014.

## `edgedriver` is not a known downloader

`KNOWN_DOWNLOADERS` includes `chromedriver` and `geckodriver`. It does not include `edgedriver`. The list is a closed set of packages whose install-time download is expected (browsers, drivers, and the native stylesheet binaries). `edgedriver` fetches a driver the same way, and that text is the same shape as a malicious download. ADR 013 leaves `edgedriver` and `prisma` as residual findings: a download that is not piped into a shell stays a review, and the name is not added to hide a corpus hit. Putting `edgedriver` on the list would also hide that pattern under any other name that copied the same script.

## Parallel scans on one advisory cache

Two processes, or two threads, may read and write the same OSV cache directory. An entry is written to a temporary file and renamed into place, so a reader does not observe a half-written file. While a rename replaces a file that another thread still has open, Windows can return access denied or a sharing violation, and the name can be missing for a moment. The cache retries access denied and sharing failures at most eight times and waits at most 140 ms in total. A missing name is retried only while a publish marker for that key is still fresh, with the same limits. A different error is not retried, and a miss with no marker returns at once. If the file is still unavailable, a read becomes a cache miss with a warning, and a write becomes a warning. The scan does not stop.

## What the SBOM does not contain

The CycloneDX document is the lockfile, not the scan result. See ADR 015.

- No vulnerabilities, no VEX, and no advisory ratings. Those stay in the JSON and Markdown reports.
- No scores, no policy findings, and no hook text.
- No unresolved edge as a `dependsOn` target. The count is `lockward:unresolved-edges` on the root component. There is no `compositions` entry for the missing targets.
- No second component when the same `name@version` is installed at more than one path. Fields that differ are merged; they are not listed per path.
- No file inventory, no external references beyond the purl, and no evidence of whether an optional dependency was actually installed.
