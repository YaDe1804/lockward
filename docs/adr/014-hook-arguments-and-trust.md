# ADR 014 — Hook arguments and trust

## Context

ADR 012 trusts a build tool by its file name and reads the first non-flag token after `node`, `sh`, or `bash`. Both rules are bypasses:

- `./husky` is trusted, because only the base name is compared, so a package can ship a file named after a trusted tool and skip inspection.
- `node --require ./setup.js install.js` reads `./setup.js` and never opens `install.js`.
- `sh -c 'node install.js'` stops at `-c`, so the inner command is not walked.
- `bun install.js` is not an interpreter, so the script is not read.

An empty hook body and an unknown command were both reported as `inspected`, which claims the body was understood.

## Decision

- `TRUSTED_COMMANDS` applies only when `argv[0]` is a bare name: no `/`, no `\`, and no Windows drive prefix. Any other form is a local path and is read under the existing rules (no symlink, no `..`, no absolute path, at most eight files, at most 1 MiB, path must stay inside the project root). A `\` in that path is rewritten to `/` before those checks, so `.\husky` and `dir\script.js` name the same files on Linux, macOS, and Windows. `..\outside.js` stays blocked. `@mapbox/node-pre-gyp` contains a slash, so the shell does not search `PATH` for it; it is a relative path. That string is not in `TRUSTED_COMMANDS`, because the path rule already excludes it. The bare bin name `node-pre-gyp` stays trusted. `@mapbox/node-pre-gyp` remains an allowed publisher of that bin.
- Node arguments follow the Node.js v26.5.1 command-line API (<https://nodejs.org/api/cli.html>, retrieved 2026-11-12). Options that take a value are consumed both as `--opt value` and as `--opt=value`. `--loader` is included because that page documents it as the previous name of `--experimental-loader`. Optional inspector flags (`--inspect`, `--inspect-brk`, `--inspect-wait`) do not consume the next token. `--experimental-config-file` accepts only the `=` form. The entry script is the first positional argument. Tokens after it belong to the script. `-e`/`--eval` and `-p`/`--print` are inline source: the text stays in the hook body and is what the heuristics scan. There is no separate entry script in that case.
- Path-like preload values are read as well, because Node executes them before the entry script: `-r`/`--require`, `--import`, `--loader`/`--experimental-loader`, and `--test-global-setup`. A bare module name (`--require esm`) is not resolved. That is the same limit as not following `require()`. A path-like preload that cannot be read makes the hook `unverified`.
- `sh -c`, `bash -c`, `zsh -c`, and `dash -c` (including a short cluster such as `-lc`) are parsed again with `walk_script`, up to three levels. The fourth level is `unverified`. File reads still share `MAX_REFERENCED_SCRIPTS`. Inline source for other interpreters (`node -e`, `python -c`, `bun -e`, `deno eval`) is not walked as a shell. The hook body already contains that text, so the heuristics see it.
- A trusted `argv[0]` does not make the segment a trusted build when the raw text contains shell syntax this parser does not fully evaluate. The scan uses the raw segment, not the quote-stripped argv. Single quotes hide their contents. Double quotes do not: `$` and backticks still expand there. `$(...)` and backticks are walked with `walk_script` under the same depth limit and the same script budget as `sh -c`. A substitution that cannot be extracted is `unverified`, with a warning. Process substitution `<(...)` and `>(...)` is walked the same way, and the segment stays `unverified` because the pipe is not modeled. A balanced subshell body is walked and the segment stays `unverified`. A brace group, a here-document (`<<`, `<<-`), input redirection, and `eval` / `source` / `.` as the command are `unverified`. `eval`'s remaining words are walked as a script. `.` and `source` read their path operand.
- Plain output redirection and plain parameters stay allowed on a trusted command: `> file`, `>> file`, `>/dev/null`, `&>`, a digit fd duplicate such as `2>&1`, `$NAME`, and `${NAME}` where `NAME` matches `[A-Za-z_][A-Za-z0-9_]*`. `${NAME:-default}`, `$?`, and `$$` do not. The 56 benign corpus hooks (package.json scripts, 2026-11-12) contain no `$`, no backticks, and no redirection. They are only `node-gyp rebuild`, `husky install`, `node install.js`, `node -e "..."`, `node scripts/build.js`, `node-pre-gyp install`, and `node-gyp-build`. The allow list is therefore the small set of forms a build command uses, not a set copied from a hook that would have been a false positive. Re-measured on the same 72 cases, the false-positive rate stayed 0.0357.
- The interpreters whose entry script is read are the sorted list `bash`, `bun`, `dash`, `deno`, `node`, `nodejs`, `python`, `python3`, `sh`, `ts-node`, `tsx`, `zsh`. `deno run` skips the `run` subcommand and then the flags. `tsx watch` skips `watch`. `bun run` skips `run`. `python -m` names a module, not a file, and is `unverified`.
- A bare command that is not trusted, not inline source, and not a readable local script is `unverified`, with a warning. It is not `inspected`. Re-measured on the curated corpus (56 benign, 16 malicious): recall stayed 0.9375, the false-positive rate stayed 0.0357, and no case changed outcome. `TRUSTED_COMMANDS` was not extended.
- `napi-build` is not a trusted command. The package of that name is not on the npm registry. Published `unrs-resolver` 1.13.0 (`https://cdn.jsdelivr.net/npm/unrs-resolver@1.13.0/package.json`, read 2026-11-12) has no `preinstall`, `install`, or `postinstall`. Its `scripts` are `fmt`, `test`, and build tasks. It depends on `napi-postinstall` and calls `napi-postinstall/fallback` from `index.js` when the native binding is missing. That is load time, not an install hook, so Mode 1 does not see it. The `napi-postinstall` bin (`lib/cli.js` of 0.3.7) installs the platform package with `npm` or downloads the tarball from the registry. A command that fetches a binary is not a trusted build step. This supersedes the `napi-build` entry in ADR 012.
- An empty or whitespace-only hook body is `empty`. It is reported, and policy records a note rather than an `install_scripts` violation.

### `bin` and `node_modules/.bin`

npm runs lifecycle scripts with `node_modules/.bin` of the package and of its ancestors prepended to `PATH` ([npm scripts, `path`](https://docs.npmjs.com/cli/v11/using-npm/scripts#path)). npm copies each package's `bin` into the lockfile package descriptor ([package-lock.json](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json)). The field has the same shape as in `package.json`: an object of command name to path, or a string whose command name is the package name. For a scoped name, npm's normalizer keeps the unscoped part (`@mapbox/node-pre-gyp` with a string `bin` installs the command `node-pre-gyp`).

Lockward reads that field and keeps the command spelling from the lockfile. Comparison uses `program_name`, the same function as the hook parser: the basename, ASCII lower case, then one trailing `.cmd`, `.exe`, or `.bat`. Case is folded before the suffix is removed, so `Husky`, `husky.cmd`, and `HUSKY.EXE` are the command `husky`. If any other package declares that command, the scan emits `bin_shadow` and quotes the lockfile spelling. Every hook that uses the normalized bare name is `unverified` instead of `trusted_build`. The real publisher declaring its own command is not a finding. A lockfile with no `bin` field keeps the previous behavior.

Mode 1 still does not follow `node_modules/.bin` symlinks and does not simulate `PATH`. The lockfile declaration is the signal. A bin that npm links without recording it in `packages[].bin` is not seen. That remaining gap is in `docs/LIMITS.md`.

## Rationale

The shell's own rule is the trust boundary: a token with a path separator is a file, and a token without one is a `PATH` lookup. Comparing only the base name inverted that rule. Preload flags and `-c` are the same class of mistake: a value that is executed was not the value that was read. Unknown commands were labeled `inspected`, which is the disposition used for a body that was actually read; callers treated that as "no review required".

`empty` is a separate harmless state. An empty npm script exits successfully and runs nothing. `inspected` would claim a body was read. `unverified` would ask for review of a no-op. Dropping the finding would hide the hook slot.

The interpreter list is the set of programs that appear as the direct runner of an install script outside `node`: Bun and Deno when they are the package manager, `tsx` and `ts-node` as TypeScript replacements for `node`, CPython for native builds, and the four shells whose `-c` flag would otherwise be a bypass of the `sh -c` rule. It is sorted because it is searched with `binary_search`.

## Alternatives

- Keep trusting the base name and ignore path forms. That leaves `./husky` unexamined.
- Resolve `node_modules/.bin` and follow symlinks. That reads the file npm linked, including a legitimate `node-gyp` shim, and marks the hook `unverified` when the shim is a symlink Mode 1 will not follow. The lockfile `bin` field names the publisher without opening the shim.
- Treat every unknown command as `inspected` when the raw text has no heuristic hit. That hides a command the analyzer did not understand.
- Drop empty hooks. The manifest still declares the hook; the report should say so without asking for a review.
