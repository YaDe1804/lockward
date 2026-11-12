# ADR 014 — Hook arguments and trust

## Context

ADR 012 trusts a build tool by its file name and reads the first non-flag token after `node`, `sh`, or `bash`. Both rules are bypasses:

- `./husky` is trusted, because only the base name is compared, so a package can ship a file named after a trusted tool and skip inspection.
- `node --require ./setup.js install.js` reads `./setup.js` and never opens `install.js`.
- `sh -c 'node install.js'` stops at `-c`, so the inner command is not walked.
- `bun install.js` is not an interpreter, so the script is not read.

An empty hook body and an unknown command were both reported as `inspected`, which claims the body was understood.

## Decision

- `TRUSTED_COMMANDS` applies only when `argv[0]` is a bare name: no `/`, no `\`, and no Windows drive prefix. Any other form is a local path and is read under the existing rules (no symlink, no `..`, no absolute path, at most eight files, at most 1 MiB, path must stay inside the project root). `@mapbox/node-pre-gyp` contains a slash, so the shell does not search `PATH` for it; it is a relative path. The bare bin name `node-pre-gyp` stays trusted.
- Node arguments follow the Node.js v26.5.1 command-line API (<https://nodejs.org/api/cli.html>, retrieved 2026-11-12). Options that take a value are consumed both as `--opt value` and as `--opt=value`. `--loader` is included because that page documents it as the previous name of `--experimental-loader`. Optional inspector flags (`--inspect`, `--inspect-brk`, `--inspect-wait`) do not consume the next token. `--experimental-config-file` accepts only the `=` form. The entry script is the first positional argument. Tokens after it belong to the script. `-e`/`--eval` and `-p`/`--print` are inline source: the text stays in the hook body and is what the heuristics scan. There is no separate entry script in that case.
- Path-like preload values are read as well, because Node executes them before the entry script: `-r`/`--require`, `--import`, `--loader`/`--experimental-loader`, and `--test-global-setup`. A bare module name (`--require esm`) is not resolved. That is the same limit as not following `require()`. A path-like preload that cannot be read makes the hook `unverified`.
- `sh -c`, `bash -c`, `zsh -c`, and `dash -c` (including a short cluster such as `-lc`) are parsed again with `walk_script`, up to three levels. The fourth level is `unverified`. File reads still share `MAX_REFERENCED_SCRIPTS`. Inline source for other interpreters (`node -e`, `python -c`, `bun -e`, `deno eval`) is not walked as a shell. The hook body already contains that text, so the heuristics see it.
- The interpreters whose entry script is read are the sorted list `bash`, `bun`, `dash`, `deno`, `node`, `nodejs`, `python`, `python3`, `sh`, `ts-node`, `tsx`, `zsh`. `deno run` skips the `run` subcommand and then the flags. `tsx watch` skips `watch`. `bun run` skips `run`. `python -m` names a module, not a file, and is `unverified`.
- A bare command that is not trusted, not inline source, and not a readable local script is `unverified`, with a warning. It is not `inspected`. Re-measured on the curated corpus (56 benign, 16 malicious): recall stayed 0.9375, the false-positive rate stayed 0.0357, and no case changed outcome. `TRUSTED_COMMANDS` was not extended.
- An empty or whitespace-only hook body is `empty`. It is reported, and policy records a note rather than an `install_scripts` violation.

### `bin` and `node_modules/.bin`

npm runs lifecycle scripts with `node_modules/.bin` of the package and of its ancestors prepended to `PATH` ([npm scripts, `path`](https://docs.npmjs.com/cli/v11/using-npm/scripts#path)).

- A dependency can shadow a trusted bare name. Its `bin` entry is linked into `node_modules/.bin`, and that directory is searched first. npm creates those links as symlinks (Windows shims are generated separately). Mode 1 does not follow symlinks. Treating an existing shim as the command to read would therefore fail the read and mark ordinary `node-gyp rebuild` hooks `unverified` once the real tool is installed. That raises the false-positive rate. This change does not do it.
- The package's own `bin` field is linked into the *parent* `node_modules/.bin`, not into the package's own `.bin`. After npm has linked bins, that parent directory is also on `PATH`. The package can shadow a trusted name when no dependency publishes the same bin. The target is a regular file inside the package and could be read without following a symlink.

Decision: bare trusted names stay trusted. Path forms are read. `PATH` is not simulated. Own-`bin` shadowing is a residual risk, recorded in `docs/LIMITS.md`, not an extension of `TRUSTED_COMMANDS`. The bypass closed here is a path-form `argv[0]`, which the shell never resolves through `PATH`.

## Rationale

The shell's own rule is the trust boundary: a token with a path separator is a file, and a token without one is a `PATH` lookup. Comparing only the base name inverted that rule. Preload flags and `-c` are the same class of mistake: a value that is executed was not the value that was read. Unknown commands were labeled `inspected`, which is the disposition used for a body that was actually read; callers treated that as "no review required".

`empty` is a separate harmless state. An empty npm script exits successfully and runs nothing. `inspected` would claim a body was read. `unverified` would ask for review of a no-op. Dropping the finding would hide the hook slot.

The interpreter list is the set of programs that appear as the direct runner of an install script outside `node`: Bun and Deno when they are the package manager, `tsx` and `ts-node` as TypeScript replacements for `node`, CPython for native builds, and the four shells whose `-c` flag would otherwise be a bypass of the `sh -c` rule. It is sorted because it is searched with `binary_search`.

## Alternatives

- Keep trusting the base name and ignore path forms. That leaves `./husky` unexamined.
- Resolve `node_modules/.bin` and follow symlinks when the target stays inside the project. That closes dependency shadowing and flags legitimate native builds that depend on `node-gyp`. The corpus false-positive rate is the reason not to do it here.
- Treat every unknown command as `inspected` when the raw text has no heuristic hit. That hides a command the analyzer did not understand.
- Drop empty hooks. The manifest still declares the hook; the report should say so without asking for a review.
