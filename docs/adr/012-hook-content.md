# ADR 012 — Hook content instead of hook existence

## Context

The measurement after ADR 011 brought the curated package allowlist to a 0% false-positive rate and left the held-out long tail at 12/12 false positives. Every one of those cases fired only `install_scripts`. `node build.js` and `node-gyp rebuild` look the same until the referenced file is read. That left `ua-parser-js-staged` as a finding only because a hook existed.

## Decision

- An install hook is split into commands. `node-gyp`, `node-gyp-build`, `node-pre-gyp`, `@mapbox/node-pre-gyp`, `prebuild-install`, `prebuildify`, `cmake-js`, `husky`, `patch-package`, and `napi-build` (the same native build driver as `node-gyp-build`) are trusted commands. When the hook consists only of those, it is a note, not a finding. The list is attached to the program name, not the package name.
- `node <file>`, `sh`/`bash <file>`, `./<file>`, and one level of `npm run <script>` are read statically: at most eight files, at most 1 MiB, no symlink, no `..`, no absolute path, and the path must stay inside the project root. `require()` is not followed. Nothing is executed.
- Content that was read, or that is visible inline, runs through the existing heuristics. Clean content is a note. `curl|sh`, obfuscation, secret paths, and network stay the findings.
- `install_scripts` is no longer a gate fail. A violation exists only when a referenced target cannot be read. The action is review.
- Known downloaders (`puppeteer`, `puppeteer-core`, `playwright`, `playwright-core`, `cypress`, `electron`, `chromedriver`, `geckodriver`, `node-sass`, `sass-embedded`) suppress `LW-H003`. `LW-H004` stays a finding. The list is a finite category, not a place to file corpus hits. An unknown downloader stays flagged.

## Rationale

The long tail of native modules calls the same build tools. The command generalizes. The package name does not. A staged downloader becomes visible once `build.js` is read. Network access without an entry on the downloader list stays a finding, because a legitimate download and a malicious download cannot be separated reliably from the text.

## Alternatives

- Keep treating every unknown install script as a finding: holds `ua-parser-js-staged` only through the existence of the hook and leaves the held-out long tail red.
- Silently allow unknown network access for downloaders: lowers the residual false positives and loses malicious downloads under an unknown name.
- Follow `require()` graphs: leaves the bounded static read depth and grows the false-positive surface.
