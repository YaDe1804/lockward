# Lockward GitHub Action

Composite action for the static npm scan. It runs `lockward scan`, appends the short summary to the GitHub step summary, and can post the pull-request comment from `comment.md`. The action exit code is the gate code: `0` OK, `1` Warning, `2` Fail.

The action expects a built binary. It does not download a release while none is published.

## Example

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
  - uses: dtolnay/rust-toolchain@686976e191b89faba57d3206551f0f330d8cb249 # stable
  - run: cargo build --release -p lockward-cli
  - uses: ./.github/actions/lockward
    with:
      path: .
      mode: warn
      lockward-bin: target/release/lockward
```

`comment: "false"` skips the pull-request comment. `offline: "true"` reads only the advisory cache.

## Marketplace

`action.yml` is the manifest (name, description, inputs, outputs, branding). Publishing to the Marketplace needs a public repository and a tag. That is a manual step and does not run in this nightly job.
