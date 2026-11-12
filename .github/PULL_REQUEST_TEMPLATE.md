## Summary

<!-- What changed, and why. Link the ADR if this is a design decision. -->

## Test plan

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo nextest run --locked`
- [ ] `cargo deny check`
- [ ] `cargo audit`
- [ ] `cargo run --locked -p lockward-eval`
- [ ] Tests cover the change, including the edge this PR touches
- [ ] An ADR is added or updated if this PR makes a design decision
- [ ] `CHANGELOG.md` has an `Unreleased` note for a user-visible change
