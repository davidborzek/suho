## What & why

<!-- What does this change, and why? Link any issue it closes. -->

## Checks

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --all-targets -- -D warnings`
- [ ] `cargo test`
- [ ] `cargo deny check`
- [ ] Docs updated (README / `docs/`) if behaviour changed
- [ ] Schema regenerated (`cargo run -- schema > schemas/network-policies.v1alpha1.json`) if policy types changed
- [ ] Enforcement changes exercised (`cargo test -- --ignored` — rootless netns e2e)

<!-- Contributions are licensed under GPL-3.0-or-later. -->
