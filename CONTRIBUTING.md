# Contributing to suho

Thanks for your interest! suho is a small, focused nftables network-policy
controller for Docker. Bug reports, docs, and code are all welcome.

## Getting started

Building compiles `rustables`, whose build script runs `bindgen`, so you need
`clang` plus the kernel UAPI headers:

- Arch: `clang` + `linux-api-headers`
- Debian/Ubuntu: `clang libclang-dev linux-libc-dev`

```sh
cargo build
cargo test
```

Enforcing against the real kernel needs root (`CAP_NET_ADMIN`). Without it, use
`--dry-run`, which resolves policy and logs the ruleset without touching nftables.

## Before you open a PR

Run the same checks CI does:

```sh
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo build --locked
cargo test --locked
cargo deny check
```

If you change enforcement behaviour, run the sandboxed end-to-end tests — they
program suho's ruleset into a throwaway, rootless namespace and verify the kernel
accepts it, plus a routed veth topology that checks real drop/allow and stateful
reply traffic (no root needed):

```sh
cargo test -- --ignored
```

Regenerate the committed JSON Schema if you change the policy types:

```sh
cargo run -- schema > schemas/network-policies.v1alpha1.json
```

## Conventions

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/)
  (`feat:`, `fix:`, `refactor:`, `docs:`, `ci:`), with the *why* in the body.
- Keep changes focused; match the surrounding style (`rustfmt`, no `unsafe`).
- Prefer updating existing files over adding new ones; update docs and tests
  alongside behaviour changes.

## Design

See [`docs/architecture.md`](docs/architecture.md) for how suho works and
[`docs/network-policies.md`](docs/network-policies.md) for the policy model.

## License

By contributing, you agree that your contributions are licensed under the
**GNU General Public License v3.0 or later**, the same as the project.
