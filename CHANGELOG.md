# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/).

## [0.1.1](https://github.com/davidborzek/suho/compare/v0.1.0...v0.1.1) (2026-08-16)


### Bug Fixes

* **nft:** force a large netlink receive buffer to avoid ENOBUFS ([#2](https://github.com/davidborzek/suho/issues/2)) ([41550c6](https://github.com/davidborzek/suho/commit/41550c60fcf5857fefbd60b23a3aa80351f2cc06))
## 0.1.0 (2026-07-22)

Initial release.

### Features

* Kubernetes-`NetworkPolicy`-style policy model: per-container
  `suho.networkpolicy.<name>` labels and label-selected globals in
  `policies/suho.yaml`, with `endpointSelector`, `policyTypes`, and additive
  ingress/egress rules.
* Peer matchers: `selector` (labels), `container` (Docker name), `network`
  (Docker network), and `cidr` with `ipBlock.except`. `container`/`network`/
  `selector` combine with AND within one peer (intersection).
* Port ranges (`"32000-32768/tcp"`) alongside single/all ports.
* **IPv6 dual-stack** enforcement (IPv4 and IPv6 side by side).
* nftables backend over netlink (no `nft` binary); stateless reconcile that
  atomically replaces suho's own `inet suho` table each run.
* Observability: opt-in Prometheus `/metrics` plus `/healthz` and `/readyz`
  (`SUHO_METRICS_ADDR`).
* Fail-closed startup: exit non-zero if the initial reconcile cannot establish
  enforcement.
* CLI subcommands: `suho schema` (JSON Schema), `suho validate` (offline policy
  check), and `suho status` (governed containers + resolved ruleset); plus
  `--help`, `--version`, and `--dry-run` on the daemon.
* Stateful enforcement: reply traffic of established/related connections is
  accepted up front, so bidirectional flows work even when both ends are
  isolated (Kubernetes-like conntrack semantics).
