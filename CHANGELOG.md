# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to
follow [Semantic Versioning](https://semver.org/).

## [0.3.0](https://github.com/davidborzek/suho/compare/v0.2.0...v0.3.0) (2026-09-19)


### Features

* **policy:** explicit deny rules with per-rule flow-log opt-out ([#10](https://github.com/davidborzek/suho/issues/10)) ([ae7aa84](https://github.com/davidborzek/suho/commit/ae7aa843b0e986e0d258edd8095125acf29bc224)), closes [#7](https://github.com/davidborzek/suho/issues/7)


### Bug Fixes

* **nft:** force a large netlink send buffer to avoid EMSGSIZE ([#8](https://github.com/davidborzek/suho/issues/8)) ([0286cd4](https://github.com/davidborzek/suho/commit/0286cd433214142904e6d3cabc533e7ec6d73372))

## [0.2.0](https://github.com/davidborzek/suho/compare/v0.1.1...v0.2.0) (2026-08-16)


### Features

* **flowlog:** add event timestamp and per-flow dedup window ([8addac5](https://github.com/davidborzek/suho/commit/8addac50f5f9758e1026d2c6001ff9b4c73f707b))
* NFLOG-based flow log with pluggable sink ([#5](https://github.com/davidborzek/suho/issues/5)) ([97d0f31](https://github.com/davidborzek/suho/commit/97d0f31ce4ea9214b65b6ba1ce2054bf61e494d6))


### Bug Fixes

* **flowlog:** use nfnetlink subsystem 4 (ULOG) for NFLOG ([71245d3](https://github.com/davidborzek/suho/commit/71245d3ec0e1d64de0e443ea65d8365e93c086a3))


### Performance Improvements

* **flowlog:** cap NFLOG copy_range to 256 bytes (headers only) ([058c3c2](https://github.com/davidborzek/suho/commit/058c3c2b93d7f4d19a6d011250ea12afee73a71f))

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
