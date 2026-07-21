---
name: Bug report
about: Something isn't working
labels: bug
---

<!-- For security issues, DO NOT open an issue — use the Security tab. -->

## What happened

A clear description of the bug, and what you expected instead.

## Reproduction

- suho version / commit:
- How suho is run (compose snippet or `docker run`, `--dry-run`?):
- Relevant `suho.networkpolicy.*` labels / `policies/suho.yaml`:
- The resolved ruleset if you have it (`--dry-run` log, or `nft list table inet suho`):

## Environment

- OS / kernel:
- Docker version:
- `br_netfilter` / `net.bridge.bridge-nf-call-iptables` enabled?
- IPv4, IPv6, or dual-stack:

## Logs

```
(suho log output, RUST_LOG=debug if possible)
```
