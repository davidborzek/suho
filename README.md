# suho

**Label-driven L3/L4 network-policy controller for plain Docker / Compose.**

*“suho” (수호) is Korean for “protection / guardianship” — the daemon guards which containers may talk to each other.*

[![CI](https://github.com/davidborzek/suho/actions/workflows/ci.yaml/badge.svg)](https://github.com/davidborzek/suho/actions/workflows/ci.yaml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPLv3-blue.svg)](LICENSE)

suho recreates Kubernetes `NetworkPolicy` / `CiliumClusterwideNetworkPolicy`
semantics on a single Docker host: container labels (and a global
`policies/suho.yaml`) declare which containers may talk to each other and to the
internet, and suho enforces that with nftables. It is a host-level daemon for
single-node Docker / Compose setups that want Kubernetes-style network policy
without Kubernetes.

> **Status:** egress and ingress enforcement work. Config, policy parsing, the
> Docker source, the event-driven reconcile loop and the nftables backend are
> wired end to end: a container's egress and ingress policies are default-deny
> with only matched traffic passing (Kubernetes dual-check via two stage chains),
> keyed on labels, Docker networks and CIDRs (IPv4 and IPv6) — not volatile IPs.
> Prometheus metrics and health endpoints are built in; `--dry-run` logs the
> resolved ruleset instead of programming nftables.

> [!WARNING]
> **Early-stage software.** suho is fresh and pre-1.0 — expect rough edges, and
> review the resolved ruleset (`--dry-run` or `suho status`) before you rely on
> it. The policy API is **`v1alpha1`** and may still change, though large shifts
> are unlikely since it mirrors the established Kubernetes `NetworkPolicy` model.

## How it works

Container IPs churn, so policy references **identity** — a container's labels, a
Docker network, a CIDR, or a container name — never IPs. Every reconcile rebuilds
suho's single `inet suho` nftables table from the current Docker snapshot plus
`policies/suho.yaml` and atomically replaces it, so stopped containers leave no
orphan rules. Enforcement mirrors Kubernetes: a direction is default-deny only
once a policy selects that container for it, and a flow is allowed only if
**both** the source's egress and the destination's ingress permit it.

See [`docs/architecture.md`](docs/architecture.md) for the full design.

## Quickstart

Run suho in the host network namespace with `CAP_NET_ADMIN`, the Docker socket
read-only, and your global policies mounted:

```sh
docker run --network host --cap-drop ALL --cap-add NET_ADMIN --read-only \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v ./policies:/etc/suho/policies:ro -e SUHO_POLICIES_PATH=/etc/suho/policies \
  suho        # build from source — see examples/docker-compose.yml
```

Then label a container with a policy (default-deny that direction, allow only
what you list):

```yaml
labels:
  suho.networkpolicy.default: |
    policyTypes: [Ingress, Egress]
    ingress:
      - from: [{selector: {com.docker.compose.service: proxy}}]
        ports: ["8080/tcp"]
    egress:
      - to: [{cidr: 0.0.0.0/0, except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]}]
        ports: ["443/tcp"]
```

`examples/` has a runnable Compose setup with inline, co-located, and file-based
global policies. To enforce container-to-container and ingress traffic, bridged
packets must traverse the forward hook — enable `br_netfilter`:
`sysctl -w net.bridge.bridge-nf-call-iptables=1` (suho warns at startup if it is
off).

## Documentation

- [`docs/network-policies.md`](docs/network-policies.md) — the policy guide:
  isolation model, the networkpolicy label, selectors, peers, ports, default
  policies, and host-wide globals (modelled on the Kubernetes NetworkPolicy docs).
- [`docs/architecture.md`](docs/architecture.md) — architecture, enforcement
  model, stack, and open questions.
- [`docs/deployment.md`](docs/deployment.md) — production deployment, socket
  hardening, observability, and troubleshooting.
- [`docs/metrics.md`](docs/metrics.md) — Prometheus metrics, health endpoints,
  and example scrape config + alerts.
- [`examples/`](examples/) — a runnable Compose example.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets -- -D warnings
cargo build
cargo test
```

Building compiles `rustables`, which runs `bindgen`: install `clang` plus the
kernel UAPI headers (`linux-api-headers` on Arch, `linux-libc-dev` on
Debian/Ubuntu). Enforcing against the kernel needs root (`CAP_NET_ADMIN`);
without it use `--dry-run`. A rootless, sandboxed end-to-end test programs a
representative dual-stack ruleset into a throwaway user+network namespace — run
it with `cargo test -- --ignored`.

Runtime config is via environment variables — `SUHO_LABEL_PREFIX`,
`SUHO_POLICIES_PATH`, `SUHO_RESYNC_INTERVAL` (periodic full-reconcile safety net),
`SUHO_DEBOUNCE_MS` (quiet window after a Docker event) and `SUHO_METRICS_ADDR`
(`host:port` exposing Prometheus `/metrics`, `/healthz` and `/readyz`) — plus the
`--dry-run` flag, which logs the resolved ruleset and applies nothing.

`suho schema` prints the JSON Schema (v1alpha1) for `policies/suho.yaml`
(committed at `schemas/network-policies.v1alpha1.json` for editor `$schema`
validation). `suho validate [path]` checks a policies file offline, and
`suho status` shows the governed containers and resolved ruleset.

## Contributing & security

Contributions welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md) and the
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Report vulnerabilities privately via
the Security tab, not a public issue (see [`SECURITY.md`](SECURITY.md)).

## License

[GPL-3.0-or-later](LICENSE) — suho links the GPL-licensed `rustables` nftables
library, so the binary is GPL-3.0-or-later. Copyright (C) 2026 David Borzek.
