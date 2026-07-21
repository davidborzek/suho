# Deployment

suho runs as a single container in the **host network namespace** with
`CAP_NET_ADMIN`, reading the Docker API and programming the host's nftables. This
guide covers a production-style deployment, socket hardening, and troubleshooting.

## Docker Compose (recommended)

```yaml
name: suho

services:
  suho:
    image: ghcr.io/davidborzek/suho:latest
    network_mode: host          # rules must sit in the host forward hook
    cap_drop: [ALL]
    cap_add: [NET_ADMIN]
    read_only: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./policies:/etc/suho/policies:ro
    environment:
      SUHO_POLICIES_PATH: /etc/suho/policies
      SUHO_METRICS_ADDR: "127.0.0.1:9090"   # optional: /metrics, /healthz, /readyz
      RUST_LOG: info
    restart: unless-stopped
```

Put your host-wide policies in `./policies/suho.yaml` (see
[network-policies.md](network-policies.md)); per-container policies are labels on
the workloads themselves.

### br_netfilter prerequisite

Container-to-container and ingress enforcement only works when bridged traffic
traverses the forward hook. Enable it on the host (persist via
`/etc/modules-load.d` and `/etc/sysctl.d`):

```sh
modprobe br_netfilter
sysctl -w net.bridge.bridge-nf-call-iptables=1
```

suho warns at startup if it is off. Routed egress to the internet is enforced
either way.

## Hardening the Docker socket

Mounting `docker.sock` read-only still exposes the full read API. To narrow it,
run a read-only socket proxy and point suho at it instead — suho honours
`DOCKER_HOST`:

```yaml
  docker-proxy:
    image: ghcr.io/tecnativa/docker-socket-proxy:latest
    environment:
      CONTAINERS: 1     # list + inspect
      EVENTS: 1         # lifecycle stream
      POST: 0           # read-only
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    # expose only to suho, e.g. on a private network

  suho:
    # …as above, but drop the docker.sock mount and set:
    environment:
      DOCKER_HOST: tcp://docker-proxy:2375
```

suho needs only `CONTAINERS` (list + inspect) and `EVENTS`.

## Observability

With `SUHO_METRICS_ADDR` set, scrape `GET /metrics` (Prometheus) and wire
`/healthz` (liveness) and `/readyz` (readiness) into your monitoring. Bind it to
`127.0.0.1` or a private interface — suho is in the host netns, so `0.0.0.0`
exposes it on every host IP.

## firewalld / nftables coexistence

suho owns exactly one nftables table (`inet suho`) and never touches others. On a
firewalld host, enabling `br_netfilter` also exposes bridged traffic to
firewalld's forward policy; suho's `drop` verdicts are terminal, but a
restrictive firewalld forward policy can additionally block traffic suho allows.
Reconcile the two if you run both.

## Troubleshooting

- **No rules applied / everything allowed** — the target containers carry no
  `suho.networkpolicy.*` labels and match no global; suho only isolates
  containers a policy selects. Check `suho --dry-run` output or
  `nft list table inet suho`.
- **Container-to-container not enforced** — `br_netfilter` is off (see above).
- **suho exits immediately (non-zero)** — the initial reconcile failed
  (fail-closed): usually missing `CAP_NET_ADMIN`, an unreachable Docker API, or
  an nftables conflict. Check the log; validate policy with `--dry-run` (no root
  needed).
- **Inspecting the live ruleset** — `nft list table inet suho`.
