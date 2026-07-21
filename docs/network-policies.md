# Network Policies

If you want to control traffic flow at the IP address or port level (OSI layer 3
or 4), suho **network policies** let you specify rules for traffic flow between
your Docker containers, and between containers and the outside world — the same
model as a Kubernetes [`NetworkPolicy`], recreated on a single Docker host with
nftables.

Entities in suho communicate over three kinds of identified endpoints:

- other **containers** (identified by their labels, Docker name, or network)
- **networks** (Docker networks a container is attached to)
- **IP blocks** (CIDR ranges — typically the LAN and the internet)

When a policy references a container, it does so by **label selector, network,
or name** — never by IP, since container IPs change on every recreate. suho
resolves the selection to current addresses fresh on every reconcile.

[`NetworkPolicy`]: https://kubernetes.io/docs/concepts/services-networking/network-policies/

## Prerequisites

Network policies are enforced by the suho daemon. It runs in the host network
namespace with `CAP_NET_ADMIN`, reads the Docker API read-only, and programs a
single `inet suho` nftables table in the `forward` hook:

```sh
docker run --network host --cap-drop ALL --cap-add NET_ADMIN --read-only \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  -v ./policies:/etc/suho/policies:ro -e SUHO_POLICIES_PATH=/etc/suho/policies \
  suho        # build from source — see examples/docker-compose.yml
```

- **Enforcing container-to-container and ingress** requires bridged traffic to
  traverse the forward hook: enable `br_netfilter` with
  `net.bridge.bridge-nf-call-iptables=1`. suho warns at startup if it is off.
  Egress to the internet works without it.
- Use the `--dry-run` flag to log the resolved ruleset without programming
  nftables.

## The two sorts of container isolation

There are two sorts of isolation for a container: isolation for **egress** and
isolation for **ingress**. They concern what connections may be established.

By default, a container is **non-isolated** for both directions: all traffic is
allowed (suho programs nothing for it). A container becomes isolated for a
direction as soon as a policy that lists that direction in `policyTypes` selects
it. Once isolated for a direction, the only allowed connections are those in the
**union** of the rules that apply to it — everything else is dropped
(default-deny). Policies are additive: they never conflict, so the order of
evaluation does not affect the outcome.

For a connection from a source container to a destination container to be
allowed, **both** the source's egress policy and the destination's ingress
policy must allow it (a dual check, exactly like Kubernetes). If either side
denies it, the connection is dropped.

Matching is **stateful** (connection-tracked): once a connection's first packet
clears the dual check, its reply traffic is allowed automatically — you only
write policy for the direction that *initiates* a connection, exactly like
Kubernetes.

## The NetworkPolicy label

A container declares policies through labels. Each `suho.networkpolicy.<name>`
label carries a YAML network-policy document (the label prefix is configurable
via `SUHO_LABEL_PREFIX`, default `suho`):

```yaml
labels:
  # A container's identity is just its labels — its Compose service
  # (com.docker.compose.service), a custom label, or its container name.
  suho.networkpolicy.default: |
    policyTypes: [Ingress, Egress]
    ingress:
      - from:
          - selector:
              com.docker.compose.service: proxy
        ports: ["8080/tcp"]
    egress:
      - to:
          - container: api
          - network: backend
        ports: ["9000/tcp"]
      - to:
          - cidr: 0.0.0.0/0
            except: [10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16]
        ports: ["443/tcp", "80/tcp"]
```

Multiple `suho.networkpolicy.<name>` labels on one container are independent
policies whose allowances add up (≈ several `NetworkPolicy` objects selecting
the same pod).

The document has four fields, all mirroring `NetworkPolicySpec`:

- **`endpointSelector`** — which containers the policy applies to.
- **`policyTypes`** — which directions it governs.
- **`ingress`** — allowed inbound sources + ports.
- **`egress`** — allowed outbound destinations + ports.

### `endpointSelector`

`endpointSelector` (≈ `spec.podSelector`) selects the containers this policy
applies to:

- **Omitted** on an inline `suho.networkpolicy.<name>` label → the policy applies
  to the **container that carries the label** (the implicit self; Docker-idiomatic,
  no cross-container authoring needed).
- **Set** to a label map → the policy applies to **every container whose labels
  match all pairs** — including containers other than the carrier. This lets one
  container ship a policy that governs a whole set (like a per-service
  `CiliumClusterwideNetworkPolicy`).
- **Empty** (`{}`) → applies to **all** containers (a host-wide default).

### `policyTypes`

`policyTypes` is a list containing `Ingress`, `Egress`, or both. It decides which
directions become default-deny for the selected containers:

- Listing a direction makes it **isolated** (default-deny) even if the
  corresponding rule list is empty — that is how you express "deny all" for a
  direction.
- If `policyTypes` is **omitted**, suho infers it: a direction is enforced when
  its rule list is non-empty. (Defining `egress` rules without `policyTypes`
  enforces egress but leaves ingress untouched.)

### `ingress` and `egress`

Each `ingress` rule allows inbound connections matching **any** of its `from`
peers on **any** of its `ports`. Each `egress` rule is the same for outbound `to`
peers. Multiple rules, and multiple peers within a rule, combine as a logical
**OR**; the `ports` on a rule restrict that rule's peers.

An empty peer list (`from: []` / `to: []`) or a rule with no peers means **all
peers** — use it to allow all traffic in that direction (see default policies
below).

#### Peers

Each peer sets one or more matchers. `cidr` (+ `except`) is a standalone address
block; `container`, `network` and `selector` are container-identity filters that
**combine with AND** — set several to match only containers satisfying all:

| Matcher | Meaning | Kubernetes |
|---|---|---|
| `selector: {label: value, …}` | containers whose labels match **all** pairs | `podSelector.matchLabels` |
| `container: <name>` | a single container by its Docker name | — |
| `network: <name>` | every container attached to a Docker network | `namespaceSelector` |
| `cidr: <block>` (+ `except: [<block>, …]`) | an address range, minus optional sub-blocks | `ipBlock` / `ipBlock.except` |
| *(no field)* | any address | empty peer |

Notes:

- **`selector`** is the general tool. Use the `com.docker.compose.service` label
  to select a Compose service (all its replicas), add `com.docker.compose.project`
  to scope to one project, or match any custom label (e.g. `tier: web`). All
  pairs must match (AND).
- **`network`** alone compiles to a named nftables set (`net_<network>`) so the
  rendered ruleset stays readable; `selector`/`container` — or any combination —
  resolve to the matched containers' current addresses.
- **`cidr` + `except`** carves sub-blocks out of a range in one rule — e.g.
  `cidr: 0.0.0.0/0` with `except: [10.0.0.0/8, …]` means "the internet, but not
  the LAN". IPv4 and IPv6 blocks are both accepted (e.g. `::/0`). `except`
  without `cidr` is ignored.
- **Combining** `container`/`network`/`selector` in one peer intersects them —
  e.g. `{network: backend, selector: {tier: db}}` matches only `tier=db`
  containers attached to the `backend` network.

#### Ports

A port is a compact string `"<number>/<proto>"` where `<proto>` is `tcp`
(default) or `udp`:

- `"443/tcp"`, `"53/udp"`, `"80"` — a single port.
- `"32000-32768/tcp"` — an inclusive **range** (≈ Kubernetes `port` + `endPort`).
- `"*/tcp"`, or omit `ports` entirely — all ports (of that protocol, or of any).

## Default policies

By default a container is unrestricted. Program common defaults per container
with `endpointSelector: {}` globals (see below) or per-container labels.

**Deny all ingress** — isolate inbound with no allow rules:

```yaml
suho.networkpolicy.deny-ingress: |
  policyTypes: [Ingress]
```

**Allow all ingress** — a single rule with no peers and no ports:

```yaml
suho.networkpolicy.allow-ingress: |
  policyTypes: [Ingress]
  ingress: [{}]
```

**Deny all egress:**

```yaml
suho.networkpolicy.deny-egress: |
  policyTypes: [Egress]
```

**Allow all egress:**

```yaml
suho.networkpolicy.allow-egress: |
  policyTypes: [Egress]
  egress: [{}]
```

**Deny all ingress and egress** (fully isolate):

```yaml
suho.networkpolicy.deny-all: |
  policyTypes: [Ingress, Egress]
```

## Host-wide (global) policies

Policies that should apply across many containers live in a file rather than on
each container. `policies/suho.yaml` (path via `SUHO_POLICIES_PATH`) is a list of
named policies, each a network-policy document plus a `name` and an
`endpointSelector` that selects which containers it applies to (≈
`CiliumClusterwideNetworkPolicy`):

```yaml
# policies/suho.yaml
- name: egress-world
  endpointSelector: {suho.allow/egress-world: "true"}   # opt-in label
  egress:
    - to: [{cidr: 0.0.0.0/0}]

- name: egress-dns
  endpointSelector: {}                                   # applies to all containers
  egress:
    - to: [{network: services}]
      ports: ["53/udp", "53/tcp"]

- name: egress-deny
  endpointSelector: {suho.allow/egress-deny: "true"}
  policyTypes: [Egress]                                  # default-deny egress class
```

Containers opt into a class with a simple label, alongside their own inline
policy — their effective allowances are the **union** of every policy that
selects them (inline plus global):

```yaml
labels:
  suho.allow/egress-world: "true"        # opt into the global class
  suho.networkpolicy.app: |              # plus an app-specific inline policy
    policyTypes: [Ingress, Egress]
    ingress: [{from: [{container: proxy}], ports: ["8080/tcp"]}]
```

An `endpointSelector: {}` global is the clean way to set host-wide defaults (for
example, letting every container resolve DNS even under a default-deny class).

## What you can't do with suho (at least, not yet)

As of the current release, the following Kubernetes NetworkPolicy features are
**not** implemented:

- **`matchExpressions`** selectors (`In`/`NotIn`/`Exists`/`DoesNotExist`). Only
  equality label maps (`matchLabels`) are supported on `selector` and
  `endpointSelector`.
- **SCTP** — only TCP and UDP.
- **Named ports** — Docker has no container-port naming equivalent; use numbers
  or ranges.
- **Multi-host / overlay** policy — suho governs a single Docker host.

And, as with Kubernetes network policies, suho cannot (by design) force traffic
through a proxy, do node-specific policy, or enforce at layer 7 (HTTP paths) —
that belongs at a reverse proxy such as Traefik.

## Differences from Kubernetes

| Kubernetes | suho |
|---|---|
| `NetworkPolicy` object in a namespace | `suho.networkpolicy.<name>` container label |
| `CiliumClusterwideNetworkPolicy` | named entry in `policies/suho.yaml` |
| `spec.podSelector` | `endpointSelector` (omitted = the carrier itself) |
| `podSelector` peer | `selector` peer |
| `namespaceSelector` peer | `network` peer (a Docker network) |
| `ipBlock` peer | `cidr` (+ `except`) peer |
| — | `container` peer (by Docker name) — suho extension |
| `port` + `endPort` | `"<start>-<end>/<proto>"` |
| Namespaces | Docker networks / label conventions |
| Cluster-wide | single host |

## See also

- [`../README.md`](../README.md) — install and run.
- [`architecture.md`](architecture.md) — architecture, enforcement model, rationale.
- [`../examples/`](../examples/) — a runnable Compose example with inline,
  co-located, and file-based global policies.
