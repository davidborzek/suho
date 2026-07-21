# suho example

Runs suho and two labelled workloads (`web`, `db`) showing inline egress and
ingress policies, label-based identity, file-based and co-located global policies, and
opt-in labels — all enforced with real nftables.

## Run

```sh
docker compose up --build
```

This builds the suho image, starts suho in the host network namespace with
`CAP_NET_ADMIN`, and applies the policies. suho's log prints the resolved
ruleset on every reconcile.

> **Requires** `br_netfilter` for the container-to-container/ingress parts:
> `modprobe br_netfilter && sysctl -w net.bridge.bridge-nf-call-iptables=1`.
> suho warns at startup if it is off. On a firewalld host this also exposes
> bridged traffic to firewalld's forward policy.

## What it demonstrates

- **`web`** has an inline **egress** policy allowing HTTPS to
  the internet, and opts into two additive policies via labels: `tier: frontend`
  and `db-client: "true"`.
- **`db`** listens on 5432, has an inline **ingress** policy
  accepting `db-client`s on 5432 (a `selector` on the same opt-in label), and
  **co-locates a policy** `db-clients` (`suho.networkpolicy.db-clients` with an
  `endpointSelector`) — like a per-service CiliumClusterwideNetworkPolicy —
  letting any container labelled `db-client: "true"` egress to it on 5432.
- **`policies/suho.yaml`** adds a file-based global `frontend-dns` (DNS egress
  for `tier: frontend`).

So `web`'s effective egress is the **union**: HTTPS (inline) + db:5432
(`db-clients` global) + DNS (`frontend-dns` global); everything else is denied.
`web → db:5432` passes only because **both** web's egress and db's ingress allow
it (Kubernetes dual-check).

## Verify

```sh
# allowed: web -> db:5432 (egress via db-clients, ingress via db's rule) -> "ok"
docker compose exec web sh -c 'echo | nc -w2 db 5432'

# denied: web -> db:9999 (no rule) — times out
docker compose exec web sh -c 'nc -w2 db 9999'; echo "exit=$?"

# allowed: web -> HTTPS 443
docker compose exec web wget -qO- --timeout 3 https://1.1.1.1 >/dev/null && echo OK
# denied: web -> HTTP 80 (not in the policy) — times out
docker compose exec web wget -qO- --timeout 3 http://1.1.1.1; echo "exit=$?"
```

Inspect the programmed ruleset (suho owns only the `inet suho` table):

```sh
sudo nft list table inet suho
```

## Tear down

```sh
docker compose down
sudo nft delete table inet suho   # suho leaves its table in place on stop
```
