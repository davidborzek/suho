# Metrics & health

suho exposes Prometheus metrics and health endpoints from a small built-in HTTP
server. It is **opt-in**: set `SUHO_METRICS_ADDR` to a `host:port` (e.g.
`127.0.0.1:9090`). Unset, no server is started.

Bind it to loopback or a private interface — suho runs in the host network
namespace, so `0.0.0.0` exposes it on every host IP.

## Endpoints

| Path | Purpose |
|---|---|
| `GET /metrics` | Prometheus/OpenMetrics exposition (`application/openmetrics-text`). |
| `GET /healthz` | Liveness — `200` while the process runs. |
| `GET /readyz` | Readiness — `200` after the first successful reconcile, else `503`. |

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `suho_build_info` | gauge | `version` | Constant `1`; exposes the build version. |
| `suho_reconciles_total` | counter | `trigger`, `result` | Reconciles attempted. `trigger` = `startup`\|`event`\|`resync`; `result` = `success`\|`error`. |
| `suho_reconcile_duration_seconds` | histogram | — | Reconcile wall-clock time (`_bucket`/`_sum`/`_count`). |
| `suho_last_reconcile_success_timestamp_seconds` | gauge | — | Unix time of the last successful reconcile. |
| `suho_rules` | gauge | `chain` | Rules in the last applied ruleset, by `chain` = `egress`\|`ingress`. |
| `suho_sets` | gauge | — | Named nftables sets in the last applied ruleset. |
| `suho_ready` | gauge | — | `1` once at least one reconcile has succeeded, else `0`. |
| `suho_watch_restarts_total` | counter | — | Times the Docker event watcher was re-established (self-heal). |

A failed reconcile increments `suho_reconciles_total{result="error"}` but leaves
`suho_rules`/`suho_sets`/`suho_last_reconcile_success_timestamp_seconds` at their
last-good values — the previous ruleset stays in force (atomic apply).

## Scraping

```yaml
scrape_configs:
  - job_name: suho
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

## Useful queries

```promql
# Enforcement is stale — no successful reconcile in 5 minutes.
time() - suho_last_reconcile_success_timestamp_seconds > 300

# suho has never reconciled successfully since start.
suho_ready == 0

# Reconciles are failing.
rate(suho_reconciles_total{result="error"}[5m]) > 0

# Docker event watcher is flapping (falling back to periodic resync).
rate(suho_watch_restarts_total[15m]) > 0

# Reconcile latency, p95.
histogram_quantile(0.95, rate(suho_reconcile_duration_seconds_bucket[5m]))
```

Good alerts: readiness (`suho_ready == 0`), staleness (the timestamp query above),
and a nonzero error rate. `suho_watch_restarts_total` flapping usually points at
Docker API instability, not suho itself.

## Dashboards & alerts

Ready-to-use monitoring lives in [`../dashboards/`](../dashboards/):

- [`grafana-dashboard.json`](../dashboards/grafana-dashboard.json) — import into
  Grafana (pick your Prometheus data source); panels for readiness, reconcile
  rate by result, duration p50/p95, rules by chain, sets, and watcher restarts.
- [`prometheus-alerts.yaml`](../dashboards/prometheus-alerts.yaml) — alerting
  rules (not-ready, stale enforcement, reconcile errors, watcher flapping);
  reference it from `rule_files` in `prometheus.yml`.
