// SPDX-License-Identifier: GPL-3.0-or-later
//! Observability: Prometheus metrics and health endpoints, served with axum.
//! Opt in with `SUHO_METRICS_ADDR` (e.g. `127.0.0.1:9090`).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::routing::get;
use prometheus_client::encoding::{EncodeLabelSet, text::encode};
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use tracing::{error, info};

/// What triggered a reconcile (a `suho_reconciles_total` label value).
#[derive(Clone, Copy)]
pub enum Trigger {
    Startup,
    Event,
    Resync,
}

impl Trigger {
    fn as_str(self) -> &'static str {
        match self {
            Self::Startup => "startup",
            Self::Event => "event",
            Self::Resync => "resync",
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReconcileLabels {
    trigger: &'static str,
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ChainLabels {
    chain: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BuildLabels {
    version: &'static str,
}

/// Reconcile metrics, updated by the reconcile loop and exposed at `/metrics`.
pub struct Metrics {
    registry: Registry,
    reconciles: Family<ReconcileLabels, Counter>,
    duration: Histogram,
    last_success: Gauge,
    rules: Family<ChainLabels, Gauge>,
    sets: Gauge,
    ready: Gauge,
    watch_restarts: Counter,
}

impl Default for Metrics {
    fn default() -> Self {
        let reconciles = Family::<ReconcileLabels, Counter>::default();
        let duration = Histogram::new(
            [
                0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0,
            ]
            .into_iter(),
        );
        let last_success = Gauge::default();
        let rules = Family::<ChainLabels, Gauge>::default();
        let sets = Gauge::default();
        let ready = Gauge::default();
        let watch_restarts = Counter::default();

        // Build info: a constant `1` carrying the version as a label.
        let build = Family::<BuildLabels, Gauge>::default();
        build
            .get_or_create(&BuildLabels {
                version: env!("CARGO_PKG_VERSION"),
            })
            .set(1);

        let mut registry = Registry::default();
        registry.register("suho_build_info", "Build information", build);
        registry.register(
            "suho_reconciles",
            "Reconciles attempted",
            reconciles.clone(),
        );
        registry.register(
            "suho_reconcile_duration_seconds",
            "Reconcile duration",
            duration.clone(),
        );
        registry.register(
            "suho_last_reconcile_success_timestamp_seconds",
            "Unix time of the last successful reconcile",
            last_success.clone(),
        );
        registry.register(
            "suho_rules",
            "Rules in the last applied ruleset",
            rules.clone(),
        );
        registry.register(
            "suho_sets",
            "Named sets in the last applied ruleset",
            sets.clone(),
        );
        registry.register(
            "suho_ready",
            "Whether at least one reconcile has succeeded",
            ready.clone(),
        );
        registry.register(
            "suho_watch_restarts",
            "Docker event watcher re-establishments",
            watch_restarts.clone(),
        );

        Self {
            registry,
            reconciles,
            duration,
            last_success,
            rules,
            sets,
            ready,
            watch_restarts,
        }
    }
}

impl Metrics {
    /// Record a completed reconcile: `outcome` is `Some((egress, ingress, sets))`
    /// counts on success, `None` on failure.
    pub fn record(
        &self,
        trigger: Trigger,
        elapsed: Duration,
        outcome: Option<(usize, usize, usize)>,
    ) {
        let result = if outcome.is_some() {
            "success"
        } else {
            "error"
        };
        self.reconciles
            .get_or_create(&ReconcileLabels {
                trigger: trigger.as_str(),
                result,
            })
            .inc();
        self.duration.observe(elapsed.as_secs_f64());
        if let Some((egress, ingress, sets)) = outcome {
            self.rules
                .get_or_create(&ChainLabels { chain: "egress" })
                .set(clamp(egress));
            self.rules
                .get_or_create(&ChainLabels { chain: "ingress" })
                .set(clamp(ingress));
            self.sets.set(clamp(sets));
            self.last_success.set(clamp_u64(unix_now()));
            self.ready.set(1);
        }
    }

    /// Count a re-established Docker event watcher (self-heal).
    pub fn watch_restarted(&self) {
        self.watch_restarts.inc();
    }

    /// Whether at least one reconcile has succeeded.
    fn ready(&self) -> bool {
        self.ready.get() == 1
    }

    /// Render the OpenMetrics/Prometheus text exposition format.
    fn render(&self) -> String {
        let mut buf = String::new();
        encode(&mut buf, &self.registry).expect("encoding metrics into a String cannot fail");
        buf
    }
}

fn clamp(v: usize) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn clamp_u64(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Spawn the metrics/health HTTP server on `addr`: `GET /metrics` (Prometheus),
/// `/healthz` (liveness) and `/readyz` (200 after the first successful
/// reconcile). Best-effort: a bind failure is logged, not fatal.
pub fn serve(addr: SocketAddr, metrics: Arc<Metrics>) {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/healthz", get(async || "ok\n"))
        .route("/readyz", get(readyz_handler))
        .with_state(metrics);
    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(listener) => listener,
            Err(err) => {
                error!(%addr, %err, "metrics server: bind failed");
                return;
            }
        };
        info!(%addr, "metrics/health server listening");
        if let Err(err) = axum::serve(listener, app).await {
            error!(%err, "metrics server stopped");
        }
    });
}

async fn metrics_handler(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    (
        [(
            header::CONTENT_TYPE,
            "application/openmetrics-text; version=1.0.0; charset=utf-8",
        )],
        metrics.render(),
    )
}

async fn readyz_handler(State(metrics): State<Arc<Metrics>>) -> impl IntoResponse {
    if metrics.ready() {
        (axum::http::StatusCode::OK, "ok\n")
    } else {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_render_and_ready() {
        let m = Metrics::default();
        assert!(!m.ready());
        m.record(Trigger::Startup, Duration::from_millis(5), None);
        assert!(!m.ready());
        m.record(Trigger::Event, Duration::from_millis(7), Some((3, 2, 1)));
        assert!(m.ready());
        m.watch_restarted();

        let out = m.render();
        assert!(
            out.contains(r#"suho_reconciles_total{trigger="startup",result="error"} 1"#),
            "{out}"
        );
        assert!(
            out.contains(r#"suho_reconciles_total{trigger="event",result="success"} 1"#),
            "{out}"
        );
        assert!(out.contains(r#"suho_rules{chain="egress"} 3"#), "{out}");
        assert!(out.contains(r#"suho_rules{chain="ingress"} 2"#), "{out}");
        assert!(out.contains("suho_sets 1"), "{out}");
        assert!(out.contains("suho_ready 1"), "{out}");
        assert!(out.contains("suho_watch_restarts_total 1"), "{out}");
        assert!(
            out.contains("suho_reconcile_duration_seconds_count 2"),
            "{out}"
        );
        assert!(out.contains("suho_build_info{version="), "{out}");
    }
}
