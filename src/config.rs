// SPDX-License-Identifier: GPL-3.0-or-later
//! Runtime configuration, sourced from the environment.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use tracing::warn;

/// All runtime settings. Everything comes from the environment so suho is
/// trivially configurable in a compose file.
#[derive(Debug, Clone)]
pub struct Config {
    /// Container label namespace, e.g. `suho` → `suho.networkpolicy.*`.
    pub label_prefix: String,
    /// File or directory holding the global `policies/suho.yaml` definitions.
    pub policies_path: PathBuf,
    /// Periodic full reconcile interval (safety net against drift / missed events).
    pub resync_interval: Duration,
    /// Quiet period after a Docker event before reconciling (coalesces bursts).
    pub debounce: Duration,
    /// Optional `host:port` for the Prometheus metrics + health server; unset
    /// disables it.
    pub metrics_addr: Option<SocketAddr>,
}

impl Config {
    /// Load configuration from the environment, applying defaults.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            label_prefix: env("SUHO_LABEL_PREFIX", "suho"),
            policies_path: PathBuf::from(env("SUHO_POLICIES_PATH", "/etc/suho/policies")),
            resync_interval: resync_from(env_u64("SUHO_RESYNC_INTERVAL", 30)),
            debounce: Duration::from_millis(env_u64("SUHO_DEBOUNCE_MS", 500)),
            metrics_addr: env_opt_addr("SUHO_METRICS_ADDR"),
        }
    }
}

fn env(key: &str, fallback: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| fallback.to_owned())
}

fn env_u64(key: &str, fallback: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

/// Resync period as a `Duration`, clamped to ≥1s: a zero period panics
/// `tokio::time::interval`, so `SUHO_RESYNC_INTERVAL=0` must never reach it.
fn resync_from(secs: u64) -> Duration {
    Duration::from_secs(secs.max(1))
}

fn env_opt_addr(key: &str) -> Option<SocketAddr> {
    let raw = std::env::var(key).ok()?;
    match raw.parse() {
        Ok(addr) => Some(addr),
        Err(err) => {
            warn!(%key, value = %raw, %err, "ignoring invalid metrics address");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resync_never_zero() {
        assert_eq!(resync_from(0), Duration::from_secs(1));
        assert_eq!(resync_from(30), Duration::from_secs(30));
    }
}
