// SPDX-License-Identifier: GPL-3.0-or-later
//! Runtime configuration, sourced from the environment.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use tracing::warn;

/// Flow-log mode: which flows suho asks nftables to NFLOG.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FlowLogMode {
    /// Flow logging is disabled (default).
    #[default]
    Off,
    /// Log dropped flows.
    Drops,
}

/// Flow-log sink backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SinkKind {
    /// Structured JSON lines to stdout (default).
    #[default]
    Stdout,
}

/// Flow-log settings.
#[derive(Debug, Clone)]
pub struct FlowLog {
    /// What to log.
    pub mode: FlowLogMode,
    /// NFLOG group used by both the nftables `log` expr and the receiver.
    pub group: u16,
    /// Where to emit parsed events.
    pub sink: SinkKind,
    /// Per-second rate limit (0 = unlimited).
    pub rate: u32,
}

impl Default for FlowLog {
    fn default() -> Self {
        Self {
            mode: FlowLogMode::Off,
            group: 100,
            sink: SinkKind::Stdout,
            rate: 200,
        }
    }
}

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
    /// Flow-log configuration.
    pub flowlog: FlowLog,
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
            flowlog: flowlog_from_env(),
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

fn flowlog_from_env() -> FlowLog {
    flowlog_from_vars(std::env::vars())
}

fn flowlog_from_vars(vars: impl Iterator<Item = (String, String)>) -> FlowLog {
    let vars: std::collections::HashMap<String, String> = vars.collect();
    let mut flowlog = FlowLog::default();

    if let Some(raw) = vars.get("SUHO_FLOWLOG").filter(|s| !s.is_empty()) {
        flowlog.mode = match raw.as_str() {
            "off" => FlowLogMode::Off,
            "drops" => FlowLogMode::Drops,
            _ => {
                warn!(value = %raw, "SUHO_FLOWLOG must be 'off' or 'drops'; using default 'off'");
                FlowLogMode::Off
            }
        };
    }

    if let Some(raw) = vars.get("SUHO_FLOWLOG_GROUP").filter(|s| !s.is_empty()) {
        match raw.parse() {
            Ok(group) => flowlog.group = group,
            Err(err) => warn!(value = %raw, %err, "ignoring invalid SUHO_FLOWLOG_GROUP"),
        }
    }

    if let Some(raw) = vars.get("SUHO_FLOWLOG_SINK").filter(|s| !s.is_empty()) {
        flowlog.sink = match raw.as_str() {
            "stdout" => SinkKind::Stdout,
            _ => {
                warn!(value = %raw, "SUHO_FLOWLOG_SINK must be 'stdout'; using default 'stdout'");
                SinkKind::Stdout
            }
        };
    }

    if let Some(raw) = vars.get("SUHO_FLOWLOG_RATE").filter(|s| !s.is_empty()) {
        match raw.parse() {
            Ok(rate) => flowlog.rate = rate,
            Err(err) => warn!(value = %raw, %err, "ignoring invalid SUHO_FLOWLOG_RATE"),
        }
    }

    flowlog
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resync_never_zero() {
        assert_eq!(resync_from(0), Duration::from_secs(1));
        assert_eq!(resync_from(30), Duration::from_secs(30));
    }

    #[test]
    fn flowlog_defaults_to_off() {
        let cfg = FlowLog::default();
        assert_eq!(cfg.mode, FlowLogMode::Off);
        assert_eq!(cfg.group, 100);
        assert_eq!(cfg.sink, SinkKind::Stdout);
        assert_eq!(cfg.rate, 200);
    }

    #[test]
    fn flowlog_parses_drops() {
        let cfg = parse_flowlog_with(&[("SUHO_FLOWLOG", "drops")]);
        assert_eq!(cfg.mode, FlowLogMode::Drops);
        assert_eq!(cfg.group, 100);
        assert_eq!(cfg.rate, 200);
    }

    #[test]
    fn flowlog_parses_group_sink_rate() {
        let cfg = parse_flowlog_with(&[
            ("SUHO_FLOWLOG", "drops"),
            ("SUHO_FLOWLOG_GROUP", "42"),
            ("SUHO_FLOWLOG_SINK", "stdout"),
            ("SUHO_FLOWLOG_RATE", "0"),
        ]);
        assert_eq!(cfg.mode, FlowLogMode::Drops);
        assert_eq!(cfg.group, 42);
        assert_eq!(cfg.sink, SinkKind::Stdout);
        assert_eq!(cfg.rate, 0);
    }

    #[test]
    fn flowlog_invalid_mode_ignored() {
        let cfg = parse_flowlog_with(&[("SUHO_FLOWLOG", "everything")]);
        assert_eq!(cfg.mode, FlowLogMode::Off);
    }

    #[test]
    fn flowlog_invalid_group_ignored() {
        let cfg = parse_flowlog_with(&[("SUHO_FLOWLOG_GROUP", "not-a-number")]);
        assert_eq!(cfg.group, 100);
    }

    #[test]
    fn flowlog_invalid_rate_ignored() {
        let cfg = parse_flowlog_with(&[("SUHO_FLOWLOG_RATE", "-1")]);
        assert_eq!(cfg.rate, 200);
    }

    fn parse_flowlog_with(vars: &[(&str, &str)]) -> FlowLog {
        flowlog_from_vars(vars.iter().map(|(k, v)| (k.to_string(), v.to_string())))
    }
}
