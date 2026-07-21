// SPDX-License-Identifier: GPL-3.0-or-later
//! suho — label-driven L3/L4 network-policy controller for Docker.
//!
//! See `docs/architecture.md`. Config, the policy model + parsing, the Docker source and
//! the event-driven reconcile loop are wired end to end. The enforcement backend
//! is pluggable ([`enforce::Enforcer`]): `--dry-run` selects the logging backend,
//! otherwise suho programs nftables ([`enforce::NftEnforcer`]).

mod api;
mod config;
mod docker;
mod enforce;
mod obs;
mod reconcile;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::{
    api::v1alpha1 as policy,
    config::Config,
    docker::Source,
    enforce::{Enforcer, LoggingEnforcer, NftEnforcer},
    obs::{Metrics, Trigger},
    reconcile::Reconciler,
};

/// suho command-line interface.
#[derive(Parser)]
#[command(
    name = "suho",
    version,
    about = "Label-driven L3/L4 network-policy controller for Docker"
)]
struct Cli {
    /// Resolve policy and log the ruleset without programming nftables.
    #[arg(long)]
    dry_run: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Print the JSON Schema for `policies/suho.yaml`.
    Schema,
    /// Validate a global policies file or directory offline (no Docker, no root).
    Validate {
        /// Path to check; defaults to $SUHO_POLICIES_PATH.
        path: Option<PathBuf>,
    },
    /// Show governed containers and the resolved ruleset (reads Docker, applies nothing).
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse() {
        Cli {
            command: Some(Command::Schema),
            ..
        } => {
            println!("{}", schema_json());
            Ok(())
        }
        Cli {
            command: Some(Command::Validate { path }),
            ..
        } => validate(path),
        Cli {
            command: Some(Command::Status),
            ..
        } => status().await,
        Cli {
            dry_run,
            command: None,
        } => run(dry_run).await,
    }
}

/// Run the reconcile daemon until terminated (SIGINT/SIGTERM).
async fn run(dry_run: bool) -> Result<()> {
    init_tracing();

    let config = Config::from_env();
    info!(api_version = policy::VERSION, ?config, "starting suho");

    let globals = reconcile::load_globals(&config)?;
    info!(count = globals.len(), "loaded global policies");

    let metrics = Arc::new(Metrics::default());
    if let Some(addr) = config.metrics_addr {
        obs::serve(addr, Arc::clone(&metrics));
    }

    let source = Source::connect()?;
    let enforcer = select_enforcer(dry_run);
    let mut reconciler = Reconciler::new(source, enforcer, config.clone(), globals);
    let mut events = reconciler.watch({
        let metrics = Arc::clone(&metrics);
        move || metrics.watch_restarted()
    });

    // Fail closed: if enforcement can't be established at startup, exit non-zero
    // rather than run with no rules in place.
    reconcile(&mut reconciler, &metrics, Trigger::Startup)
        .await
        .context("initial reconcile")?;

    let mut ticker = tokio::time::interval(config.resync_interval);
    ticker.tick().await; // the first tick fires immediately; skip it

    let shutdown = shutdown();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            () = &mut shutdown => {
                info!("shutting down");
                return Ok(());
            }
            _ = ticker.tick() => {
                if let Err(err) = reconcile(&mut reconciler, &metrics, Trigger::Resync).await {
                    error!("reconcile failed: {err:?}");
                }
            }
            signal = events.recv() => {
                if signal.is_none() {
                    warn!("docker event watcher stopped; re-establishing");
                    metrics.watch_restarted();
                events = reconciler.watch({
                    let metrics = Arc::clone(&metrics);
                    move || metrics.watch_restarted()
                });
                    continue;
                }
                // Coalesce a burst of container events into a single reconcile.
                debounce(&mut events, config.debounce).await;
                if let Err(err) = reconcile(&mut reconciler, &metrics, Trigger::Event).await {
                    error!("reconcile failed: {err:?}");
                }
            }
        }
    }
}

/// Validate a global policies file/directory offline: structure, ports, CIDRs.
fn validate(path: Option<PathBuf>) -> Result<()> {
    let config = Config::from_env();
    let path = path.unwrap_or(config.policies_path);
    if !path.exists() {
        anyhow::bail!("path not found: {}", path.display());
    }
    let globals = reconcile::load_globals_path(&path)?;
    for global in &globals {
        let peers = global
            .policy
            .ingress
            .iter()
            .flat_map(|rule| &rule.from)
            .chain(global.policy.egress.iter().flat_map(|rule| &rule.to));
        for peer in peers {
            for cidr in peer.cidr.iter().chain(peer.except.iter()) {
                cidr.parse::<crate::enforce::Cidr>().map_err(|err| {
                    anyhow::anyhow!("policy {:?}: invalid CIDR {cidr:?}: {err}", global.name)
                })?;
            }
        }
    }
    let n = globals.len();
    println!(
        "ok: {n} global {} in {}",
        if n == 1 { "policy" } else { "policies" },
        path.display()
    );
    Ok(())
}

/// Show governed containers and the resolved ruleset without applying it.
async fn status() -> Result<()> {
    let config = Config::from_env();
    let globals = reconcile::load_globals(&config)?;
    let source = Source::connect()?;
    let (targets, ruleset) = reconcile::resolve(&source, &config, &globals).await?;
    println!(
        "suho status — {} containers, {} egress rules, {} ingress rules, {} sets\n",
        targets.len(),
        ruleset.egress.len(),
        ruleset.ingress.len(),
        ruleset.sets.len()
    );
    if !targets.is_empty() {
        println!("containers:");
        for target in &targets {
            let addrs: Vec<String> = target
                .networks
                .values()
                .flatten()
                .map(ToString::to_string)
                .collect();
            println!("  {}  [{}]", target.name, addrs.join(", "));
        }
        println!();
    }
    print!("{ruleset}");
    Ok(())
}

/// Pick the enforcement backend. `--dry-run` resolves policy and logs the
/// ruleset without touching the host; otherwise suho programs nftables (needs
/// root / `CAP_NET_ADMIN`).
fn select_enforcer(dry_run: bool) -> Box<dyn Enforcer> {
    if dry_run {
        info!("dry-run: resolving policy and logging the ruleset, applying nothing");
        Box::new(LoggingEnforcer)
    } else {
        info!("enforcing via nftables (table inet suho)");
        warn_if_bridge_netfilter_disabled();
        Box::new(NftEnforcer)
    }
}

/// Intra-bridge (same Docker network) traffic only traverses the forward hook
/// when br_netfilter is enabled. Without it suho enforces routed egress but not
/// container-to-container or ingress policy — warn loudly rather than silently
/// failing open.
fn warn_if_bridge_netfilter_disabled() {
    let enabled = std::fs::read_to_string("/proc/sys/net/bridge/bridge-nf-call-iptables")
        .is_ok_and(|v| v.trim() == "1");
    if !enabled {
        warn!(
            "br_netfilter/bridge-nf-call-iptables is not enabled: suho cannot filter \
             container-to-container traffic on the same Docker network (inter-container \
             egress and all ingress). Enable with `modprobe br_netfilter && sysctl -w \
             net.bridge.bridge-nf-call-iptables=1`."
        );
    }
}

/// Run one reconcile, recording timing and outcome in `metrics`.
async fn reconcile<E: Enforcer>(
    reconciler: &mut Reconciler<E>,
    metrics: &Metrics,
    trigger: Trigger,
) -> Result<()> {
    let start = Instant::now();
    let result = reconciler.run_once().await;
    metrics.record(trigger, start.elapsed(), result.as_ref().ok().copied());
    result.map(|_| ())
}

/// Wait until Docker events have been quiet for `delay`, draining any that
/// arrive within the window.
async fn debounce(events: &mut mpsc::Receiver<()>, delay: Duration) {
    // Loops while events keep arriving within the window; ends on the first
    // quiet period (timeout `Err`) or when the channel closes (`Ok(None)`).
    while let Ok(Some(())) = tokio::time::timeout(delay, events.recv()).await {}
}

/// Resolve when the process is asked to terminate (SIGINT or SIGTERM).
async fn shutdown() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

fn init_tracing() {
    use tracing_subscriber::{EnvFilter, fmt};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt().with_env_filter(filter).init();
}

/// The JSON Schema for the global policies document (`policies/suho.yaml`),
/// generated from the Rust policy types. Emitted by `suho schema`; the committed
/// `schemas/network-policies.v1alpha1.json` must stay in sync (see the test).
fn schema_json() -> String {
    let mut schema = schemars::schema_for!(Vec<policy::GlobalPolicy>);
    let obj = schema.ensure_object();
    obj.insert(
        "title".into(),
        format!("suho network policies ({})", policy::VERSION).into(),
    );
    obj.insert(
        "$comment".into(),
        "Generated from suho's Rust types; regenerate with `suho schema`.".into(),
    );
    serde_json::to_string_pretty(&schema).expect("schema serializes to JSON")
}

#[cfg(test)]
mod tests {
    #[test]
    fn committed_schema_is_up_to_date() {
        let committed = include_str!("../schemas/network-policies.v1alpha1.json");
        assert_eq!(
            super::schema_json().trim(),
            committed.trim(),
            "policy schema drifted; regenerate: cargo run -- schema > \
             schemas/network-policies.v1alpha1.json"
        );
    }
}
