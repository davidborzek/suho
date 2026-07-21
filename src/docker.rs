// SPDX-License-Identifier: GPL-3.0-or-later
//! Docker source: the running containers suho may govern.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use bollard::Docker;
use bollard::models::{EventMessage, EventMessageTypeEnum};
use futures_util::StreamExt;
use tokio::sync::mpsc;
use tracing::warn;

/// A running container relevant to suho.
#[derive(Debug, Clone)]
pub struct Target {
    pub name: String,
    pub labels: BTreeMap<String, String>,
    /// Docker network attachments: network name → the container's addresses on
    /// it (IPv4 and/or IPv6). A container on several networks has several
    /// addresses — the enforcer must cover all of them, and `network:` peers
    /// resolve against these names.
    pub networks: BTreeMap<String, Vec<IpAddr>>,
}

/// Wraps the Docker API client.
pub struct Source {
    docker: Docker,
}

impl Source {
    /// Connect using the standard Docker environment (`DOCKER_HOST`, or the
    /// local socket / a socket proxy).
    ///
    /// # Errors
    /// Fails if the Docker client cannot be constructed.
    pub fn connect() -> Result<Self> {
        let docker =
            Docker::connect_with_local_defaults().context("connecting to the Docker API")?;
        Ok(Self { docker })
    }

    /// List running containers as [`Target`]s.
    ///
    /// # Errors
    /// Fails if the Docker API call fails.
    pub async fn list_targets(&self) -> Result<Vec<Target>> {
        // `None` = default query = running containers only.
        let containers = self
            .docker
            .list_containers(None)
            .await
            .context("listing containers")?;

        let targets = containers
            .into_iter()
            .map(|c| {
                let labels = c.labels.unwrap_or_default().into_iter().collect();
                let name = c
                    .names
                    .and_then(|names| names.into_iter().next())
                    .map(|n| n.trim_start_matches('/').to_owned())
                    .unwrap_or_default();
                let networks = c
                    .network_settings
                    .and_then(|ns| ns.networks)
                    .map(|nets| {
                        nets.into_iter()
                            .map(|(net, e)| {
                                let addrs: Vec<IpAddr> = [e.ip_address, e.global_ipv6_address]
                                    .into_iter()
                                    .flatten()
                                    .filter(|s| !s.is_empty())
                                    .filter_map(|s| s.parse().ok())
                                    .collect();
                                (net, addrs)
                            })
                            .filter(|(_, addrs)| !addrs.is_empty())
                            .collect()
                    })
                    .unwrap_or_default();
                Target {
                    name,
                    labels,
                    networks,
                }
            })
            .collect();
        Ok(targets)
    }

    /// Watch Docker for container lifecycle changes, returning a channel that
    /// signals (coalesced) whenever a reconcile may be needed. Resubscribes on
    /// error; the task ends once the receiver is dropped.
    #[must_use]
    pub fn watch(&self, on_restart: impl Fn() + Send + 'static) -> mpsc::Receiver<()> {
        let docker = self.docker.clone();
        let (tx, rx) = mpsc::channel(1);
        tokio::spawn(async move {
            let mut resubscribing = false;
            loop {
                // Every iteration after the first is a self-heal re-subscribe
                // (the event stream errored or ended); surface it as a metric.
                if resubscribing {
                    on_restart();
                }
                resubscribing = true;
                let mut events = std::pin::pin!(docker.events(None));
                while let Some(event) = events.next().await {
                    match event {
                        Ok(msg) if is_relevant(&msg) => {
                            // Capacity 1: a full buffer already means a reconcile
                            // is pending, so dropping the extra signal is fine.
                            if tx.try_send(()).is_err() && tx.is_closed() {
                                return;
                            }
                        }
                        Ok(_) => {}
                        Err(err) => {
                            warn!(%err, "docker event stream error, resubscribing");
                            break;
                        }
                    }
                }
                if tx.is_closed() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
        rx
    }
}

/// Container start/stop/removal events — the ones that change the target set.
fn is_relevant(msg: &EventMessage) -> bool {
    matches!(msg.typ, Some(EventMessageTypeEnum::CONTAINER))
        && matches!(msg.action.as_deref(), Some("start" | "die" | "destroy"))
}
