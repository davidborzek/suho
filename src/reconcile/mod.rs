// SPDX-License-Identifier: GPL-3.0-or-later
//! Reconcile loop: current containers + policies → desired ruleset → enforce.
//!
//! Stateless and orphan-free by construction: every run rebuilds the entire
//! desired ruleset from the current Docker snapshot, so a stopped container's
//! rules simply never reappear (see `docs/architecture.md`).
//!
//! Compilation is split by concern: [`resolve`] turns policy peers into concrete
//! address matches, and [`egress`] / [`ingress`] compile the two policy chains a
//! packet must clear.

mod egress;
mod ingress;
mod resolve;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::warn;

use crate::{
    api::v1alpha1::{self as policy, GlobalPolicy, NetworkPolicy},
    config::Config,
    docker::{Source, Target},
    enforce::{Enforcer, Ruleset},
};

use resolve::{Index, target_ips};

/// Load global policies from the configured path (a YAML file or a directory of
/// YAML files). Missing path → no global policies.
///
/// # Errors
/// Fails if a policy file cannot be read or parsed.
pub fn load_globals(config: &Config) -> Result<Vec<GlobalPolicy>> {
    load_globals_path(&config.policies_path)
}

/// Load global policies from `path` (a YAML file or a directory of YAML files).
/// Missing path → no global policies.
///
/// # Errors
/// Fails if a policy file cannot be read or parsed.
pub fn load_globals_path(path: &Path) -> Result<Vec<GlobalPolicy>> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let files: Vec<PathBuf> = if path.is_dir() {
        std::fs::read_dir(path)
            .with_context(|| format!("reading {}", path.display()))?
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|p| matches!(p.extension().and_then(|s| s.to_str()), Some("yaml" | "yml")))
            .collect()
    } else {
        vec![path.to_path_buf()]
    };

    let mut globals = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file)
            .with_context(|| format!("reading {}", file.display()))?;
        let parsed =
            policy::parse_globals(&text).with_context(|| format!("parsing {}", file.display()))?;
        globals.extend(parsed);
    }
    Ok(globals)
}

/// Reconciles container state into an enforced ruleset.
pub struct Reconciler<E: Enforcer> {
    source: Source,
    enforcer: E,
    config: Config,
    globals: Vec<GlobalPolicy>,
}

impl<E: Enforcer> Reconciler<E> {
    /// Create a reconciler.
    pub fn new(source: Source, enforcer: E, config: Config, globals: Vec<GlobalPolicy>) -> Self {
        Self {
            source,
            enforcer,
            config,
            globals,
        }
    }

    /// Perform one full reconcile: list containers, build the desired ruleset,
    /// and apply it (replacing any previous suho state).
    ///
    /// # Errors
    /// Fails if listing containers or applying the ruleset fails.
    pub async fn run_once(&mut self) -> Result<(usize, usize, usize)> {
        let targets = self.source.list_targets().await?;
        let ruleset = compile(&targets, &self.config.label_prefix, &self.globals);
        let counts = (
            ruleset.egress.len(),
            ruleset.ingress.len(),
            ruleset.sets.len(),
        );
        self.enforcer.apply(&ruleset)?;
        Ok(counts)
    }

    /// Subscribe to Docker lifecycle events (see [`Source::watch`]).
    #[must_use]
    pub fn watch(&self, on_restart: impl Fn() + Send + 'static) -> tokio::sync::mpsc::Receiver<()> {
        self.source.watch(on_restart)
    }
}

/// List current containers and compile the desired ruleset without applying it
/// (used by `suho status`).
///
/// # Errors
/// Fails if listing containers fails.
pub async fn resolve(
    source: &Source,
    config: &Config,
    globals: &[GlobalPolicy],
) -> Result<(Vec<Target>, Ruleset)> {
    let targets = source.list_targets().await?;
    let ruleset = compile(&targets, &config.label_prefix, globals);
    Ok((targets, ruleset))
}

/// Compile the current containers + policies into the desired [`Ruleset`]:
/// per container, the egress rules and the ingress rules it enforces.
fn compile(targets: &[Target], label_prefix: &str, globals: &[GlobalPolicy]) -> Ruleset {
    let index = Index::build(targets);

    // Parse every container's policy labels once, keeping the carrier so a
    // policy without an endpointSelector applies to its own container.
    let mut inline: Vec<(&Target, String, NetworkPolicy)> = Vec::new();
    for target in targets {
        for (name, value) in policy::inline_policies(label_prefix, &target.labels) {
            match policy::parse_inline(&value) {
                Ok(np) => inline.push((target, name, np)),
                Err(err) => {
                    warn!(container = %target.name, policy = %name, %err, "invalid policy label");
                }
            }
        }
    }

    let mut rs = Ruleset::default();
    for target in targets {
        let ips = target_ips(target);
        if ips.is_empty() {
            // Host networking or unparsable addresses: nothing to match on. If a
            // policy nonetheless selects this container, silently skipping it is
            // a fail-open — make that visible.
            if !policies_for(target, &inline, globals).is_empty() {
                warn!(
                    container = %target.name,
                    "selected by a network policy but has no resolvable IP \
                     (host networking?); left unenforced"
                );
            }
            continue;
        }
        let policies = policies_for(target, &inline, globals);

        let egress: Vec<&(String, NetworkPolicy)> = policies
            .iter()
            .filter(|(_, np)| egress::enforces(np))
            .collect();
        if !egress.is_empty() {
            egress::emit(target, &ips, &egress, &index, targets, &mut rs);
        }

        let ingress: Vec<&(String, NetworkPolicy)> = policies
            .iter()
            .filter(|(_, np)| ingress::enforces(np))
            .collect();
        if !ingress.is_empty() {
            ingress::emit(target, &ips, &ingress, &index, targets, &mut rs);
        }
    }
    rs
}

/// Policies applying to `target`: policy labels scoped to it (its own labels
/// with no `endpointSelector`, plus any container's label whose selector matches
/// it) and file globals whose selector matches (absent = all).
fn policies_for(
    target: &Target,
    inline: &[(&Target, String, NetworkPolicy)],
    globals: &[GlobalPolicy],
) -> Vec<(String, NetworkPolicy)> {
    let mut out = Vec::new();
    for (carrier, name, np) in inline {
        let applies = match &np.endpoint_selector {
            None => carrier.name == target.name,
            Some(selector) => policy::selector_matches(selector, &target.labels),
        };
        if applies {
            out.push((name.clone(), np.clone()));
        }
    }
    for global in globals {
        let applies = global
            .policy
            .endpoint_selector
            .as_ref()
            .is_none_or(|selector| policy::selector_matches(selector, &target.labels));
        if applies {
            out.push((global.name.clone(), global.policy.clone()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::compile;
    use crate::api::v1alpha1 as policy;
    use crate::docker::Target;
    use crate::enforce::{Match, Ruleset, Verdict};

    fn tgt(name: &str, ip: &str, labels: &[(&str, &str)]) -> Target {
        Target {
            name: name.to_owned(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            networks: [("net".to_owned(), vec![ip.parse::<IpAddr>().unwrap()])]
                .into_iter()
                .collect(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn port(s: &str) -> policy::Port {
        s.parse().unwrap()
    }

    fn egress_drops(rs: &Ruleset) -> usize {
        rs.egress
            .iter()
            .filter(|r| r.verdict == Verdict::Drop)
            .count()
    }

    #[test]
    fn egress_to_container_returns_then_default_deny() {
        let app = tgt(
            "app",
            "10.0.0.2",
            &[(
                "suho.networkpolicy.db",
                "policyTypes: [Egress]\negress:\n  - to: [{container: db}]\n    ports: [\"5432/tcp\"]\n",
            )],
        );
        let db = tgt("db", "10.0.0.5", &[]);
        let rs = compile(&[app, db], "suho", &[]);

        let allow = rs
            .egress
            .iter()
            .find(|r| r.verdict == Verdict::Return)
            .unwrap();
        assert_eq!(
            allow.saddr,
            Match::Addrs([ip("10.0.0.2")].into_iter().collect())
        );
        assert_eq!(
            allow.daddr,
            Match::Addrs([ip("10.0.0.5")].into_iter().collect())
        );
        assert_eq!(allow.ports, vec![port("5432/tcp")]);
        assert_eq!(egress_drops(&rs), 1);
    }

    #[test]
    fn egress_to_cidr() {
        let app = tgt(
            "app",
            "10.0.0.2",
            &[(
                "suho.networkpolicy.web",
                "policyTypes: [Egress]\negress:\n  - to: [{cidr: 0.0.0.0/0}]\n    ports: [\"443/tcp\"]\n",
            )],
        );
        let rs = compile(&[app], "suho", &[]);
        let allow = rs
            .egress
            .iter()
            .find(|r| r.verdict == Verdict::Return)
            .unwrap();
        assert_eq!(
            allow.daddr,
            Match::Cidr {
                cidr: "0.0.0.0/0".parse().unwrap(),
                except: vec![]
            }
        );
    }

    #[test]
    fn multiple_egress_policies_share_one_default_deny() {
        let app = tgt(
            "app",
            "10.0.0.2",
            &[
                (
                    "suho.networkpolicy.a",
                    "policyTypes: [Egress]\negress:\n  - to: [{cidr: 1.1.1.1/32}]\n",
                ),
                (
                    "suho.networkpolicy.b",
                    "policyTypes: [Egress]\negress:\n  - to: [{cidr: 8.8.8.8/32}]\n",
                ),
            ],
        );
        let rs = compile(&[app], "suho", &[]);
        assert_eq!(
            rs.egress
                .iter()
                .filter(|r| r.verdict == Verdict::Return)
                .count(),
            2
        );
        assert_eq!(egress_drops(&rs), 1);
    }

    #[test]
    fn omitted_policy_types_derives_egress_from_rules() {
        let app = tgt(
            "app",
            "10.0.0.2",
            &[(
                "suho.networkpolicy.x",
                "egress:\n  - to: [{cidr: 0.0.0.0/0}]\n",
            )],
        );
        let rs = compile(&[app], "suho", &[]);
        assert_eq!(egress_drops(&rs), 1);
    }

    #[test]
    fn ingress_from_container_returns_then_default_deny() {
        // db accepts ingress only from the `web` container.
        let db = tgt(
            "db",
            "10.0.0.5",
            &[(
                "suho.networkpolicy.in",
                "policyTypes: [Ingress]\ningress:\n  - from: [{container: web}]\n",
            )],
        );
        let web = tgt("web", "10.0.0.2", &[]);
        let rs = compile(&[db, web], "suho", &[]);

        assert!(rs.egress.is_empty());
        let allow = rs
            .ingress
            .iter()
            .find(|r| r.verdict == Verdict::Return)
            .unwrap();
        assert_eq!(
            allow.saddr,
            Match::Addrs([ip("10.0.0.2")].into_iter().collect())
        );
        assert_eq!(
            allow.daddr,
            Match::Addrs([ip("10.0.0.5")].into_iter().collect())
        );
        assert_eq!(
            rs.ingress
                .iter()
                .filter(|r| r.verdict == Verdict::Drop)
                .count(),
            1
        );
    }

    #[test]
    fn explicit_ingress_only_does_not_enforce_egress() {
        let app = tgt(
            "app",
            "10.0.0.2",
            &[(
                "suho.networkpolicy.x",
                "policyTypes: [Ingress]\negress:\n  - to: [{cidr: 0.0.0.0/0}]\n",
            )],
        );
        let rs = compile(&[app], "suho", &[]);
        assert!(rs.egress.is_empty());
        assert!(!rs.ingress.is_empty());
    }

    #[test]
    fn host_network_container_is_skipped() {
        let mut app = tgt(
            "app",
            "10.0.0.2",
            &[(
                "suho.networkpolicy.web",
                "policyTypes: [Egress]\negress: []\n",
            )],
        );
        app.networks.clear();
        let rs = compile(&[app], "suho", &[]);
        assert!(rs.egress.is_empty() && rs.ingress.is_empty());
    }

    #[test]
    fn label_defined_global_applies_to_selected_containers() {
        // Container `xxx` co-locates a global policy: any container labelled
        // egress-xxx=true may egress to container `xxx` on 80/tcp.
        let xxx = tgt(
            "xxx",
            "10.0.0.5",
            &[(
                "suho.networkpolicy.egress-xxx",
                "endpointSelector: {egress-xxx: \"true\"}\npolicyTypes: [Egress]\negress:\n  - to: [{container: xxx}]\n    ports: [\"80/tcp\"]",
            )],
        );
        let app = tgt("app", "10.0.0.2", &[("egress-xxx", "true")]);
        let rs = compile(&[xxx, app], "suho", &[]);

        let allow = rs
            .egress
            .iter()
            .find(|r| r.verdict == Verdict::Return)
            .unwrap();
        assert_eq!(
            allow.saddr,
            Match::Addrs([ip("10.0.0.2")].into_iter().collect())
        );
        assert_eq!(
            allow.daddr,
            Match::Addrs([ip("10.0.0.5")].into_iter().collect())
        );
        assert_eq!(allow.ports, vec![port("80/tcp")]);
        assert_eq!(egress_drops(&rs), 1); // only app carries the opt-in label
    }
}
