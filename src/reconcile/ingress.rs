// SPDX-License-Identifier: GPL-3.0-or-later
//! Ingress compilation: a container carrying an ingress policy is default-deny
//! inbound; only sources matched by an ingress rule pass. Rules land in the
//! `suho_ingress` chain — allowed traffic returns (to the forward chain's
//! accept), the rest of the traffic to the container is dropped.
//!
//! Kubernetes checks both directions independently, so egress and ingress are
//! separate chains and a packet must clear both (see the enforcer's jump
//! structure). See `docs/architecture.md`.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::api::v1alpha1::{NetworkPolicy, PolicyType};
use crate::docker::Target;
use crate::enforce::{Match, Rule, Ruleset, Verdict};

use super::resolve::{Index, resolve_peer};

/// Ingress is enforced when the policy lists `Ingress`, or — mirroring
/// Kubernetes — when `policyTypes` is omitted but ingress rules are present.
pub(super) fn enforces(np: &NetworkPolicy) -> bool {
    np.policy_types.contains(&PolicyType::Ingress)
        || (np.policy_types.is_empty() && !np.ingress.is_empty())
}

/// Append `suho_ingress` rules for one container: `return` for every allowed
/// source (union across the container's ingress policies), then a single
/// default-deny `drop`.
pub(super) fn emit(
    target: &Target,
    ips: &BTreeSet<IpAddr>,
    policies: &[&(String, NetworkPolicy)],
    index: &Index,
    targets: &[Target],
    rs: &mut Ruleset,
) {
    let dst = Match::Addrs(ips.clone());
    for (name, np) in policies.iter().copied() {
        for rule in &np.ingress {
            let sources = if rule.from.is_empty() {
                vec![Match::Any]
            } else {
                rule.from
                    .iter()
                    .filter_map(|peer| resolve_peer(peer, index, targets, rs))
                    .collect()
            };
            for saddr in sources {
                rs.ingress.push(Rule {
                    comment: format!("{}/{name} ingress", target.name),
                    saddr,
                    daddr: dst.clone(),
                    ports: rule.ports.clone(),
                    verdict: Verdict::Return,
                });
            }
        }
    }
    rs.ingress.push(Rule {
        comment: format!("{} ingress default-deny", target.name),
        saddr: Match::Any,
        daddr: dst,
        ports: Vec::new(),
        verdict: Verdict::Drop,
    });
}

#[cfg(test)]
mod tests {
    use super::enforces;
    use crate::api::v1alpha1::{IngressRule, NetworkPolicy, PolicyType};

    fn np(types: &[PolicyType], ingress_rules: usize) -> NetworkPolicy {
        NetworkPolicy {
            endpoint_selector: None,
            policy_types: types.to_vec(),
            egress: Vec::new(),
            ingress: vec![IngressRule::default(); ingress_rules],
        }
    }

    #[test]
    fn explicit_ingress_enforces_even_without_rules() {
        assert!(enforces(&np(&[PolicyType::Ingress], 0)));
    }

    #[test]
    fn omitted_types_with_ingress_rules_enforces() {
        assert!(enforces(&np(&[], 1)));
    }

    #[test]
    fn omitted_types_without_rules_does_not_enforce() {
        assert!(!enforces(&np(&[], 0)));
    }

    #[test]
    fn explicit_egress_only_does_not_enforce_ingress() {
        assert!(!enforces(&np(&[PolicyType::Egress], 1)));
    }
}
