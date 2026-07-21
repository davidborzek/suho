// SPDX-License-Identifier: GPL-3.0-or-later
//! Egress compilation: a container carrying an egress policy is default-deny
//! outbound; only destinations matched by an egress rule pass. Rules land in the
//! `suho_egress` chain — allowed traffic returns (to the ingress stage), the
//! rest of the container's egress is dropped. See `docs/architecture.md`.

use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::api::v1alpha1::{NetworkPolicy, PolicyType};
use crate::docker::Target;
use crate::enforce::{Match, Rule, Ruleset, Verdict};

use super::resolve::{Index, resolve_peer};

/// Egress is enforced when the policy lists `Egress`, or — mirroring
/// Kubernetes — when `policyTypes` is omitted but egress rules are present.
pub(super) fn enforces(np: &NetworkPolicy) -> bool {
    np.policy_types.contains(&PolicyType::Egress)
        || (np.policy_types.is_empty() && !np.egress.is_empty())
}

/// Append `suho_egress` rules for one container: `return` for every allowed
/// destination (union across the container's egress policies), then a single
/// default-deny `drop` — so one policy's deny never shadows another's allow.
pub(super) fn emit(
    target: &Target,
    ips: &BTreeSet<IpAddr>,
    policies: &[&(String, NetworkPolicy)],
    index: &Index,
    targets: &[Target],
    rs: &mut Ruleset,
) {
    let src = Match::Addrs(ips.clone());
    for (name, np) in policies.iter().copied() {
        for rule in &np.egress {
            let dests = if rule.to.is_empty() {
                vec![Match::Any]
            } else {
                rule.to
                    .iter()
                    .filter_map(|peer| resolve_peer(peer, index, targets, rs))
                    .collect()
            };
            for daddr in dests {
                rs.egress.push(Rule {
                    comment: format!("{}/{name} egress", target.name),
                    saddr: src.clone(),
                    daddr,
                    ports: rule.ports.clone(),
                    verdict: Verdict::Return,
                });
            }
        }
    }
    rs.egress.push(Rule {
        comment: format!("{} egress default-deny", target.name),
        saddr: src,
        daddr: Match::Any,
        ports: Vec::new(),
        verdict: Verdict::Drop,
    });
}

#[cfg(test)]
mod tests {
    use super::enforces;
    use crate::api::v1alpha1::{EgressRule, NetworkPolicy, PolicyType};

    fn np(types: &[PolicyType], egress_rules: usize) -> NetworkPolicy {
        NetworkPolicy {
            endpoint_selector: None,
            policy_types: types.to_vec(),
            egress: vec![EgressRule::default(); egress_rules],
            ingress: Vec::new(),
        }
    }

    #[test]
    fn explicit_egress_enforces_even_without_rules() {
        assert!(enforces(&np(&[PolicyType::Egress], 0)));
    }

    #[test]
    fn omitted_types_with_egress_rules_enforces() {
        assert!(enforces(&np(&[], 1)));
    }

    #[test]
    fn omitted_types_without_rules_does_not_enforce() {
        assert!(!enforces(&np(&[], 0)));
    }

    #[test]
    fn explicit_ingress_only_does_not_enforce_egress() {
        assert!(!enforces(&np(&[PolicyType::Ingress], 1)));
    }
}
