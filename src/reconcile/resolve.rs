// SPDX-License-Identifier: GPL-3.0-or-later
//! Peer resolution over the Docker snapshot: index containers by network, and
//! turn a policy peer into a concrete address match. Shared by the per-direction
//! compilers ([`super::egress`], [`super::ingress`]).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use tracing::warn;

use crate::api::v1alpha1 as policy;
use crate::docker::Target;
use crate::enforce::{Cidr, Match, Ruleset};

/// Docker-network membership across a snapshot: network name → member IPs.
pub(super) struct Index {
    net_ips: BTreeMap<String, BTreeSet<IpAddr>>,
}

impl Index {
    pub(super) fn build(targets: &[Target]) -> Self {
        let mut net_ips: BTreeMap<String, BTreeSet<IpAddr>> = BTreeMap::new();
        for target in targets {
            for (net, addrs) in &target.networks {
                net_ips
                    .entry(net.clone())
                    .or_default()
                    .extend(addrs.iter().copied());
            }
        }
        Self { net_ips }
    }
}

/// Resolve a policy peer into an address match, registering any named set it
/// references in `rs`. Returns `None` when the peer resolves to nothing
/// enforceable.
///
/// `cidr` (+ `except`) is a standalone address block. `container`, `network` and
/// `selector` are container-identity filters that **combine** (AND): a peer
/// setting several matches only containers satisfying all of them. A lone
/// `network` compiles to a named set (readable `@net_<n>`); combined with another
/// filter it resolves to the intersecting containers' addresses. No field = any.
pub(super) fn resolve_peer(
    peer: &policy::Peer,
    index: &Index,
    targets: &[Target],
    rs: &mut Ruleset,
) -> Option<Match> {
    if let Some(cidr) = &peer.cidr {
        return match cidr.parse::<Cidr>() {
            Ok(cidr) => {
                let except = peer
                    .except
                    .iter()
                    .filter_map(|e| match e.parse::<Cidr>() {
                        Ok(c) if c.addr.is_ipv6() == cidr.addr.is_ipv6() => Some(c),
                        Ok(_) => {
                            warn!(%e, "except CIDR family differs from cidr; ignoring");
                            None
                        }
                        Err(err) => {
                            warn!(%e, %err, "invalid except CIDR; skipping");
                            None
                        }
                    })
                    .collect();
                Some(Match::Cidr { cidr, except })
            }
            Err(err) => {
                warn!(%cidr, %err, "invalid CIDR peer; skipping");
                None
            }
        };
    }

    match (&peer.container, &peer.network, &peer.selector) {
        (None, None, None) => Some(Match::Any),
        // A lone network is a named set (readable in the rendered ruleset).
        (None, Some(network), None) => {
            let name = format!("net_{}", sanitize(network));
            let members = index.net_ips.get(network).cloned().unwrap_or_default();
            match rs.sets.get(&name) {
                // Same sanitized name but different members ⇒ two distinct
                // networks collapsed onto one set name. Inline this peer's
                // addresses instead of silently reusing the other network's set.
                Some(existing) if *existing != members => {
                    warn!(%network, %name, "network set name collides after sanitization; inlining addresses");
                    (!members.is_empty()).then_some(Match::Addrs(members))
                }
                _ => {
                    rs.sets.entry(name.clone()).or_insert(members);
                    Some(Match::Set(name))
                }
            }
        }
        // Otherwise intersect (AND) the identity filters that are set.
        (container, network, selector) => {
            let addrs: BTreeSet<IpAddr> = targets
                .iter()
                .filter(|t| container.as_ref().is_none_or(|c| &t.name == c))
                .filter(|t| network.as_ref().is_none_or(|n| t.networks.contains_key(n)))
                .filter(|t| {
                    selector
                        .as_ref()
                        .is_none_or(|s| policy::selector_matches(s, &t.labels))
                })
                .flat_map(target_ips)
                .collect();
            (!addrs.is_empty()).then_some(Match::Addrs(addrs))
        }
    }
}

/// A container's addresses (IPv4 and IPv6) across all its Docker networks.
pub(super) fn target_ips(target: &Target) -> BTreeSet<IpAddr> {
    target.networks.values().flatten().copied().collect()
}

/// Replace characters invalid in an nftables set identifier with `_`.
fn sanitize(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::IpAddr;

    use super::{Index, resolve_peer};
    use crate::api::v1alpha1::Peer;
    use crate::docker::Target;
    use crate::enforce::{Match, Ruleset};

    fn tgt(name: &str, labels: &[(&str, &str)], nets: &[(&str, &str)]) -> Target {
        Target {
            name: name.to_owned(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            networks: nets
                .iter()
                .map(|(k, v)| ((*k).to_owned(), vec![v.parse::<IpAddr>().unwrap()]))
                .collect(),
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn container_peer_resolves_by_name() {
        let db = tgt("db", &[], &[("n", "10.0.0.5")]);
        let targets = [db];
        let index = Index::build(&targets);
        let mut rs = Ruleset::default();
        let peer = Peer {
            container: Some("db".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            resolve_peer(&peer, &index, &targets, &mut rs),
            Some(Match::Addrs([ip("10.0.0.5")].into_iter().collect()))
        );
    }

    #[test]
    fn unknown_container_is_none() {
        let index = Index::build(&[]);
        let mut rs = Ruleset::default();
        let peer = Peer {
            container: Some("absent".to_owned()),
            ..Default::default()
        };
        assert_eq!(resolve_peer(&peer, &index, &[], &mut rs), None);
    }

    #[test]
    fn network_peer_sanitizes_set_name() {
        let c = tgt("c", &[], &[("suho-net-a", "10.0.0.7")]);
        let targets = [c];
        let index = Index::build(&targets);
        let mut rs = Ruleset::default();
        let peer = Peer {
            network: Some("suho-net-a".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            resolve_peer(&peer, &index, &targets, &mut rs),
            Some(Match::Set("net_suho_net_a".to_owned()))
        );
        assert_eq!(
            rs.sets.get("net_suho_net_a"),
            Some(&[ip("10.0.0.7")].into_iter().collect())
        );
    }

    #[test]
    fn except_ignores_mismatched_family() {
        let index = Index::build(&[]);
        let mut rs = Ruleset::default();
        let peer = Peer {
            cidr: Some("0.0.0.0/0".to_owned()),
            except: vec!["10.0.0.0/8".to_owned(), "fd00::/8".to_owned()],
            ..Default::default()
        };
        match resolve_peer(&peer, &index, &[], &mut rs) {
            Some(Match::Cidr { except, .. }) => {
                assert_eq!(except.len(), 1, "v6 except on a v4 cidr must be dropped");
                assert!(!except[0].addr.is_ipv6());
            }
            other => panic!("expected a cidr match, got {other:?}"),
        }
    }

    #[test]
    fn colliding_network_set_names_inline() {
        let a = tgt("a", &[], &[("x-y", "10.0.0.1")]);
        let b = tgt("b", &[], &[("x_y", "10.0.0.2")]);
        let targets = [a, b];
        let index = Index::build(&targets);
        let mut rs = Ruleset::default();
        let first = resolve_peer(
            &Peer {
                network: Some("x-y".to_owned()),
                ..Default::default()
            },
            &index,
            &targets,
            &mut rs,
        );
        assert_eq!(first, Some(Match::Set("net_x_y".to_owned())));
        // Sanitizes to the same set name but has different members ⇒ inline.
        let second = resolve_peer(
            &Peer {
                network: Some("x_y".to_owned()),
                ..Default::default()
            },
            &index,
            &targets,
            &mut rs,
        );
        assert_eq!(
            second,
            Some(Match::Addrs([ip("10.0.0.2")].into_iter().collect()))
        );
    }

    #[test]
    fn combined_peer_intersects_filters() {
        // Only a container on network "back" AND labelled tier=db qualifies.
        let db = tgt("db", &[("tier", "db")], &[("back", "10.0.0.5")]);
        let wrong_net = tgt("x", &[("tier", "db")], &[("front", "10.0.0.6")]);
        let wrong_label = tgt("y", &[("tier", "web")], &[("back", "10.0.0.7")]);
        let targets = [db, wrong_net, wrong_label];
        let index = Index::build(&targets);
        let mut rs = Ruleset::default();
        let selector: BTreeMap<String, String> =
            [("tier".to_owned(), "db".to_owned())].into_iter().collect();
        let peer = Peer {
            network: Some("back".to_owned()),
            selector: Some(selector),
            ..Default::default()
        };
        assert_eq!(
            resolve_peer(&peer, &index, &targets, &mut rs),
            Some(Match::Addrs([ip("10.0.0.5")].into_iter().collect()))
        );
    }

    #[test]
    fn valid_cidr_resolves() {
        let index = Index::build(&[]);
        let mut rs = Ruleset::default();
        let peer = Peer {
            cidr: Some("10.0.0.0/8".to_owned()),
            ..Default::default()
        };
        assert_eq!(
            resolve_peer(&peer, &index, &[], &mut rs),
            Some(Match::Cidr {
                cidr: "10.0.0.0/8".parse().unwrap(),
                except: vec![],
            })
        );
    }

    #[test]
    fn invalid_cidr_is_dropped() {
        let index = Index::build(&[]);
        let mut rs = Ruleset::default();
        let peer = Peer {
            cidr: Some("not-a-cidr".to_owned()),
            ..Default::default()
        };
        assert_eq!(resolve_peer(&peer, &index, &[], &mut rs), None);
    }

    #[test]
    fn cidr_with_except_parses_sub_blocks() {
        let index = Index::build(&[]);
        let mut rs = Ruleset::default();
        let peer = Peer {
            cidr: Some("0.0.0.0/0".to_owned()),
            except: vec!["10.0.0.0/8".to_owned(), "bogus".to_owned()],
            ..Default::default()
        };
        // Valid excepts are kept; unparseable ones are dropped.
        assert_eq!(
            resolve_peer(&peer, &index, &[], &mut rs),
            Some(Match::Cidr {
                cidr: "0.0.0.0/0".parse().unwrap(),
                except: vec!["10.0.0.0/8".parse().unwrap()],
            })
        );
    }

    #[test]
    fn selector_peer_resolves_matching_addrs() {
        // e.g. selecting a Compose service by its label.
        let web = tgt(
            "proj-web-1",
            &[("com.docker.compose.service", "web")],
            &[("n", "10.0.0.9")],
        );
        let other = tgt(
            "proj-db-1",
            &[("com.docker.compose.service", "db")],
            &[("n", "10.0.0.10")],
        );
        let targets = [web, other];
        let index = Index::build(&targets);
        let mut rs = Ruleset::default();

        let selector: BTreeMap<String, String> =
            [("com.docker.compose.service".to_owned(), "web".to_owned())]
                .into_iter()
                .collect();
        let peer = Peer {
            selector: Some(selector),
            ..Default::default()
        };
        assert_eq!(
            resolve_peer(&peer, &index, &targets, &mut rs),
            Some(Match::Addrs([ip("10.0.0.9")].into_iter().collect()))
        );
    }

    #[test]
    fn selector_matching_nothing_is_none() {
        let index = Index::build(&[]);
        let mut rs = Ruleset::default();
        let selector: BTreeMap<String, String> = [("app".to_owned(), "absent".to_owned())]
            .into_iter()
            .collect();
        let peer = Peer {
            selector: Some(selector),
            ..Default::default()
        };
        assert_eq!(resolve_peer(&peer, &index, &[], &mut rs), None);
    }

    #[test]
    fn empty_peer_is_any() {
        let index = Index::build(&[]);
        let mut rs = Ruleset::default();
        assert_eq!(
            resolve_peer(&Peer::default(), &index, &[], &mut rs),
            Some(Match::Any)
        );
    }
}
