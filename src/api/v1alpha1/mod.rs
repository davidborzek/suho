// SPDX-License-Identifier: GPL-3.0-or-later
//! `v1alpha1` policy data model and parsing.
//!
//! Modelled on Kubernetes `NetworkPolicy`: per-container policies
//! (`suho.networkpolicy.<name>` labels, optionally with an `endpointSelector`)
//! and label-selected globals (`policies/suho.yaml`). See `docs/architecture.md`.

use std::{collections::BTreeMap, fmt, str::FromStr};

use serde::Deserialize;

/// This module's API version. Kubernetes-style maturity ladder
/// (`v1alpha1` → `v1beta1` → `v1`); a new version becomes a sibling module.
pub const VERSION: &str = "v1alpha1";

/// Which direction a policy governs. Presence makes that direction default-deny
/// (Kubernetes semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, schemars::JsonSchema)]
pub enum PolicyType {
    Ingress,
    Egress,
}

/// L4 protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

/// A port (or range) + protocol, parsed from strings like `"9696/tcp"`,
/// `"53/udp"`, `"80"` (proto defaults to tcp), `"32000-32768/tcp"` (a range) or
/// `"*/tcp"` (all ports).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Port {
    /// Single port, or the lower bound of a range. `None` = all ports.
    pub number: Option<u16>,
    pub protocol: Protocol,
    /// Upper bound of a port range (`<start>-<end>`); `None` for a single port.
    pub end: Option<u16>,
}

impl FromStr for Port {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (num, proto) = s.split_once('/').unwrap_or((s, "tcp"));
        let protocol = match proto.to_ascii_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => return Err(format!("unknown protocol {other:?}")),
        };
        let (number, end) = if num == "*" || num.is_empty() {
            (None, None)
        } else if let Some((lo, hi)) = num.split_once('-') {
            let lo: u16 = lo.parse().map_err(|_| format!("invalid port {lo:?}"))?;
            let hi: u16 = hi.parse().map_err(|_| format!("invalid port {hi:?}"))?;
            if hi <= lo {
                return Err(format!("port range {num:?}: end must exceed start"));
            }
            (Some(lo), Some(hi))
        } else {
            let n: u16 = num.parse().map_err(|_| format!("invalid port {num:?}"))?;
            (Some(n), None)
        };
        Ok(Self {
            number,
            protocol,
            end,
        })
    }
}

impl TryFrom<String> for Port {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let proto = match self.protocol {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        };
        match (self.number, self.end) {
            (Some(n), Some(e)) => write!(f, "{n}-{e}/{proto}"),
            (Some(n), None) => write!(f, "{n}/{proto}"),
            (None, _) => write!(f, "*/{proto}"),
        }
    }
}

impl schemars::JsonSchema for Port {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Port".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "description": "L4 port as `<number>/<proto>`, a range `<start>-<end>/<proto>`, or `*`/omitted for all ports (proto defaults to tcp).",
            "examples": ["443/tcp", "53/udp", "80", "32000-32768/tcp"]
        })
    }
}

/// A policy peer. `cidr` (+ `except`) is a standalone address block; `container`,
/// `network` and `selector` are container-identity filters that combine (AND) —
/// set several to match only containers satisfying all of them. Maps to
/// Kubernetes peers: `selector` ≈ `podSelector`, `network` ≈ `namespaceSelector`,
/// `cidr`/`except` ≈ `ipBlock`; `container` (by Docker name) is a suho extension.
#[derive(Debug, Clone, PartialEq, Eq, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// A single container by its Docker name.
    pub container: Option<String>,
    /// A Docker network name (every container attached to it).
    pub network: Option<String>,
    /// A CIDR block, e.g. `0.0.0.0/0`.
    pub cidr: Option<String>,
    /// CIDRs to exclude from `cidr` (≈ `ipBlock.except`); ignored without `cidr`.
    #[serde(default)]
    pub except: Vec<String>,
    /// Arbitrary label match (e.g. `com.docker.compose.service`, or your own
    /// grouping label). ≈ `podSelector.matchLabels`.
    pub selector: Option<BTreeMap<String, String>>,
}

impl fmt::Display for Peer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(c) = &self.container {
            write!(f, "container={c}")
        } else if let Some(n) = &self.network {
            write!(f, "network={n}")
        } else if let Some(c) = &self.cidr {
            if self.except.is_empty() {
                write!(f, "cidr={c}")
            } else {
                write!(f, "cidr={c} except={:?}", self.except)
            }
        } else if let Some(s) = &self.selector {
            write!(f, "selector={s:?}")
        } else {
            write!(f, "any")
        }
    }
}

/// An ingress rule: allow traffic *from* these peers on these ports.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IngressRule {
    #[serde(default)]
    pub from: Vec<Peer>,
    #[serde(default)]
    pub ports: Vec<Port>,
}

/// An egress rule: allow traffic *to* these peers on these ports.
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    #[serde(default)]
    pub to: Vec<Peer>,
    #[serde(default)]
    pub ports: Vec<Port>,
}

/// A single network policy (≈ one Kubernetes `NetworkPolicy` spec).
#[derive(Debug, Clone, Default, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    /// Containers this policy applies to. Omitted on a `networkpolicy.<name>`
    /// label means the container carrying it; set means every container whose
    /// labels match (so one label can define policy for a whole group).
    #[serde(default)]
    pub endpoint_selector: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub policy_types: Vec<PolicyType>,
    #[serde(default)]
    pub ingress: Vec<IngressRule>,
    #[serde(default)]
    pub egress: Vec<EgressRule>,
}

/// A global, label-selected policy (≈ `CiliumClusterwideNetworkPolicy`),
/// defined in `policies/suho.yaml`.
#[derive(Debug, Clone, Deserialize, schemars::JsonSchema)]
pub struct GlobalPolicy {
    #[serde(default)]
    pub name: String,
    #[serde(flatten)]
    pub policy: NetworkPolicy,
}

/// Strict parse mirrors of the policy structs: `deny_unknown_fields` turns a
/// mistyped key (e.g. `policyTyps`) into a hard error instead of silently
/// dropping it into a weaker, fail-open policy. serde forbids
/// `deny_unknown_fields` together with `#[serde(flatten)]`, so these are flat
/// structs (kept in sync with `NetworkPolicy` / `GlobalPolicy`) used only when
/// parsing; the public types keep `flatten` for the emitted JSON schema.
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StrictPolicy {
    #[serde(default)]
    endpoint_selector: Option<BTreeMap<String, String>>,
    #[serde(default)]
    policy_types: Vec<PolicyType>,
    #[serde(default)]
    ingress: Vec<IngressRule>,
    #[serde(default)]
    egress: Vec<EgressRule>,
}

impl From<StrictPolicy> for NetworkPolicy {
    fn from(s: StrictPolicy) -> Self {
        Self {
            endpoint_selector: s.endpoint_selector,
            policy_types: s.policy_types,
            ingress: s.ingress,
            egress: s.egress,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct StrictGlobal {
    #[serde(default)]
    name: String,
    #[serde(default)]
    endpoint_selector: Option<BTreeMap<String, String>>,
    #[serde(default)]
    policy_types: Vec<PolicyType>,
    #[serde(default)]
    ingress: Vec<IngressRule>,
    #[serde(default)]
    egress: Vec<EgressRule>,
}

impl From<StrictGlobal> for GlobalPolicy {
    fn from(s: StrictGlobal) -> Self {
        Self {
            name: s.name,
            policy: NetworkPolicy {
                endpoint_selector: s.endpoint_selector,
                policy_types: s.policy_types,
                ingress: s.ingress,
                egress: s.egress,
            },
        }
    }
}

/// Parse the YAML value of a `suho.networkpolicy.<name>` label.
///
/// # Errors
/// Returns an error if the value is not a valid [`NetworkPolicy`], including an
/// unknown/misspelled field.
pub fn parse_inline(value: &str) -> Result<NetworkPolicy, serde_yaml_ng::Error> {
    serde_yaml_ng::from_str::<StrictPolicy>(value).map(Into::into)
}

/// Parse a `policies/suho.yaml` document (a list of [`GlobalPolicy`]).
///
/// # Errors
/// Returns an error if the document is not a valid list of policies, including
/// an unknown/misspelled field.
pub fn parse_globals(text: &str) -> Result<Vec<GlobalPolicy>, serde_yaml_ng::Error> {
    serde_yaml_ng::from_str::<Vec<StrictGlobal>>(text)
        .map(|raws| raws.into_iter().map(Into::into).collect())
}

/// Extract labels of the form `<prefix>.<infix>.<name>` into `(name, value)`.
fn policy_labels(
    prefix: &str,
    infix: &str,
    labels: &BTreeMap<String, String>,
) -> Vec<(String, String)> {
    let key_prefix = format!("{prefix}.{infix}.");
    labels
        .iter()
        .filter_map(|(k, v)| {
            k.strip_prefix(&key_prefix)
                .map(|name| (name.to_owned(), v.clone()))
        })
        .collect()
}

/// Inline per-container policies (`<prefix>.networkpolicy.<name>`), as
/// `(name, raw_yaml_value)` pairs.
#[must_use]
pub fn inline_policies(prefix: &str, labels: &BTreeMap<String, String>) -> Vec<(String, String)> {
    policy_labels(prefix, "networkpolicy", labels)
}

/// Whether a container's labels satisfy an endpoint selector (all key/value
/// pairs must match; an empty selector matches everything).
#[must_use]
pub fn selector_matches(
    selector: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
) -> bool {
    selector
        .iter()
        .all(|(k, v)| labels.get(k).is_some_and(|got| got == v))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::{
        PolicyType, Port, Protocol, inline_policies, parse_globals, parse_inline, selector_matches,
    };

    #[test]
    fn parses_ports() {
        assert_eq!(
            "9696/tcp".parse::<Port>().unwrap(),
            Port {
                number: Some(9696),
                protocol: Protocol::Tcp,
                end: None,
            }
        );
        assert_eq!(
            "*/udp".parse::<Port>().unwrap(),
            Port {
                number: None,
                protocol: Protocol::Udp,
                end: None,
            }
        );
        assert_eq!(
            "32000-32768/tcp".parse::<Port>().unwrap(),
            Port {
                number: Some(32000),
                protocol: Protocol::Tcp,
                end: Some(32768),
            }
        );
        // Range round-trips through Display.
        assert_eq!(
            "32000-32768/tcp".parse::<Port>().unwrap().to_string(),
            "32000-32768/tcp"
        );
        assert!("80/sctp".parse::<Port>().is_err());
        assert!("32768-32000/tcp".parse::<Port>().is_err()); // end must exceed start
        assert!("80-80/tcp".parse::<Port>().is_err());
        assert!("a-b/tcp".parse::<Port>().is_err());
    }

    #[test]
    fn parses_inline_policy() {
        let yaml = r#"
policyTypes: [Ingress, Egress]
ingress:
  - from: [{container: proxy}]
    ports: ["8989/tcp"]
egress:
  - to: [{cidr: 0.0.0.0/0}]
"#;
        let np = parse_inline(yaml).unwrap();
        assert_eq!(
            np.policy_types,
            vec![PolicyType::Ingress, PolicyType::Egress]
        );
        assert_eq!(np.ingress[0].from[0].container.as_deref(), Some("proxy"));
        assert_eq!(
            np.ingress[0].ports[0],
            Port {
                number: Some(8989),
                protocol: Protocol::Tcp,
                end: None,
            }
        );
        assert_eq!(np.egress[0].to[0].cidr.as_deref(), Some("0.0.0.0/0"));
    }

    #[test]
    fn parses_global_policy() {
        let yaml = r#"
- name: egress-world
  endpointSelector: { "suho.allow/egress-world": "true" }
  egress:
    - to: [{cidr: 0.0.0.0/0}]
"#;
        let globals = parse_globals(yaml).unwrap();
        assert_eq!(globals.len(), 1);
        assert_eq!(globals[0].name, "egress-world");
        assert_eq!(
            globals[0]
                .policy
                .endpoint_selector
                .as_ref()
                .and_then(|s| s.get("suho.allow/egress-world"))
                .map(String::as_str),
            Some("true")
        );
        assert_eq!(globals[0].policy.egress.len(), 1);
    }

    #[test]
    fn inline_policies_are_prefixed() {
        let mut labels = BTreeMap::new();
        labels.insert(
            "suho.networkpolicy.app".to_owned(),
            "policyTypes: [Egress]".to_owned(),
        );
        labels.insert("unrelated".to_owned(), "x".to_owned());
        assert_eq!(
            inline_policies("suho", &labels),
            vec![("app".to_owned(), "policyTypes: [Egress]".to_owned())]
        );
    }

    #[test]
    fn selector_matching() {
        let mut labels = BTreeMap::new();
        labels.insert("k".to_owned(), "v".to_owned());
        assert!(selector_matches(&BTreeMap::new(), &labels));
        let mut sel = BTreeMap::new();
        sel.insert("k".to_owned(), "v".to_owned());
        assert!(selector_matches(&sel, &labels));
        sel.insert("k".to_owned(), "other".to_owned());
        assert!(!selector_matches(&sel, &labels));
    }

    #[test]
    fn rejects_unknown_policy_field() {
        // A typo must fail loudly, not silently drop to a weaker (fail-open) policy.
        assert!(parse_inline("policyTyps: [Ingress]").is_err());
    }

    #[test]
    fn rejects_unknown_global_field() {
        assert!(parse_globals("- name: x\n  policyTyps: [Ingress]\n").is_err());
    }

    #[test]
    fn rejects_unknown_peer_field() {
        assert!(parse_inline("ingress:\n  - from: [{containr: db}]\n").is_err());
    }
}
