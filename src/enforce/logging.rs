// SPDX-License-Identifier: GPL-3.0-or-later
//! The `--dry-run` backend: logs the resolved ruleset and applies nothing.

use anyhow::Result;
use tracing::info;

use super::{Enforcer, Rule, Ruleset};

/// Renders the resolved ruleset to the log without touching the host.
pub struct LoggingEnforcer;

impl Enforcer for LoggingEnforcer {
    fn apply(&mut self, ruleset: &Ruleset) -> Result<()> {
        info!(
            sets = ruleset.sets.len(),
            egress = ruleset.egress.len(),
            ingress = ruleset.ingress.len(),
            "resolved ruleset (logging enforcer — nothing applied)"
        );
        for (name, addrs) in &ruleset.sets {
            let list: Vec<String> = addrs.iter().map(ToString::to_string).collect();
            info!("  set {name} = {{{}}}", list.join(", "));
        }
        log_chain("suho_egress", &ruleset.egress);
        log_chain("suho_ingress", &ruleset.ingress);
        Ok(())
    }
}

fn log_chain(name: &str, rules: &[Rule]) {
    if rules.is_empty() {
        return;
    }
    info!("  chain {name}:");
    for rule in rules {
        info!("    {rule}");
    }
}
