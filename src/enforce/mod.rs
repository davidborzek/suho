// SPDX-License-Identifier: GPL-3.0-or-later
//! Enforcement: the desired-state IR and the backends that apply it.
//!
//! [`Ruleset`] (module [`ruleset`]) is the compiled desired state. [`Enforcer`]
//! is the backend abstraction: [`LoggingEnforcer`] is the `--dry-run` backend
//! (renders the ruleset, applies nothing); [`NftEnforcer`] programs nftables.

mod logging;
pub mod nft;
mod ruleset;

use anyhow::Result;

pub use logging::LoggingEnforcer;
pub use nft::NftEnforcer;
pub use ruleset::{Cidr, Match, Rule, Ruleset, Verdict};

/// Applies a [`Ruleset`], replacing any previous suho state.
pub trait Enforcer {
    /// Apply the desired ruleset.
    ///
    /// # Errors
    /// Fails if the ruleset cannot be applied.
    fn apply(&mut self, ruleset: &Ruleset) -> Result<()>;
}

/// Lets a boxed, runtime-selected backend satisfy the [`Enforcer`] bound, so
/// [`crate::reconcile::Reconciler`] stays generic while `main` picks the backend
/// (`--dry-run` → [`LoggingEnforcer`], otherwise [`NftEnforcer`]).
impl Enforcer for Box<dyn Enforcer> {
    fn apply(&mut self, ruleset: &Ruleset) -> Result<()> {
        (**self).apply(ruleset)
    }
}
