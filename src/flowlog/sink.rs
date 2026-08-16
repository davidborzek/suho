// SPDX-License-Identifier: GPL-3.0-or-later
//! Pluggable flow-log sinks.

use std::io::{self, Write};

use crate::config::SinkKind;

use super::FlowEvent;

/// Something that consumes a parsed flow event.
pub trait FlowSink: Send + Sync {
    /// Emit one event.
    fn emit(&self, ev: &FlowEvent);
}

/// Structured JSON lines to stdout.
pub struct StdoutSink;

impl FlowSink for StdoutSink {
    fn emit(&self, ev: &FlowEvent) {
        let Ok(json) = serde_json::to_string(ev) else {
            return;
        };
        let stdout = io::stdout();
        let mut lock = stdout.lock();
        let _ = writeln!(lock, "{json}");
    }
}

/// Build a sink for the configured kind.
pub fn sink_for(kind: SinkKind) -> Box<dyn FlowSink + Send + Sync> {
    match kind {
        SinkKind::Stdout => Box::new(StdoutSink),
    }
}
