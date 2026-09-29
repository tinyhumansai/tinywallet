//! A logger that accepts everything and keeps nothing.
//!
//! The crate logs through the `log` facade, which does not evaluate a record's
//! arguments while no logger is installed. Installing a sink makes every
//! `debug!` in the code under test actually format its arguments, so a log line
//! that would panic or is wrong to build fails a test instead of production.

use std::sync::Once;

use log::{LevelFilter, Log, Metadata, Record};

struct Sink;

impl Log for Sink {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &Record<'_>) {
        // Formatting is the point; the text is discarded.
        let _ = record.args().to_string();
    }

    fn flush(&self) {}
}

static SINK: Sink = Sink;
static INIT: Once = Once::new();

/// Install the sink once per process.
pub(crate) fn init() {
    INIT.call_once(|| {
        // Another logger may already be installed by a dependency's test
        // harness; either way the level is raised.
        let _ = log::set_logger(&SINK);
        log::set_max_level(LevelFilter::Debug);
    });
}
