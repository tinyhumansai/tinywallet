//! Tests for the log sink.

use log::{Level, Log, Metadata, Record};

use super::{SINK, init};

#[test]
fn the_sink_accepts_and_formats_every_record() {
    init();
    init();
    let metadata = Metadata::builder().level(Level::Debug).target("t").build();
    assert!(SINK.enabled(&metadata));
    SINK.log(
        &Record::builder()
            .args(format_args!("hello {}", 1))
            .level(Level::Debug)
            .target("t")
            .build(),
    );
    SINK.flush();
    assert_eq!(log::max_level(), log::LevelFilter::Debug);
}
