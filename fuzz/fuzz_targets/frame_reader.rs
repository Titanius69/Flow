#![no_main]
//! Feeds arbitrary streams to the framing layer, with and without compression.

use libfuzzer_sys::fuzz_target;

use flow_proxy::protocol::connection::FrameReader;

fuzz_target!(|data: &[u8]| {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();

    runtime.block_on(async {
        let mut reader = FrameReader::new(data);
        let _ = reader.read_frame().await;

        let mut reader = FrameReader::new(data);
        reader.set_threshold(256);
        let _ = reader.read_frame().await;
    });
});
