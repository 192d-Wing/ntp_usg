#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::extension::{iter_extension_fields, parse_extension_fields_buf};

fuzz_target!(|data: &[u8]| {
    // Test the iterator-based API (no allocation).
    for result in iter_extension_fields(data) {
        let _ = result;
    }

    // Test the allocation-based API.
    let _ = parse_extension_fields_buf(data);
});
