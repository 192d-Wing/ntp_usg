#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::roughtime::TagValueMap;

fuzz_target!(|data: &[u8]| {
    // Parse Roughtime tag-value maps from arbitrary bytes — must not panic or cause UB.
    if let Ok(map) = TagValueMap::parse(data) {
        // Exercise accessor methods on successfully parsed maps.
        let _ = map.num_tags();
        // Try common Roughtime tags.
        let _ = map.get(b"CERT");
        let _ = map.get(b"SIG\0");
        let _ = map.get(b"SREP");
        let _ = map.get(b"MIDP");
        let _ = map.get(b"RADI");
    }
});
