#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::protocol::FromBytes;
use ntp_proto::protocol::Packet;

fuzz_target!(|data: &[u8]| {
    // Parse from arbitrary bytes — must not panic or cause UB.
    let _ = Packet::from_bytes(data);
});
