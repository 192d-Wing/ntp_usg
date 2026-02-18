#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::protocol::ntpv5::PacketV5;
use ntp_proto::protocol::FromBytes;

fuzz_target!(|data: &[u8]| {
    // Parse NTPv5 packets from arbitrary bytes — must not panic or cause UB.
    let _ = PacketV5::from_bytes(data);
});
