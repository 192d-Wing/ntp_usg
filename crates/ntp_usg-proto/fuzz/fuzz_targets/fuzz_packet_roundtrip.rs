#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp_proto::protocol::{ConstPackedSizeBytes, FromBytes, Packet, ToBytes};

fuzz_target!(|data: &[u8]| {
    if let Ok((packet, consumed)) = Packet::from_bytes(data) {
        // Verify we consumed exactly the expected size.
        assert_eq!(consumed, Packet::PACKED_SIZE_BYTES);

        // Serialize back and verify roundtrip.
        let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
        let written = packet
            .to_bytes(&mut buf)
            .expect("ToBytes should succeed for valid Packet");
        assert_eq!(written, Packet::PACKED_SIZE_BYTES);

        // Parse again and verify equality.
        let (packet2, _) = Packet::from_bytes(&buf).expect("roundtrip parse should succeed");
        assert_eq!(packet, packet2);
    }
});
