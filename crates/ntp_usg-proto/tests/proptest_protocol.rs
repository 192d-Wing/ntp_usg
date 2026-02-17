use ntp_proto::protocol::{
    ConstPackedSizeBytes, DateFormat, FromBytes, Packet, ShortFormat, TimestampFormat, ToBytes,
};
use proptest::prelude::*;

/// Strategy that generates exactly 48 random bytes.
fn arb_48_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 48)
}

proptest! {
    #[test]
    fn short_format_roundtrip(seconds in any::<u16>(), fraction in any::<u16>()) {
        let sf = ShortFormat { seconds, fraction };
        let mut buf = [0u8; 4];
        let written = sf.to_bytes(&mut buf).unwrap();
        prop_assert_eq!(written, 4);
        let (parsed, consumed) = ShortFormat::from_bytes(&buf).unwrap();
        prop_assert_eq!(consumed, 4);
        prop_assert_eq!(sf, parsed);
    }

    #[test]
    fn timestamp_format_roundtrip(seconds in any::<u32>(), fraction in any::<u32>()) {
        let ts = TimestampFormat { seconds, fraction };
        let mut buf = [0u8; 8];
        let written = ts.to_bytes(&mut buf).unwrap();
        prop_assert_eq!(written, 8);
        let (parsed, consumed) = TimestampFormat::from_bytes(&buf).unwrap();
        prop_assert_eq!(consumed, 8);
        prop_assert_eq!(ts, parsed);
    }

    #[test]
    fn date_format_roundtrip(era_number in any::<i32>(), era_offset in any::<u32>(), fraction in any::<u64>()) {
        let df = DateFormat { era_number, era_offset, fraction };
        let mut buf = [0u8; 16];
        let written = df.to_bytes(&mut buf).unwrap();
        prop_assert_eq!(written, 16);
        let (parsed, consumed) = DateFormat::from_bytes(&buf).unwrap();
        prop_assert_eq!(consumed, 16);
        prop_assert_eq!(df, parsed);
    }

    /// Any 48 random bytes either parse successfully as a Packet or fail gracefully.
    #[test]
    fn packet_from_arbitrary_bytes_never_panics(bytes in arb_48_bytes()) {
        let _ = Packet::from_bytes(&bytes);
    }

    /// Buffers shorter than 48 bytes must always return Err.
    #[test]
    fn packet_from_short_buffer_always_errors(len in 0usize..48) {
        let buf = vec![0u8; len];
        let result = Packet::from_bytes(&buf);
        prop_assert!(result.is_err());
    }

    /// If Packet::from_bytes succeeds, roundtrip through to_bytes must be lossless.
    #[test]
    fn packet_roundtrip_when_valid(bytes in arb_48_bytes()) {
        if let Ok((packet, consumed)) = Packet::from_bytes(&bytes) {
            prop_assert_eq!(consumed, Packet::PACKED_SIZE_BYTES);
            let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
            let written = packet.to_bytes(&mut buf).unwrap();
            prop_assert_eq!(written, Packet::PACKED_SIZE_BYTES);
            let (packet2, _) = Packet::from_bytes(&buf).unwrap();
            prop_assert_eq!(packet, packet2);
        }
    }
}
