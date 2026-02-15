use ntp::protocol::{
    ConstPackedSizeBytes, KissOfDeath, LeapIndicator, Mode, Packet, PrimarySource, ReadBytes,
    ReferenceIdentifier, ShortFormat, Stratum, TimestampFormat, Version, WriteBytes,
};

#[test]
fn packet_from_bytes() {
    let input = [
        20u8, 1, 3, 240, 0, 0, 0, 0, 0, 0, 0, 24, 67, 68, 77, 65, 215, 188, 128, 105, 198, 169, 46,
        99, 215, 187, 177, 194, 159, 47, 120, 0, 215, 188, 128, 113, 45, 236, 230, 45, 215, 188,
        128, 113, 46, 35, 158, 108,
    ];
    let expected_output = Packet {
        leap_indicator: LeapIndicator::NoWarning,
        version: Version::V2,
        mode: Mode::Server,
        stratum: Stratum::PRIMARY,
        poll: 3,
        precision: -16,
        root_delay: ShortFormat {
            seconds: 0,
            fraction: 0,
        },
        root_dispersion: ShortFormat {
            seconds: 0,
            fraction: 24,
        },
        reference_id: ReferenceIdentifier::PrimarySource(PrimarySource::Cdma),
        reference_timestamp: TimestampFormat {
            seconds: 3619455081,
            fraction: 3332976227,
        },
        origin_timestamp: TimestampFormat {
            seconds: 3619402178,
            fraction: 2670688256,
        },
        receive_timestamp: TimestampFormat {
            seconds: 3619455089,
            fraction: 770500141,
        },
        transmit_timestamp: TimestampFormat {
            seconds: 3619455089,
            fraction: 774086252,
        },
    };

    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    assert_eq!(expected_output, packet);
}

#[test]
fn packet_to_bytes() {
    let expected_output = [
        20, 1, 3, 240, 0, 0, 0, 0, 0, 0, 0, 24, 67, 68, 77, 65, 215, 188, 128, 105, 198, 169, 46,
        99, 215, 187, 177, 194, 159, 47, 120, 0, 215, 188, 128, 113, 45, 236, 230, 45, 215, 188,
        128, 113, 46, 35, 158, 108,
    ];
    let input = Packet {
        leap_indicator: LeapIndicator::NoWarning,
        version: Version::V2,
        mode: Mode::Server,
        stratum: Stratum::PRIMARY,
        poll: 3,
        precision: -16,
        root_delay: ShortFormat {
            seconds: 0,
            fraction: 0,
        },
        root_dispersion: ShortFormat {
            seconds: 0,
            fraction: 24,
        },
        reference_id: ReferenceIdentifier::PrimarySource(PrimarySource::Cdma),
        reference_timestamp: TimestampFormat {
            seconds: 3619455081,
            fraction: 3332976227,
        },
        origin_timestamp: TimestampFormat {
            seconds: 3619402178,
            fraction: 2670688256,
        },
        receive_timestamp: TimestampFormat {
            seconds: 3619455089,
            fraction: 770500141,
        },
        transmit_timestamp: TimestampFormat {
            seconds: 3619455089,
            fraction: 774086252,
        },
    };
    let mut bytes = [0u8; Packet::PACKED_SIZE_BYTES];
    (&mut bytes[..]).write_bytes(input).unwrap();
    assert_eq!(&bytes[..], &expected_output[..]);
}

#[test]
fn packet_conversion_roundtrip() {
    let input = [
        20, 1, 3, 240, 0, 0, 0, 0, 0, 0, 0, 24, 67, 68, 77, 65, 215, 188, 128, 105, 198, 169, 46,
        99, 215, 187, 177, 194, 159, 47, 120, 0, 215, 188, 128, 113, 45, 236, 230, 45, 215, 188,
        128, 113, 46, 35, 158, 108,
    ];
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    let mut output = [0u8; Packet::PACKED_SIZE_BYTES];
    (&mut output[..]).write_bytes(packet).unwrap();
    assert_eq!(&input[..], &output[..]);
}

/// Helper: build a 48-byte NTP packet with the given stratum and reference_id bytes.
/// Uses LI=0, VN=4, Mode=Server for all other fields.
fn make_test_packet(stratum: u8, ref_id: [u8; 4]) -> [u8; 48] {
    let mut buf = [0u8; 48];
    // Byte 0: LI=0, VN=4, Mode=4 (Server) => 0b00_100_100 = 0x24
    buf[0] = 0x24;
    buf[1] = stratum;
    buf[2] = 3; // poll
    buf[3] = 0xF0; // precision = -16 (signed)
    // Bytes 4-11: root delay + root dispersion (zeros)
    // Bytes 12-15: reference ID
    buf[12] = ref_id[0];
    buf[13] = ref_id[1];
    buf[14] = ref_id[2];
    buf[15] = ref_id[3];
    // Bytes 16-47: timestamps (set non-zero so they're valid)
    // reference timestamp
    buf[16] = 0xD7; buf[17] = 0xBC; buf[18] = 0x80; buf[19] = 0x69;
    buf[20] = 0x00; buf[21] = 0x00; buf[22] = 0x00; buf[23] = 0x01;
    // origin timestamp
    buf[24] = 0xD7; buf[25] = 0xBB; buf[26] = 0xB1; buf[27] = 0xC2;
    buf[28] = 0x00; buf[29] = 0x00; buf[30] = 0x00; buf[31] = 0x01;
    // receive timestamp
    buf[32] = 0xD7; buf[33] = 0xBC; buf[34] = 0x80; buf[35] = 0x71;
    buf[36] = 0x00; buf[37] = 0x00; buf[38] = 0x00; buf[39] = 0x01;
    // transmit timestamp
    buf[40] = 0xD7; buf[41] = 0xBC; buf[42] = 0x80; buf[43] = 0x71;
    buf[44] = 0x00; buf[45] = 0x00; buf[46] = 0x00; buf[47] = 0x02;
    buf
}

#[test]
fn stratum_0_kod_deny() {
    // DENY = [0x44, 0x45, 0x4E, 0x59]
    let input = make_test_packet(0, [0x44, 0x45, 0x4E, 0x59]);
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    assert_eq!(packet.stratum, Stratum::UNSPECIFIED);
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny)
    );
    assert!(packet.reference_id.is_kiss_of_death());
}

#[test]
fn stratum_0_kod_rate() {
    // RATE = [0x52, 0x41, 0x54, 0x45]
    let input = make_test_packet(0, [0x52, 0x41, 0x54, 0x45]);
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    assert_eq!(packet.stratum, Stratum::UNSPECIFIED);
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::KissOfDeath(KissOfDeath::Rate)
    );
}

#[test]
fn stratum_0_unknown_kiss_code() {
    // XYZW = unknown kiss code
    let input = make_test_packet(0, [b'X', b'Y', b'Z', b'W']);
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    assert_eq!(packet.stratum, Stratum::UNSPECIFIED);
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::Unknown([b'X', b'Y', b'Z', b'W'])
    );
    assert!(!packet.reference_id.is_kiss_of_death());
}

#[test]
fn stratum_1_unknown_primary_source() {
    // ABCD = unknown primary source identifier
    let input = make_test_packet(1, [b'A', b'B', b'C', b'D']);
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    assert_eq!(packet.stratum, Stratum::PRIMARY);
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::Unknown([b'A', b'B', b'C', b'D'])
    );
}

#[test]
fn stratum_16_unsynchronized() {
    let input = make_test_packet(16, [0x00, 0x00, 0x00, 0x00]);
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    assert_eq!(packet.stratum, Stratum(16));
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::Unknown([0x00, 0x00, 0x00, 0x00])
    );
}

#[test]
fn stratum_0_kod_roundtrip() {
    let input = make_test_packet(0, [0x44, 0x45, 0x4E, 0x59]); // DENY
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    let mut output = [0u8; Packet::PACKED_SIZE_BYTES];
    (&mut output[..]).write_bytes(packet).unwrap();
    assert_eq!(&input[..], &output[..]);
}

#[test]
fn unknown_variant_roundtrip() {
    let input = make_test_packet(16, [0xAA, 0xBB, 0xCC, 0xDD]);
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    let mut output = [0u8; Packet::PACKED_SIZE_BYTES];
    (&mut output[..]).write_bytes(packet).unwrap();
    assert_eq!(&input[..], &output[..]);
}

#[test]
fn reference_identifier_as_bytes() {
    let primary = ReferenceIdentifier::PrimarySource(PrimarySource::Gps);
    assert_eq!(primary.as_bytes(), [b'G', b'P', b'S', 0]);

    let secondary = ReferenceIdentifier::SecondaryOrClient([192, 168, 1, 1]);
    assert_eq!(secondary.as_bytes(), [192, 168, 1, 1]);

    let kod = ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny);
    assert_eq!(kod.as_bytes(), [b'D', b'E', b'N', b'Y']);

    let unknown = ReferenceIdentifier::Unknown([0xAA, 0xBB, 0xCC, 0xDD]);
    assert_eq!(unknown.as_bytes(), [0xAA, 0xBB, 0xCC, 0xDD]);
}
