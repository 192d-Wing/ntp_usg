use ntp_proto::error::ParseError;
use ntp_proto::protocol::{
    ConstPackedSizeBytes, DateFormat, FromBytes, KissOfDeath, LeapIndicator, Mode, Packet,
    PrimarySource, ReadBytes, ReferenceIdentifier, ShortFormat, Stratum, TimestampFormat, ToBytes,
    Version, WriteBytes,
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
    buf[16] = 0xD7;
    buf[17] = 0xBC;
    buf[18] = 0x80;
    buf[19] = 0x69;
    buf[20] = 0x00;
    buf[21] = 0x00;
    buf[22] = 0x00;
    buf[23] = 0x01;
    // origin timestamp
    buf[24] = 0xD7;
    buf[25] = 0xBB;
    buf[26] = 0xB1;
    buf[27] = 0xC2;
    buf[28] = 0x00;
    buf[29] = 0x00;
    buf[30] = 0x00;
    buf[31] = 0x01;
    // receive timestamp
    buf[32] = 0xD7;
    buf[33] = 0xBC;
    buf[34] = 0x80;
    buf[35] = 0x71;
    buf[36] = 0x00;
    buf[37] = 0x00;
    buf[38] = 0x00;
    buf[39] = 0x01;
    // transmit timestamp
    buf[40] = 0xD7;
    buf[41] = 0xBC;
    buf[42] = 0x80;
    buf[43] = 0x71;
    buf[44] = 0x00;
    buf[45] = 0x00;
    buf[46] = 0x00;
    buf[47] = 0x02;
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

// ============================================================================
// Buffer-based (io-independent) parsing tests
// ============================================================================

#[test]
fn buf_packet_from_bytes() {
    let input = [
        20u8, 1, 3, 240, 0, 0, 0, 0, 0, 0, 0, 24, 67, 68, 77, 65, 215, 188, 128, 105, 198, 169, 46,
        99, 215, 187, 177, 194, 159, 47, 120, 0, 215, 188, 128, 113, 45, 236, 230, 45, 215, 188,
        128, 113, 46, 35, 158, 108,
    ];
    let (packet, consumed) = Packet::from_bytes(&input).unwrap();
    assert_eq!(consumed, 48);
    assert_eq!(packet.leap_indicator, LeapIndicator::NoWarning);
    assert_eq!(packet.version, Version::V2);
    assert_eq!(packet.mode, Mode::Server);
    assert_eq!(packet.stratum, Stratum::PRIMARY);
    assert_eq!(packet.poll, 3);
    assert_eq!(packet.precision, -16);
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::PrimarySource(PrimarySource::Cdma)
    );
}

#[test]
fn buf_packet_to_bytes() {
    let expected_output = [
        20u8, 1, 3, 240, 0, 0, 0, 0, 0, 0, 0, 24, 67, 68, 77, 65, 215, 188, 128, 105, 198, 169, 46,
        99, 215, 187, 177, 194, 159, 47, 120, 0, 215, 188, 128, 113, 45, 236, 230, 45, 215, 188,
        128, 113, 46, 35, 158, 108,
    ];
    let packet = Packet {
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
    let written = packet.to_bytes(&mut bytes).unwrap();
    assert_eq!(written, 48);
    assert_eq!(&bytes[..], &expected_output[..]);
}

#[test]
fn buf_packet_roundtrip() {
    let input = [
        20u8, 1, 3, 240, 0, 0, 0, 0, 0, 0, 0, 24, 67, 68, 77, 65, 215, 188, 128, 105, 198, 169, 46,
        99, 215, 187, 177, 194, 159, 47, 120, 0, 215, 188, 128, 113, 45, 236, 230, 45, 215, 188,
        128, 113, 46, 35, 158, 108,
    ];
    let (packet, _) = Packet::from_bytes(&input).unwrap();
    let mut output = [0u8; Packet::PACKED_SIZE_BYTES];
    packet.to_bytes(&mut output).unwrap();
    assert_eq!(&input[..], &output[..]);
}

#[test]
fn buf_equivalence_with_io_api() {
    let input = [
        20u8, 1, 3, 240, 0, 0, 0, 0, 0, 0, 0, 24, 67, 68, 77, 65, 215, 188, 128, 105, 198, 169, 46,
        99, 215, 187, 177, 194, 159, 47, 120, 0, 215, 188, 128, 113, 45, 236, 230, 45, 215, 188,
        128, 113, 46, 35, 158, 108,
    ];

    // Parse with both APIs.
    let io_packet = (&input[..]).read_bytes::<Packet>().unwrap();
    let (buf_packet, _) = Packet::from_bytes(&input).unwrap();
    assert_eq!(io_packet, buf_packet);

    // Serialize with both APIs.
    let mut io_output = [0u8; Packet::PACKED_SIZE_BYTES];
    (&mut io_output[..]).write_bytes(io_packet).unwrap();
    let mut buf_output = [0u8; Packet::PACKED_SIZE_BYTES];
    buf_packet.to_bytes(&mut buf_output).unwrap();
    assert_eq!(&io_output[..], &buf_output[..]);
}

#[test]
fn buf_short_format_roundtrip() {
    let sf = ShortFormat {
        seconds: 1234,
        fraction: 5678,
    };
    let mut buf = [0u8; 4];
    let written = sf.to_bytes(&mut buf).unwrap();
    assert_eq!(written, 4);
    let (parsed, consumed) = ShortFormat::from_bytes(&buf).unwrap();
    assert_eq!(consumed, 4);
    assert_eq!(sf, parsed);
}

#[test]
fn buf_timestamp_format_roundtrip() {
    let ts = TimestampFormat {
        seconds: 3619455081,
        fraction: 3332976227,
    };
    let mut buf = [0u8; 8];
    let written = ts.to_bytes(&mut buf).unwrap();
    assert_eq!(written, 8);
    let (parsed, consumed) = TimestampFormat::from_bytes(&buf).unwrap();
    assert_eq!(consumed, 8);
    assert_eq!(ts, parsed);
}

#[test]
fn buf_date_format_roundtrip() {
    let df = DateFormat {
        era_number: 1,
        era_offset: 1000000,
        fraction: 0xDEADBEEFCAFEBABE,
    };
    let mut buf = [0u8; 16];
    let written = df.to_bytes(&mut buf).unwrap();
    assert_eq!(written, 16);
    let (parsed, consumed) = DateFormat::from_bytes(&buf).unwrap();
    assert_eq!(consumed, 16);
    assert_eq!(df, parsed);
}

#[test]
fn buf_buffer_too_short_errors() {
    // Empty buffer for Packet.
    let err = Packet::from_bytes(&[]).unwrap_err();
    assert_eq!(
        err,
        ParseError::BufferTooShort {
            needed: 48,
            available: 0
        }
    );

    // 47 bytes (one short).
    let err = Packet::from_bytes(&[0u8; 47]).unwrap_err();
    assert_eq!(
        err,
        ParseError::BufferTooShort {
            needed: 48,
            available: 47
        }
    );

    // Short buffer for ShortFormat.
    let err = ShortFormat::from_bytes(&[0u8; 3]).unwrap_err();
    assert_eq!(
        err,
        ParseError::BufferTooShort {
            needed: 4,
            available: 3
        }
    );

    // Short buffer for TimestampFormat.
    let err = TimestampFormat::from_bytes(&[0u8; 1]).unwrap_err();
    assert_eq!(
        err,
        ParseError::BufferTooShort {
            needed: 8,
            available: 1
        }
    );

    // Short output buffer for Packet::to_bytes.
    let packet = Packet {
        leap_indicator: LeapIndicator::NoWarning,
        version: Version::V4,
        mode: Mode::Client,
        stratum: Stratum::UNSPECIFIED,
        poll: 0,
        precision: 0,
        root_delay: ShortFormat::default(),
        root_dispersion: ShortFormat::default(),
        reference_id: ReferenceIdentifier::Unknown([0; 4]),
        reference_timestamp: TimestampFormat::default(),
        origin_timestamp: TimestampFormat::default(),
        receive_timestamp: TimestampFormat::default(),
        transmit_timestamp: TimestampFormat::default(),
    };
    let mut short_buf = [0u8; 20];
    let err = packet.to_bytes(&mut short_buf).unwrap_err();
    assert_eq!(
        err,
        ParseError::BufferTooShort {
            needed: 48,
            available: 20
        }
    );
}

#[test]
fn buf_stratum_0_kod_deny() {
    let input = make_test_packet(0, [0x44, 0x45, 0x4E, 0x59]);
    let (packet, _) = Packet::from_bytes(&input).unwrap();
    assert_eq!(packet.stratum, Stratum::UNSPECIFIED);
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny)
    );
}

#[test]
fn buf_stratum_16_unsynchronized() {
    let input = make_test_packet(16, [0x00, 0x00, 0x00, 0x00]);
    let (packet, _) = Packet::from_bytes(&input).unwrap();
    assert_eq!(packet.stratum, Stratum(16));
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::Unknown([0x00, 0x00, 0x00, 0x00])
    );
}

#[test]
fn buf_kod_roundtrip() {
    let input = make_test_packet(0, [0x44, 0x45, 0x4E, 0x59]); // DENY
    let (packet, _) = Packet::from_bytes(&input).unwrap();
    let mut output = [0u8; Packet::PACKED_SIZE_BYTES];
    packet.to_bytes(&mut output).unwrap();
    assert_eq!(&input[..], &output[..]);
}

#[test]
fn buf_extra_bytes_after_packet_ignored() {
    // 52 bytes: 48-byte packet + 4 extra bytes.
    let mut input = [0u8; 52];
    input[0] = 0x24; // LI=0, VN=4, Mode=4
    input[1] = 1; // Stratum 1
    input[12..16].copy_from_slice(b"GPS\0");
    // Put non-zero data in extra bytes.
    input[48] = 0xFF;
    input[49] = 0xFF;

    let (packet, consumed) = Packet::from_bytes(&input).unwrap();
    assert_eq!(consumed, 48);
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::PrimarySource(PrimarySource::Gps)
    );
}

// ============================================================================
// TryFrom conversion tests
// ============================================================================

#[test]
fn leap_indicator_try_from_all_variants() {
    assert_eq!(
        LeapIndicator::try_from(0u8).unwrap(),
        LeapIndicator::NoWarning
    );
    assert_eq!(LeapIndicator::try_from(1u8).unwrap(), LeapIndicator::AddOne);
    assert_eq!(LeapIndicator::try_from(2u8).unwrap(), LeapIndicator::SubOne);
    assert_eq!(
        LeapIndicator::try_from(3u8).unwrap(),
        LeapIndicator::Unknown
    );
    assert!(LeapIndicator::try_from(4u8).is_err());
    assert!(LeapIndicator::try_from(255u8).is_err());
}

#[test]
fn mode_try_from_all_variants() {
    assert_eq!(Mode::try_from(0u8).unwrap(), Mode::Reserved);
    assert_eq!(Mode::try_from(1u8).unwrap(), Mode::SymmetricActive);
    assert_eq!(Mode::try_from(2u8).unwrap(), Mode::SymmetricPassive);
    assert_eq!(Mode::try_from(3u8).unwrap(), Mode::Client);
    assert_eq!(Mode::try_from(4u8).unwrap(), Mode::Server);
    assert_eq!(Mode::try_from(5u8).unwrap(), Mode::Broadcast);
    assert_eq!(Mode::try_from(6u8).unwrap(), Mode::NtpControlMessage);
    assert_eq!(Mode::try_from(7u8).unwrap(), Mode::ReservedForPrivateUse);
    assert!(Mode::try_from(8u8).is_err());
    assert!(Mode::try_from(255u8).is_err());
}

#[test]
fn kiss_of_death_rstr_variant() {
    // RSTR = [0x52, 0x53, 0x54, 0x52]
    let input = make_test_packet(0, [0x52, 0x53, 0x54, 0x52]);
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::KissOfDeath(KissOfDeath::Rstr)
    );
    assert!(packet.reference_id.is_kiss_of_death());
}

// ============================================================================
// Version and Stratum method tests
// ============================================================================

#[test]
fn version_is_known() {
    assert!(Version::V1.is_known());
    assert!(Version::V2.is_known());
    assert!(Version::V3.is_known());
    assert!(Version::V4.is_known());

    // Parse a packet with VN=0 to get an unknown version.
    let mut buf = make_test_packet(4, [192, 168, 1, 1]);
    buf[0] &= 0xC7; // Clear version bits (VN=0)
    let packet = (&buf[..]).read_bytes::<Packet>().unwrap();
    assert!(!packet.version.is_known());

    // Parse a packet with VN=5 to get another unknown version.
    buf[0] = (buf[0] & 0xC7) | (5 << 3); // VN=5
    let packet = (&buf[..]).read_bytes::<Packet>().unwrap();
    assert!(!packet.version.is_known());
}

#[test]
fn stratum_is_secondary() {
    assert!(!Stratum::UNSPECIFIED.is_secondary());
    assert!(!Stratum::PRIMARY.is_secondary());
    assert!(Stratum::SECONDARY_MIN.is_secondary());
    assert!(Stratum(8).is_secondary());
    assert!(Stratum::SECONDARY_MAX.is_secondary());
    assert!(!Stratum::UNSYNCHRONIZED.is_secondary());
    assert!(!Stratum(17).is_secondary());
}

#[test]
fn stratum_is_reserved() {
    assert!(!Stratum::UNSPECIFIED.is_reserved());
    assert!(!Stratum::PRIMARY.is_reserved());
    assert!(!Stratum::SECONDARY_MAX.is_reserved());
    assert!(!Stratum::MAX.is_reserved());
    assert!(Stratum(17).is_reserved());
    assert!(Stratum(100).is_reserved());
    assert!(Stratum(255).is_reserved());
}

// ============================================================================
// PrimarySource Display tests
// ============================================================================

#[test]
fn primary_source_display() {
    assert_eq!(PrimarySource::Gps.to_string(), "GPS");
    assert_eq!(PrimarySource::Cdma.to_string(), "CDMA");
    assert_eq!(PrimarySource::Goes.to_string(), "GOES");
    assert_eq!(PrimarySource::Nist.to_string(), "NIST");
    assert_eq!(PrimarySource::Pps.to_string(), "PPS");
    assert_eq!(PrimarySource::Null.to_string(), "");
}

// ============================================================================
// Packet with all leap indicator and mode variants
// ============================================================================

#[test]
fn packet_with_all_leap_indicators() {
    for li_val in 0u8..=3 {
        let mut buf = make_test_packet(4, [192, 168, 1, 1]);
        buf[0] = (buf[0] & 0x3F) | (li_val << 6);
        let packet = (&buf[..]).read_bytes::<Packet>().unwrap();
        assert_eq!(
            packet.leap_indicator,
            LeapIndicator::try_from(li_val).unwrap()
        );
    }
}

#[test]
fn packet_with_all_mode_variants() {
    for mode_val in 0u8..=7 {
        let mut buf = make_test_packet(4, [192, 168, 1, 1]);
        buf[0] = (buf[0] & 0xF8) | mode_val;
        let packet = (&buf[..]).read_bytes::<Packet>().unwrap();
        assert_eq!(packet.mode, Mode::try_from(mode_val).unwrap());
    }
}

// ============================================================================
// Primary source GPS variant in packet
// ============================================================================

#[test]
fn stratum_1_gps_source() {
    let input = make_test_packet(1, [b'G', b'P', b'S', 0]);
    let packet = (&input[..]).read_bytes::<Packet>().unwrap();
    assert_eq!(packet.stratum, Stratum::PRIMARY);
    assert_eq!(
        packet.reference_id,
        ReferenceIdentifier::PrimarySource(PrimarySource::Gps)
    );
}

// ============================================================================
// ToBytes buffer-too-short errors
// ============================================================================

#[test]
fn buf_short_format_to_bytes_too_short() {
    let sf = ShortFormat {
        seconds: 1,
        fraction: 2,
    };
    let mut buf = [0u8; 3];
    let err = sf.to_bytes(&mut buf).unwrap_err();
    assert_eq!(
        err,
        ParseError::BufferTooShort {
            needed: 4,
            available: 3
        }
    );
}

#[test]
fn buf_timestamp_format_to_bytes_too_short() {
    let ts = TimestampFormat {
        seconds: 1,
        fraction: 2,
    };
    let mut buf = [0u8; 7];
    let err = ts.to_bytes(&mut buf).unwrap_err();
    assert_eq!(
        err,
        ParseError::BufferTooShort {
            needed: 8,
            available: 7
        }
    );
}

#[test]
fn buf_reference_id_to_bytes_too_short() {
    let rid = ReferenceIdentifier::PrimarySource(PrimarySource::Gps);
    let mut buf = [0u8; 3];
    let err = rid.to_bytes(&mut buf).unwrap_err();
    assert_eq!(
        err,
        ParseError::BufferTooShort {
            needed: 4,
            available: 3
        }
    );
}
