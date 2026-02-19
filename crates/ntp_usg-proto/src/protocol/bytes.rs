use crate::error::ParseError;

use super::{
    ConstPackedSizeBytes, DateFormat, FromBytes, KissOfDeath, LeapIndicator, Mode, Packet,
    PrimarySource, ReferenceIdentifier, ShortFormat, Stratum, TimestampFormat, ToBytes, Version,
};

impl FromBytes for ShortFormat {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let seconds = u16::from_be_bytes([buf[0], buf[1]]);
        let fraction = u16::from_be_bytes([buf[2], buf[3]]);
        Ok((ShortFormat { seconds, fraction }, Self::PACKED_SIZE_BYTES))
    }
}

impl FromBytes for TimestampFormat {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let seconds = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let fraction = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Ok((
            TimestampFormat { seconds, fraction },
            Self::PACKED_SIZE_BYTES,
        ))
    }
}

impl FromBytes for DateFormat {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let era_number = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let era_offset = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let fraction = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        Ok((
            DateFormat {
                era_number,
                era_offset,
                fraction,
            },
            Self::PACKED_SIZE_BYTES,
        ))
    }
}

impl FromBytes for Stratum {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        Ok((Stratum(buf[0]), 1))
    }
}

impl FromBytes for (LeapIndicator, Version, Mode) {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        let li_vn_mode = buf[0];
        let li_u8 = li_vn_mode >> 6;
        let vn_u8 = (li_vn_mode >> 3) & 0b111;
        let mode_u8 = li_vn_mode & 0b111;
        let li = LeapIndicator::try_from(li_u8).map_err(|_| ParseError::InvalidField {
            field: "leap indicator",
            value: li_u8 as u32,
        })?;
        let vn = Version(vn_u8);
        let mode = Mode::try_from(mode_u8).map_err(|_| ParseError::InvalidField {
            field: "association mode",
            value: mode_u8 as u32,
        })?;
        Ok(((li, vn, mode), 1))
    }
}

impl ReferenceIdentifier {
    /// Parse a reference identifier from 4 bytes, using stratum for disambiguation.
    ///
    /// The interpretation of the reference identifier depends on the stratum:
    /// - Stratum 0: Kiss-o'-Death code
    /// - Stratum 1: Primary source identifier
    /// - Stratum 2-15: Secondary/client reference (IPv4 or IPv6 hash)
    /// - Stratum 16+: Unknown
    pub fn from_bytes_with_stratum(bytes: [u8; 4], stratum: Stratum) -> Self {
        let u = u32::from_be_bytes(bytes);
        if stratum == Stratum::UNSPECIFIED {
            match KissOfDeath::try_from(u) {
                Ok(kod) => ReferenceIdentifier::KissOfDeath(kod),
                Err(_) => ReferenceIdentifier::Unknown(bytes),
            }
        } else if stratum == Stratum::PRIMARY {
            match PrimarySource::try_from(u) {
                Ok(src) => ReferenceIdentifier::PrimarySource(src),
                Err(_) => ReferenceIdentifier::Unknown(bytes),
            }
        } else if stratum.is_secondary() {
            ReferenceIdentifier::SecondaryOrClient(bytes)
        } else {
            ReferenceIdentifier::Unknown(bytes)
        }
    }
}

impl FromBytes for Packet {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }

        let mut offset = 0;

        let ((leap_indicator, version, mode), n) =
            <(LeapIndicator, Version, Mode)>::from_bytes(&buf[offset..])?;
        offset += n;

        let (stratum, n) = Stratum::from_bytes(&buf[offset..])?;
        offset += n;

        let poll = buf[offset] as i8;
        offset += 1;

        let precision = buf[offset] as i8;
        offset += 1;

        let (root_delay, n) = ShortFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let (root_dispersion, n) = ShortFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let ref_id_bytes = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        let reference_id = ReferenceIdentifier::from_bytes_with_stratum(ref_id_bytes, stratum);
        offset += 4;

        let (reference_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let (origin_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let (receive_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let (transmit_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        Ok((
            Packet {
                leap_indicator,
                version,
                mode,
                stratum,
                poll,
                precision,
                root_delay,
                root_dispersion,
                reference_id,
                reference_timestamp,
                origin_timestamp,
                receive_timestamp,
                transmit_timestamp,
            },
            offset,
        ))
    }
}

// Buffer-based writer implementations (io-independent).

impl ToBytes for ShortFormat {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let s = self.seconds.to_be_bytes();
        let f = self.fraction.to_be_bytes();
        buf[0] = s[0];
        buf[1] = s[1];
        buf[2] = f[0];
        buf[3] = f[1];
        Ok(Self::PACKED_SIZE_BYTES)
    }
}

impl ToBytes for TimestampFormat {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let s = self.seconds.to_be_bytes();
        let f = self.fraction.to_be_bytes();
        buf[..4].copy_from_slice(&s);
        buf[4..8].copy_from_slice(&f);
        Ok(Self::PACKED_SIZE_BYTES)
    }
}

impl ToBytes for DateFormat {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        buf[..4].copy_from_slice(&self.era_number.to_be_bytes());
        buf[4..8].copy_from_slice(&self.era_offset.to_be_bytes());
        buf[8..16].copy_from_slice(&self.fraction.to_be_bytes());
        Ok(Self::PACKED_SIZE_BYTES)
    }
}

impl ToBytes for Stratum {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        buf[0] = self.0;
        Ok(1)
    }
}

impl ToBytes for (LeapIndicator, Version, Mode) {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        let (li, vn, mode) = *self;
        let mut li_vn_mode = 0u8;
        li_vn_mode |= (li as u8) << 6;
        li_vn_mode |= vn.0 << 3;
        li_vn_mode |= mode as u8;
        buf[0] = li_vn_mode;
        Ok(1)
    }
}

impl ToBytes for ReferenceIdentifier {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let bytes = self.as_bytes();
        buf[..4].copy_from_slice(&bytes);
        Ok(Self::PACKED_SIZE_BYTES)
    }
}

impl ToBytes for Packet {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }

        let mut offset = 0;

        let li_vn_mode = (self.leap_indicator, self.version, self.mode);
        offset += li_vn_mode.to_bytes(&mut buf[offset..])?;
        offset += self.stratum.to_bytes(&mut buf[offset..])?;
        buf[offset] = self.poll as u8;
        offset += 1;
        buf[offset] = self.precision as u8;
        offset += 1;
        offset += self.root_delay.to_bytes(&mut buf[offset..])?;
        offset += self.root_dispersion.to_bytes(&mut buf[offset..])?;
        offset += self.reference_id.to_bytes(&mut buf[offset..])?;
        offset += self.reference_timestamp.to_bytes(&mut buf[offset..])?;
        offset += self.origin_timestamp.to_bytes(&mut buf[offset..])?;
        offset += self.receive_timestamp.to_bytes(&mut buf[offset..])?;
        offset += self.transmit_timestamp.to_bytes(&mut buf[offset..])?;

        Ok(offset)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    // ── ShortFormat ──────────────────────────────────────────────────

    #[test]
    fn short_format_roundtrip() {
        let sf = ShortFormat {
            seconds: 0x1234,
            fraction: 0x5678,
        };
        let mut buf = [0u8; 4];
        let written = sf.to_bytes(&mut buf).unwrap();
        assert_eq!(written, 4);
        let (decoded, consumed) = ShortFormat::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(decoded.seconds, sf.seconds);
        assert_eq!(decoded.fraction, sf.fraction);
    }

    #[test]
    fn short_format_edge_values() {
        for (s, f) in [(0u16, 0u16), (u16::MAX, u16::MAX)] {
            let sf = ShortFormat {
                seconds: s,
                fraction: f,
            };
            let mut buf = [0u8; 4];
            sf.to_bytes(&mut buf).unwrap();
            let (decoded, _) = ShortFormat::from_bytes(&buf).unwrap();
            assert_eq!(decoded.seconds, s);
            assert_eq!(decoded.fraction, f);
        }
    }

    #[test]
    fn short_format_buffer_too_short_read() {
        let buf = [0u8; 3];
        let err = ShortFormat::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            ParseError::BufferTooShort {
                needed: 4,
                available: 3
            }
        ));
    }

    #[test]
    fn short_format_buffer_too_short_write() {
        let sf = ShortFormat::default();
        let mut buf = [0u8; 3];
        let err = sf.to_bytes(&mut buf).unwrap_err();
        assert!(matches!(err, ParseError::BufferTooShort { .. }));
    }

    // ── TimestampFormat ─────────────────────────────────────────────

    #[test]
    fn timestamp_format_roundtrip() {
        let ts = TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0xABCD_1234,
        };
        let mut buf = [0u8; 8];
        let written = ts.to_bytes(&mut buf).unwrap();
        assert_eq!(written, 8);
        let (decoded, consumed) = TimestampFormat::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(decoded.seconds, ts.seconds);
        assert_eq!(decoded.fraction, ts.fraction);
    }

    #[test]
    fn timestamp_format_edge_values() {
        for (s, f) in [(0u32, 0u32), (u32::MAX, u32::MAX)] {
            let ts = TimestampFormat {
                seconds: s,
                fraction: f,
            };
            let mut buf = [0u8; 8];
            ts.to_bytes(&mut buf).unwrap();
            let (decoded, _) = TimestampFormat::from_bytes(&buf).unwrap();
            assert_eq!(decoded.seconds, s);
            assert_eq!(decoded.fraction, f);
        }
    }

    #[test]
    fn timestamp_format_buffer_too_short() {
        let buf = [0u8; 7];
        let err = TimestampFormat::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            ParseError::BufferTooShort {
                needed: 8,
                available: 7
            }
        ));
    }

    // ── DateFormat ──────────────────────────────────────────────────

    #[test]
    fn date_format_roundtrip() {
        let df = DateFormat {
            era_number: -1,
            era_offset: 0x1234_5678,
            fraction: 0xDEAD_BEEF_CAFE_BABE,
        };
        let mut buf = [0u8; 16];
        let written = df.to_bytes(&mut buf).unwrap();
        assert_eq!(written, 16);
        let (decoded, consumed) = DateFormat::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 16);
        assert_eq!(decoded.era_number, df.era_number);
        assert_eq!(decoded.era_offset, df.era_offset);
        assert_eq!(decoded.fraction, df.fraction);
    }

    #[test]
    fn date_format_buffer_too_short() {
        let buf = [0u8; 15];
        let err = DateFormat::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            ParseError::BufferTooShort {
                needed: 16,
                available: 15
            }
        ));
    }

    // ── Stratum ─────────────────────────────────────────────────────

    #[test]
    fn stratum_roundtrip() {
        for val in [0u8, 1, 2, 15, 16, 255] {
            let s = Stratum(val);
            let mut buf = [0u8; 1];
            s.to_bytes(&mut buf).unwrap();
            let (decoded, consumed) = Stratum::from_bytes(&buf).unwrap();
            assert_eq!(consumed, 1);
            assert_eq!(decoded.0, val);
        }
    }

    #[test]
    fn stratum_buffer_empty() {
        let buf: [u8; 0] = [];
        let err = Stratum::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, ParseError::BufferTooShort { .. }));
    }

    // ── (LeapIndicator, Version, Mode) ──────────────────────────────

    #[test]
    fn li_vn_mode_roundtrip() {
        let tuple = (LeapIndicator::NoWarning, Version::V4, Mode::Client);
        let mut buf = [0u8; 1];
        let written = tuple.to_bytes(&mut buf).unwrap();
        assert_eq!(written, 1);
        let (decoded, consumed) = <(LeapIndicator, Version, Mode)>::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(decoded.0, LeapIndicator::NoWarning);
        assert_eq!(decoded.1, Version::V4);
        assert_eq!(decoded.2, Mode::Client);
    }

    #[test]
    fn li_vn_mode_byte_encoding() {
        // LI=0, VN=4, Mode=3 → (0<<6)|(4<<3)|3 = 0x23
        let tuple = (LeapIndicator::NoWarning, Version::V4, Mode::Client);
        let mut buf = [0u8; 1];
        tuple.to_bytes(&mut buf).unwrap();
        assert_eq!(buf[0], 0x23);
    }

    #[test]
    fn li_vn_mode_all_leap_indicators() {
        for li in [
            LeapIndicator::NoWarning,
            LeapIndicator::AddOne,
            LeapIndicator::SubOne,
            LeapIndicator::Unknown,
        ] {
            let mut buf = [0u8; 1];
            (li, Version::V4, Mode::Server).to_bytes(&mut buf).unwrap();
            let (decoded, _) = <(LeapIndicator, Version, Mode)>::from_bytes(&buf).unwrap();
            assert_eq!(decoded.0, li);
        }
    }

    #[test]
    fn li_vn_mode_buffer_empty() {
        let buf: [u8; 0] = [];
        let err = <(LeapIndicator, Version, Mode)>::from_bytes(&buf).unwrap_err();
        assert!(matches!(err, ParseError::BufferTooShort { .. }));
    }

    // ── ReferenceIdentifier ─────────────────────────────────────────

    #[test]
    fn reference_id_to_bytes_primary() {
        let ref_id = ReferenceIdentifier::PrimarySource(PrimarySource::Gps);
        let mut buf = [0u8; 4];
        let written = ref_id.to_bytes(&mut buf).unwrap();
        assert_eq!(written, 4);
    }

    #[test]
    fn reference_id_to_bytes_secondary() {
        let ref_id = ReferenceIdentifier::SecondaryOrClient([192, 168, 1, 1]);
        let mut buf = [0u8; 4];
        ref_id.to_bytes(&mut buf).unwrap();
        assert_eq!(buf, [192, 168, 1, 1]);
    }

    #[test]
    fn reference_id_buffer_too_short() {
        let ref_id = ReferenceIdentifier::PrimarySource(PrimarySource::Gps);
        let mut buf = [0u8; 3];
        let err = ref_id.to_bytes(&mut buf).unwrap_err();
        assert!(matches!(err, ParseError::BufferTooShort { .. }));
    }

    #[test]
    fn reference_id_from_bytes_with_stratum_kod() {
        let kod = ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny);
        let bytes = kod.as_bytes();
        let decoded = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum::UNSPECIFIED);
        assert!(matches!(
            decoded,
            ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny)
        ));
    }

    #[test]
    fn reference_id_from_bytes_with_stratum_primary() {
        let src = ReferenceIdentifier::PrimarySource(PrimarySource::Gps);
        let bytes = src.as_bytes();
        let decoded = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum::PRIMARY);
        assert!(matches!(
            decoded,
            ReferenceIdentifier::PrimarySource(PrimarySource::Gps)
        ));
    }

    #[test]
    fn reference_id_from_bytes_with_stratum_secondary() {
        let bytes = [10, 0, 0, 1];
        let decoded = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum(2));
        assert!(matches!(
            decoded,
            ReferenceIdentifier::SecondaryOrClient([10, 0, 0, 1])
        ));
    }

    #[test]
    fn reference_id_from_bytes_with_stratum_unknown() {
        let bytes = [0xFF, 0xFE, 0xFD, 0xFC];
        let decoded = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum(16));
        assert!(matches!(decoded, ReferenceIdentifier::Unknown(_)));
    }

    // ── Packet ──────────────────────────────────────────────────────

    fn make_test_packet() -> Packet {
        Packet {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V4,
            mode: Mode::Client,
            stratum: Stratum::UNSPECIFIED,
            poll: 6,
            precision: -20,
            root_delay: ShortFormat {
                seconds: 1,
                fraction: 0x8000,
            },
            root_dispersion: ShortFormat {
                seconds: 0,
                fraction: 0x4000,
            },
            reference_id: ReferenceIdentifier::default(),
            reference_timestamp: TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 0,
            },
            origin_timestamp: TimestampFormat::default(),
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat {
                seconds: 3_913_056_001,
                fraction: 0x1234_5678,
            },
        }
    }

    #[test]
    fn packet_roundtrip() {
        let pkt = make_test_packet();
        let mut buf = [0u8; 48];
        let written = pkt.to_bytes(&mut buf).unwrap();
        assert_eq!(written, 48);
        let (decoded, consumed) = Packet::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 48);
        assert_eq!(decoded.leap_indicator, pkt.leap_indicator);
        assert_eq!(decoded.version, pkt.version);
        assert_eq!(decoded.mode, pkt.mode);
        assert_eq!(decoded.stratum, pkt.stratum);
        assert_eq!(decoded.poll, pkt.poll);
        assert_eq!(decoded.precision, pkt.precision);
        assert_eq!(decoded.root_delay, pkt.root_delay);
        assert_eq!(decoded.root_dispersion, pkt.root_dispersion);
        assert_eq!(decoded.reference_timestamp, pkt.reference_timestamp);
        assert_eq!(decoded.origin_timestamp, pkt.origin_timestamp);
        assert_eq!(decoded.receive_timestamp, pkt.receive_timestamp);
        assert_eq!(decoded.transmit_timestamp, pkt.transmit_timestamp);
    }

    #[test]
    fn packet_size_constant() {
        assert_eq!(Packet::PACKED_SIZE_BYTES, 48);
    }

    #[test]
    fn packet_from_bytes_too_short() {
        let buf = [0u8; 47];
        let err = Packet::from_bytes(&buf).unwrap_err();
        assert!(matches!(
            err,
            ParseError::BufferTooShort {
                needed: 48,
                available: 47
            }
        ));
    }

    #[test]
    fn packet_to_bytes_too_short() {
        let pkt = make_test_packet();
        let mut buf = [0u8; 47];
        let err = pkt.to_bytes(&mut buf).unwrap_err();
        assert!(matches!(err, ParseError::BufferTooShort { .. }));
    }

    #[test]
    fn packet_stratum1_gps_reference() {
        let pkt = Packet {
            stratum: Stratum::PRIMARY,
            reference_id: ReferenceIdentifier::PrimarySource(PrimarySource::Gps),
            ..make_test_packet()
        };
        let mut buf = [0u8; 48];
        pkt.to_bytes(&mut buf).unwrap();
        let (decoded, _) = Packet::from_bytes(&buf).unwrap();
        assert!(matches!(
            decoded.reference_id,
            ReferenceIdentifier::PrimarySource(PrimarySource::Gps)
        ));
    }

    #[test]
    fn packet_stratum0_kod() {
        let pkt = Packet {
            stratum: Stratum::UNSPECIFIED,
            reference_id: ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny),
            ..make_test_packet()
        };
        let mut buf = [0u8; 48];
        pkt.to_bytes(&mut buf).unwrap();
        let (decoded, _) = Packet::from_bytes(&buf).unwrap();
        assert!(matches!(
            decoded.reference_id,
            ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny)
        ));
    }

    #[test]
    fn packet_stratum2_secondary() {
        let pkt = Packet {
            stratum: Stratum(2),
            reference_id: ReferenceIdentifier::SecondaryOrClient([10, 0, 0, 1]),
            ..make_test_packet()
        };
        let mut buf = [0u8; 48];
        pkt.to_bytes(&mut buf).unwrap();
        let (decoded, _) = Packet::from_bytes(&buf).unwrap();
        assert!(matches!(
            decoded.reference_id,
            ReferenceIdentifier::SecondaryOrClient([10, 0, 0, 1])
        ));
    }

    #[test]
    fn packet_negative_poll_precision() {
        let pkt = Packet {
            poll: -6,
            precision: -32,
            ..make_test_packet()
        };
        let mut buf = [0u8; 48];
        pkt.to_bytes(&mut buf).unwrap();
        let (decoded, _) = Packet::from_bytes(&buf).unwrap();
        assert_eq!(decoded.poll, -6);
        assert_eq!(decoded.precision, -32);
    }

    #[test]
    fn packet_extra_bytes_ignored() {
        let pkt = make_test_packet();
        let mut buf = [0u8; 64];
        pkt.to_bytes(&mut buf).unwrap();
        let (decoded, consumed) = Packet::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 48);
        assert_eq!(decoded.version, pkt.version);
    }

    // ── Cross-module consistency ────────────────────────────────────

    #[test]
    fn bytes_and_io_produce_same_output() {
        // Verify that ToBytes (buffer-based) produces the same bytes as
        // WriteToBytes (io-based) for the same packet.
        use crate::protocol::WriteBytes;

        let pkt = make_test_packet();

        // Buffer-based
        let mut buf_bytes = [0u8; 48];
        pkt.to_bytes(&mut buf_bytes).unwrap();

        // IO-based
        let mut io_bytes = Vec::new();
        io_bytes.write_bytes(pkt).unwrap();

        assert_eq!(&buf_bytes[..], &io_bytes[..]);
    }
}
