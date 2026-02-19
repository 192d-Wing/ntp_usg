use byteorder::{BE, ReadBytesExt, WriteBytesExt};
use std::io;

#[cfg(feature = "ntpv5")]
use super::ntpv5::{NtpV5Flags, PacketV5, Time32, Timescale};
use super::{
    DateFormat, KissOfDeath, LeapIndicator, Mode, Packet, PrimarySource, ReadBytes, ReadFromBytes,
    ReferenceIdentifier, ShortFormat, Stratum, TimestampFormat, Version, WriteBytes, WriteToBytes,
    be_u32_to_bytes,
};
use crate::error::ParseError;

// Writer implementations.

impl<W> WriteBytes for W
where
    W: WriteBytesExt,
{
    fn write_bytes<P: WriteToBytes>(&mut self, protocol: P) -> io::Result<()> {
        protocol.write_to_bytes(self)
    }
}

impl<P> WriteToBytes for &P
where
    P: WriteToBytes,
{
    fn write_to_bytes<W: WriteBytesExt>(&self, writer: W) -> io::Result<()> {
        (*self).write_to_bytes(writer)
    }
}

impl WriteToBytes for ShortFormat {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<BE>(self.seconds)?;
        writer.write_u16::<BE>(self.fraction)?;
        Ok(())
    }
}

impl WriteToBytes for TimestampFormat {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<BE>(self.seconds)?;
        writer.write_u32::<BE>(self.fraction)?;
        Ok(())
    }
}

impl WriteToBytes for DateFormat {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_i32::<BE>(self.era_number)?;
        writer.write_u32::<BE>(self.era_offset)?;
        writer.write_u64::<BE>(self.fraction)?;
        Ok(())
    }
}

impl WriteToBytes for Stratum {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.0)?;
        Ok(())
    }
}

impl WriteToBytes for ReferenceIdentifier {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        match *self {
            ReferenceIdentifier::KissOfDeath(kod) => {
                writer.write_u32::<BE>(kod as u32)?;
            }
            ReferenceIdentifier::PrimarySource(src) => {
                writer.write_u32::<BE>(src as u32)?;
            }
            ReferenceIdentifier::SecondaryOrClient(arr) => {
                writer.write_u32::<BE>(code_to_u32!(&arr))?;
            }
            ReferenceIdentifier::Unknown(arr) => {
                writer.write_u32::<BE>(code_to_u32!(&arr))?;
            }
        }
        Ok(())
    }
}

impl WriteToBytes for (LeapIndicator, Version, Mode) {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        let (li, vn, mode) = *self;
        let mut li_vn_mode = 0;
        li_vn_mode |= (li as u8) << 6;
        li_vn_mode |= vn.0 << 3;
        li_vn_mode |= mode as u8;
        writer.write_u8(li_vn_mode)?;
        Ok(())
    }
}

impl WriteToBytes for Packet {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        let li_vn_mode = (self.leap_indicator, self.version, self.mode);
        writer.write_bytes(li_vn_mode)?;
        writer.write_bytes(self.stratum)?;
        writer.write_i8(self.poll)?;
        writer.write_i8(self.precision)?;
        writer.write_bytes(self.root_delay)?;
        writer.write_bytes(self.root_dispersion)?;
        writer.write_bytes(self.reference_id)?;
        writer.write_bytes(self.reference_timestamp)?;
        writer.write_bytes(self.origin_timestamp)?;
        writer.write_bytes(self.receive_timestamp)?;
        writer.write_bytes(self.transmit_timestamp)?;
        Ok(())
    }
}

// Reader implementations.

impl<R> ReadBytes for R
where
    R: ReadBytesExt,
{
    fn read_bytes<P: ReadFromBytes>(&mut self) -> io::Result<P> {
        P::read_from_bytes(self)
    }
}

impl ReadFromBytes for ShortFormat {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let seconds = reader.read_u16::<BE>()?;
        let fraction = reader.read_u16::<BE>()?;
        let short_format = ShortFormat { seconds, fraction };
        Ok(short_format)
    }
}

impl ReadFromBytes for TimestampFormat {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let seconds = reader.read_u32::<BE>()?;
        let fraction = reader.read_u32::<BE>()?;
        let timestamp_format = TimestampFormat { seconds, fraction };
        Ok(timestamp_format)
    }
}

impl ReadFromBytes for DateFormat {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let era_number = reader.read_i32::<BE>()?;
        let era_offset = reader.read_u32::<BE>()?;
        let fraction = reader.read_u64::<BE>()?;
        let date_format = DateFormat {
            era_number,
            era_offset,
            fraction,
        };
        Ok(date_format)
    }
}

impl ReadFromBytes for Stratum {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let stratum = Stratum(reader.read_u8()?);
        Ok(stratum)
    }
}

impl ReadFromBytes for (LeapIndicator, Version, Mode) {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let li_vn_mode = reader.read_u8()?;
        let li_u8 = li_vn_mode >> 6;
        let vn_u8 = (li_vn_mode >> 3) & 0b111;
        let mode_u8 = li_vn_mode & 0b111;
        let li = LeapIndicator::try_from(li_u8).map_err(|_| ParseError::InvalidField {
            field: "leap indicator",
            value: li_u8 as u32,
        })?;
        let vn = Version(vn_u8);
        let mode = Mode::try_from(mode_u8).map_err(|_| ParseError::InvalidField {
            field: "mode",
            value: mode_u8 as u32,
        })?;
        Ok((li, vn, mode))
    }
}

impl ReadFromBytes for Packet {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let (leap_indicator, version, mode) = reader.read_bytes()?;
        let stratum = reader.read_bytes::<Stratum>()?;
        let poll = reader.read_i8()?;
        let precision = reader.read_i8()?;
        let root_delay = reader.read_bytes()?;
        let root_dispersion = reader.read_bytes()?;
        let reference_id = {
            let u = reader.read_u32::<BE>()?;
            let raw_bytes = be_u32_to_bytes(u);
            if stratum == Stratum::UNSPECIFIED {
                // Stratum 0: Kiss-o'-Death packet (RFC 5905 Section 7.4).
                match KissOfDeath::try_from(u) {
                    Ok(kod) => ReferenceIdentifier::KissOfDeath(kod),
                    Err(_) => ReferenceIdentifier::Unknown(raw_bytes),
                }
            } else if stratum == Stratum::PRIMARY {
                // Stratum 1: primary reference source (4-char ASCII).
                match PrimarySource::try_from(u) {
                    Ok(src) => ReferenceIdentifier::PrimarySource(src),
                    Err(_) => ReferenceIdentifier::Unknown(raw_bytes),
                }
            } else if stratum.is_secondary() {
                // Stratum 2-15: IPv4 address or first 4 octets of MD5 hash of IPv6 address.
                ReferenceIdentifier::SecondaryOrClient(raw_bytes)
            } else {
                // Stratum 16 (unsynchronized) or 17-255 (reserved).
                ReferenceIdentifier::Unknown(raw_bytes)
            }
        };
        let reference_timestamp = reader.read_bytes()?;
        let origin_timestamp = reader.read_bytes()?;
        let receive_timestamp = reader.read_bytes()?;
        let transmit_timestamp = reader.read_bytes()?;
        Ok(Packet {
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
        })
    }
}

// ============================================================================
// NTPv5 ReadFromBytes / WriteToBytes implementations
// ============================================================================

#[cfg(feature = "ntpv5")]
impl WriteToBytes for Time32 {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<BE>(self.0)?;
        Ok(())
    }
}

#[cfg(feature = "ntpv5")]
impl ReadFromBytes for Time32 {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let raw = reader.read_u32::<BE>()?;
        Ok(Time32(raw))
    }
}

#[cfg(feature = "ntpv5")]
impl WriteToBytes for Timescale {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(*self as u8)?;
        Ok(())
    }
}

#[cfg(feature = "ntpv5")]
impl ReadFromBytes for Timescale {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let raw = reader.read_u8()?;
        Timescale::try_from(raw).map_err(|_| {
            ParseError::InvalidField {
                field: "timescale",
                value: raw as u32,
            }
            .into()
        })
    }
}

#[cfg(feature = "ntpv5")]
impl WriteToBytes for NtpV5Flags {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<BE>(self.0)?;
        Ok(())
    }
}

#[cfg(feature = "ntpv5")]
impl ReadFromBytes for NtpV5Flags {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let raw = reader.read_u16::<BE>()?;
        Ok(NtpV5Flags(raw))
    }
}

#[cfg(feature = "ntpv5")]
impl WriteToBytes for PacketV5 {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        let li_vn_mode = (self.leap_indicator, self.version, self.mode);
        writer.write_bytes(li_vn_mode)?;
        writer.write_bytes(self.stratum)?;
        writer.write_i8(self.poll)?;
        writer.write_i8(self.precision)?;
        writer.write_bytes(self.root_delay)?;
        writer.write_bytes(self.root_dispersion)?;
        writer.write_bytes(self.timescale)?;
        writer.write_u8(self.era)?;
        writer.write_bytes(self.flags)?;
        writer.write_u64::<BE>(self.server_cookie)?;
        writer.write_u64::<BE>(self.client_cookie)?;
        writer.write_bytes(self.receive_timestamp)?;
        writer.write_bytes(self.transmit_timestamp)?;
        Ok(())
    }
}

#[cfg(feature = "ntpv5")]
impl ReadFromBytes for PacketV5 {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let (leap_indicator, version, mode) = reader.read_bytes()?;
        let stratum = reader.read_bytes::<Stratum>()?;
        let poll = reader.read_i8()?;
        let precision = reader.read_i8()?;
        let root_delay = reader.read_bytes::<Time32>()?;
        let root_dispersion = reader.read_bytes::<Time32>()?;
        let timescale = reader.read_bytes::<Timescale>()?;
        let era = reader.read_u8()?;
        let flags = reader.read_bytes::<NtpV5Flags>()?;
        let server_cookie = reader.read_u64::<BE>()?;
        let client_cookie = reader.read_u64::<BE>()?;
        let receive_timestamp = reader.read_bytes()?;
        let transmit_timestamp = reader.read_bytes()?;
        Ok(PacketV5 {
            leap_indicator,
            version,
            mode,
            stratum,
            poll,
            precision,
            root_delay,
            root_dispersion,
            timescale,
            era,
            flags,
            server_cookie,
            client_cookie,
            receive_timestamp,
            transmit_timestamp,
        })
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    // ── ShortFormat ──────────────────────────────────────────────────

    #[test]
    fn short_format_roundtrip() {
        let sf = ShortFormat {
            seconds: 0x1234,
            fraction: 0x5678,
        };
        let mut buf = Vec::new();
        buf.write_bytes(sf).unwrap();
        assert_eq!(buf.len(), 4);
        let decoded: ShortFormat = Cursor::new(&buf).read_bytes().unwrap();
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
            let mut buf = Vec::new();
            buf.write_bytes(sf).unwrap();
            let decoded: ShortFormat = Cursor::new(&buf).read_bytes().unwrap();
            assert_eq!(decoded.seconds, s);
            assert_eq!(decoded.fraction, f);
        }
    }

    #[test]
    fn short_format_read_too_short() {
        let buf = [0u8; 3];
        let result = Cursor::new(&buf[..]).read_bytes::<ShortFormat>();
        assert!(result.is_err());
    }

    // ── TimestampFormat ─────────────────────────────────────────────

    #[test]
    fn timestamp_format_roundtrip() {
        let ts = TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0xABCD_1234,
        };
        let mut buf = Vec::new();
        buf.write_bytes(ts).unwrap();
        assert_eq!(buf.len(), 8);
        let decoded: TimestampFormat = Cursor::new(&buf).read_bytes().unwrap();
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
            let mut buf = Vec::new();
            buf.write_bytes(ts).unwrap();
            let decoded: TimestampFormat = Cursor::new(&buf).read_bytes().unwrap();
            assert_eq!(decoded.seconds, s);
            assert_eq!(decoded.fraction, f);
        }
    }

    #[test]
    fn timestamp_format_read_too_short() {
        let buf = [0u8; 7];
        let result = Cursor::new(&buf[..]).read_bytes::<TimestampFormat>();
        assert!(result.is_err());
    }

    // ── DateFormat ──────────────────────────────────────────────────

    #[test]
    fn date_format_roundtrip() {
        let df = DateFormat {
            era_number: -1,
            era_offset: 0x1234_5678,
            fraction: 0xDEAD_BEEF_CAFE_BABE,
        };
        let mut buf = Vec::new();
        buf.write_bytes(df).unwrap();
        assert_eq!(buf.len(), 16);
        let decoded: DateFormat = Cursor::new(&buf).read_bytes().unwrap();
        assert_eq!(decoded.era_number, df.era_number);
        assert_eq!(decoded.era_offset, df.era_offset);
        assert_eq!(decoded.fraction, df.fraction);
    }

    #[test]
    fn date_format_read_too_short() {
        let buf = [0u8; 15];
        let result = Cursor::new(&buf[..]).read_bytes::<DateFormat>();
        assert!(result.is_err());
    }

    // ── Stratum ─────────────────────────────────────────────────────

    #[test]
    fn stratum_roundtrip() {
        for val in [0u8, 1, 2, 15, 16, 255] {
            let s = Stratum(val);
            let mut buf = Vec::new();
            buf.write_bytes(s).unwrap();
            assert_eq!(buf.len(), 1);
            let decoded: Stratum = Cursor::new(&buf).read_bytes().unwrap();
            assert_eq!(decoded.0, val);
        }
    }

    #[test]
    fn stratum_read_empty() {
        let buf: [u8; 0] = [];
        let result = Cursor::new(&buf[..]).read_bytes::<Stratum>();
        assert!(result.is_err());
    }

    // ── (LeapIndicator, Version, Mode) ──────────────────────────────

    #[test]
    fn li_vn_mode_roundtrip() {
        let li = LeapIndicator::NoWarning;
        let vn = Version::V4;
        let mode = Mode::Client;
        let mut buf = Vec::new();
        buf.write_bytes((li, vn, mode)).unwrap();
        assert_eq!(buf.len(), 1);
        let (dli, dvn, dmode): (LeapIndicator, Version, Mode) =
            Cursor::new(&buf).read_bytes().unwrap();
        assert_eq!(dli, li);
        assert_eq!(dvn, vn);
        assert_eq!(dmode, mode);
    }

    #[test]
    fn li_vn_mode_all_leap_indicators() {
        for li in [
            LeapIndicator::NoWarning,
            LeapIndicator::AddOne,
            LeapIndicator::SubOne,
            LeapIndicator::Unknown,
        ] {
            let mut buf = Vec::new();
            buf.write_bytes((li, Version::V4, Mode::Server)).unwrap();
            let (dli, _, _): (LeapIndicator, Version, Mode) =
                Cursor::new(&buf).read_bytes().unwrap();
            assert_eq!(dli, li);
        }
    }

    #[test]
    fn li_vn_mode_all_modes() {
        for mode in [
            Mode::Reserved,
            Mode::SymmetricActive,
            Mode::SymmetricPassive,
            Mode::Client,
            Mode::Server,
            Mode::Broadcast,
            Mode::NtpControlMessage,
            Mode::ReservedForPrivateUse,
        ] {
            let mut buf = Vec::new();
            buf.write_bytes((LeapIndicator::NoWarning, Version::V4, mode))
                .unwrap();
            let (_, _, dm): (LeapIndicator, Version, Mode) =
                Cursor::new(&buf).read_bytes().unwrap();
            assert_eq!(dm, mode);
        }
    }

    #[test]
    fn li_vn_mode_read_empty() {
        let buf: [u8; 0] = [];
        let result = Cursor::new(&buf[..]).read_bytes::<(LeapIndicator, Version, Mode)>();
        assert!(result.is_err());
    }

    // ── ReferenceIdentifier ─────────────────────────────────────────

    #[test]
    fn reference_id_primary_source_roundtrip() {
        let ref_id = ReferenceIdentifier::PrimarySource(PrimarySource::Gps);
        let mut buf = Vec::new();
        buf.write_bytes(ref_id).unwrap();
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn reference_id_kiss_of_death_roundtrip() {
        let ref_id = ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny);
        let mut buf = Vec::new();
        buf.write_bytes(ref_id).unwrap();
        assert_eq!(buf.len(), 4);
    }

    #[test]
    fn reference_id_secondary_roundtrip() {
        let ref_id = ReferenceIdentifier::SecondaryOrClient([192, 168, 1, 1]);
        let mut buf = Vec::new();
        buf.write_bytes(ref_id).unwrap();
        assert_eq!(buf, [192, 168, 1, 1]);
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
        let mut buf = Vec::new();
        buf.write_bytes(pkt).unwrap();
        assert_eq!(buf.len(), 48);
        let decoded: Packet = Cursor::new(&buf).read_bytes().unwrap();
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
    fn packet_read_too_short() {
        let buf = [0u8; 47];
        let result = Cursor::new(&buf[..]).read_bytes::<Packet>();
        assert!(result.is_err());
    }

    #[test]
    fn packet_stratum1_gps_reference() {
        let pkt = Packet {
            stratum: Stratum::PRIMARY,
            reference_id: ReferenceIdentifier::PrimarySource(PrimarySource::Gps),
            ..make_test_packet()
        };
        let mut buf = Vec::new();
        buf.write_bytes(pkt).unwrap();
        let decoded: Packet = Cursor::new(&buf).read_bytes().unwrap();
        assert!(matches!(
            decoded.reference_id,
            ReferenceIdentifier::PrimarySource(PrimarySource::Gps)
        ));
    }

    #[test]
    fn packet_stratum0_kod_deny() {
        let pkt = Packet {
            stratum: Stratum::UNSPECIFIED,
            reference_id: ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny),
            ..make_test_packet()
        };
        let mut buf = Vec::new();
        buf.write_bytes(pkt).unwrap();
        let decoded: Packet = Cursor::new(&buf).read_bytes().unwrap();
        assert!(matches!(
            decoded.reference_id,
            ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny)
        ));
    }

    #[test]
    fn packet_stratum2_secondary_reference() {
        let pkt = Packet {
            stratum: Stratum(2),
            reference_id: ReferenceIdentifier::SecondaryOrClient([10, 0, 0, 1]),
            ..make_test_packet()
        };
        let mut buf = Vec::new();
        buf.write_bytes(pkt).unwrap();
        let decoded: Packet = Cursor::new(&buf).read_bytes().unwrap();
        assert!(matches!(
            decoded.reference_id,
            ReferenceIdentifier::SecondaryOrClient([10, 0, 0, 1])
        ));
    }

    #[test]
    fn packet_stratum16_unknown_reference() {
        let pkt = Packet {
            stratum: Stratum(16),
            reference_id: ReferenceIdentifier::Unknown([0xFF, 0xFE, 0xFD, 0xFC]),
            ..make_test_packet()
        };
        let mut buf = Vec::new();
        buf.write_bytes(pkt).unwrap();
        let decoded: Packet = Cursor::new(&buf).read_bytes().unwrap();
        assert!(matches!(
            decoded.reference_id,
            ReferenceIdentifier::Unknown([0xFF, 0xFE, 0xFD, 0xFC])
        ));
    }

    #[test]
    fn packet_negative_poll_precision() {
        let pkt = Packet {
            poll: -6,
            precision: -32,
            ..make_test_packet()
        };
        let mut buf = Vec::new();
        buf.write_bytes(pkt).unwrap();
        let decoded: Packet = Cursor::new(&buf).read_bytes().unwrap();
        assert_eq!(decoded.poll, -6);
        assert_eq!(decoded.precision, -32);
    }

    #[test]
    fn packet_reference_write_is_big_endian() {
        let pkt = make_test_packet();
        let mut buf = Vec::new();
        buf.write_bytes(pkt).unwrap();
        // Byte 0: LI=0, VN=4, Mode=3 → (0<<6)|(4<<3)|3 = 0x23
        assert_eq!(buf[0], 0x23);
    }
}
