// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTPv5 protocol types per `draft-ietf-ntp-ntpv5-07`.
//!
//! NTPv5 shares the same 48-byte header size as NTPv4 but with a fundamentally
//! different field layout starting at byte 12. The first 12 bytes
//! (LI/VN/Mode, Stratum, Poll, Precision, Root Delay, Root Dispersion) use
//! the same wire positions, but Root Delay/Dispersion use the higher-resolution
//! [`Time32`] format (4+28 bits) instead of NTPv4's [`super::ShortFormat`] (16+16).
//!
//! Key differences from NTPv4:
//! - Reference ID moved to 120-bit Bloom filter via extension fields
//! - Reference Timestamp moved to extension field 0xF507
//! - Origin Timestamp replaced by Client Cookie (T1 not on the wire)
//! - New fields: Timescale, Era, Flags, Server Cookie, Client Cookie
//! - Only Client (mode 3) and Server (mode 4) modes supported
//!
//! # Wire Format
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |LI | VN  |Mode |    Stratum    |     Poll      |  Precision    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Root Delay (time32)                     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Root Dispersion (time32)                  |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |   Timescale   |      Era      |             Flags             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                      Server Cookie (64)                       +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                      Client Cookie (64)                       +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                    Receive Timestamp (64)                     +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                                                               |
//! +                    Transmit Timestamp (64)                    +
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use crate::error::ParseError;

use super::{
    ConstPackedSizeBytes, FromBytes, LeapIndicator, Mode, Packet, ShortFormat, Stratum,
    TimestampFormat, ToBytes, Version,
};

/// NTPv5 `time32` format: 4-bit unsigned integer + 28-bit fraction.
///
/// Resolution: ~3.7 nanoseconds (1/2^28 seconds). Maximum value: ~16 seconds.
/// Used for Root Delay and Root Dispersion in NTPv5 (replacing NTPv4's
/// [`ShortFormat`] which has 16+16 bits and coarser ~15 µs resolution).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Time32(pub u32);

impl Time32 {
    /// The zero value.
    pub const ZERO: Self = Time32(0);

    /// Convert to seconds as `f64`.
    pub fn to_seconds_f64(self) -> f64 {
        self.0 as f64 / (1u32 << 28) as f64
    }

    /// Create from seconds as `f64`. Values ≥ 16.0 saturate to the maximum.
    pub fn from_seconds_f64(s: f64) -> Self {
        let raw = (s * (1u32 << 28) as f64) as u64;
        Time32(raw.min(u32::MAX as u64) as u32)
    }

    /// Convert from NTPv4 [`ShortFormat`] (16+16 bits) to `Time32` (4+28 bits).
    ///
    /// Values exceeding ~16 seconds are clamped to the `Time32` maximum.
    pub fn from_short_format(sf: ShortFormat) -> Self {
        // ShortFormat: seconds(16) . fraction(16)
        // Time32:      integer(4)  . fraction(28)
        // Conversion: raw32 = (seconds << 28) | (fraction << 12)
        let seconds = sf.seconds as u32;
        if seconds >= 16 {
            return Time32(u32::MAX);
        }
        let raw = (seconds << 28) | ((sf.fraction as u32) << 12);
        Time32(raw)
    }
}

impl ConstPackedSizeBytes for Time32 {
    const PACKED_SIZE_BYTES: usize = 4;
}

impl FromBytes for Time32 {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < 4 {
            return Err(ParseError::BufferTooShort {
                needed: 4,
                available: buf.len(),
            });
        }
        let raw = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        Ok((Time32(raw), 4))
    }
}

impl ToBytes for Time32 {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < 4 {
            return Err(ParseError::BufferTooShort {
                needed: 4,
                available: buf.len(),
            });
        }
        buf[..4].copy_from_slice(&self.0.to_be_bytes());
        Ok(4)
    }
}

/// NTPv5 timescale identifier.
///
/// Specifies which timescale the timestamps in the packet refer to.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Timescale {
    /// Coordinated Universal Time. Leap indicator signals pending leap seconds.
    #[default]
    Utc = 0,
    /// International Atomic Time. Leap indicator is always 0.
    Tai = 1,
    /// Universal Time (rotation-based). Leap indicator signals pending leap seconds.
    Ut1 = 2,
    /// Leap-smeared UTC. Leap indicator is always 0.
    LeapSmearedUtc = 3,
}

impl TryFrom<u8> for Timescale {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Timescale::Utc),
            1 => Ok(Timescale::Tai),
            2 => Ok(Timescale::Ut1),
            3 => Ok(Timescale::LeapSmearedUtc),
            _ => Err(()),
        }
    }
}

impl ConstPackedSizeBytes for Timescale {
    const PACKED_SIZE_BYTES: usize = 1;
}

impl FromBytes for Timescale {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        let ts = Timescale::try_from(buf[0]).map_err(|_| ParseError::InvalidField {
            field: "timescale",
            value: buf[0] as u32,
        })?;
        Ok((ts, 1))
    }
}

impl ToBytes for Timescale {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        buf[0] = *self as u8;
        Ok(1)
    }
}

/// NTPv5 flags bitfield (16 bits, bytes 14-15 of the header).
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct NtpV5Flags(pub u16);

impl NtpV5Flags {
    /// Server is synchronized to a time source.
    pub const SYNCHRONIZED: u16 = 0x0001;
    /// Interleaved mode is in use (transmit timestamp is from previous exchange).
    pub const INTERLEAVED: u16 = 0x0002;
    /// Server failed to authenticate the request.
    pub const AUTH_NAK: u16 = 0x0004;

    /// Returns `true` if the server is synchronized.
    pub fn is_synchronized(self) -> bool {
        self.0 & Self::SYNCHRONIZED != 0
    }

    /// Returns `true` if interleaved mode is active.
    pub fn is_interleaved(self) -> bool {
        self.0 & Self::INTERLEAVED != 0
    }

    /// Returns `true` if the server could not authenticate the request.
    pub fn is_auth_nak(self) -> bool {
        self.0 & Self::AUTH_NAK != 0
    }
}

impl ConstPackedSizeBytes for NtpV5Flags {
    const PACKED_SIZE_BYTES: usize = 2;
}

impl FromBytes for NtpV5Flags {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < 2 {
            return Err(ParseError::BufferTooShort {
                needed: 2,
                available: buf.len(),
            });
        }
        let raw = u16::from_be_bytes([buf[0], buf[1]]);
        Ok((NtpV5Flags(raw), 2))
    }
}

impl ToBytes for NtpV5Flags {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < 2 {
            return Err(ParseError::BufferTooShort {
                needed: 2,
                available: buf.len(),
            });
        }
        buf[..2].copy_from_slice(&self.0.to_be_bytes());
        Ok(2)
    }
}

/// NTPv5 packet header (48 bytes).
///
/// Same size as NTPv4 but with a different field layout starting at byte 12.
/// See the [module-level documentation](self) for the wire format diagram.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PacketV5 {
    /// Leap indicator warning of impending leap second.
    pub leap_indicator: LeapIndicator,
    /// NTP protocol version number (must be 5).
    pub version: Version,
    /// Association mode (Client = 3 or Server = 4 only).
    pub mode: Mode,
    /// Stratum level of the time source (0-15).
    pub stratum: Stratum,
    /// Log2 of the maximum polling interval in seconds.
    pub poll: i8,
    /// Log2 of the system clock precision in seconds.
    pub precision: i8,
    /// Total round-trip delay to the primary source (NTPv5 `time32` format).
    pub root_delay: Time32,
    /// Total dispersion to the primary source (NTPv5 `time32` format).
    pub root_dispersion: Time32,
    /// Timescale of the timestamps in this packet.
    pub timescale: Timescale,
    /// NTP era number of the receive timestamp.
    pub era: u8,
    /// Flags bitfield (synchronized, interleaved, auth NAK).
    pub flags: NtpV5Flags,
    /// Server-generated identifier for interleaved mode.
    pub server_cookie: u64,
    /// Client-generated random value for request/response matching.
    pub client_cookie: u64,
    /// Time at the server when the request arrived.
    pub receive_timestamp: TimestampFormat,
    /// Time at the server when the response was sent (or previous response in interleaved mode).
    pub transmit_timestamp: TimestampFormat,
}

impl ConstPackedSizeBytes for PacketV5 {
    const PACKED_SIZE_BYTES: usize = 48;
}

impl FromBytes for PacketV5 {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }

        let mut offset = 0;

        // Byte 0: LI(2) | VN(3) | Mode(3) — same as V4
        let ((leap_indicator, version, mode), n) =
            <(LeapIndicator, Version, Mode)>::from_bytes(&buf[offset..])?;
        offset += n;

        // Byte 1: Stratum
        let (stratum, n) = Stratum::from_bytes(&buf[offset..])?;
        offset += n;

        // Byte 2: Poll, Byte 3: Precision
        let poll = buf[offset] as i8;
        offset += 1;
        let precision = buf[offset] as i8;
        offset += 1;

        // Bytes 4-7: Root Delay (Time32)
        let (root_delay, n) = Time32::from_bytes(&buf[offset..])?;
        offset += n;

        // Bytes 8-11: Root Dispersion (Time32)
        let (root_dispersion, n) = Time32::from_bytes(&buf[offset..])?;
        offset += n;

        // Byte 12: Timescale
        let (timescale, n) = Timescale::from_bytes(&buf[offset..])?;
        offset += n;

        // Byte 13: Era
        let era = buf[offset];
        offset += 1;

        // Bytes 14-15: Flags
        let (flags, n) = NtpV5Flags::from_bytes(&buf[offset..])?;
        offset += n;

        // Bytes 16-23: Server Cookie
        let server_cookie = u64::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        offset += 8;

        // Bytes 24-31: Client Cookie
        let client_cookie = u64::from_be_bytes([
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
            buf[offset + 4],
            buf[offset + 5],
            buf[offset + 6],
            buf[offset + 7],
        ]);
        offset += 8;

        // Bytes 32-39: Receive Timestamp
        let (receive_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        // Bytes 40-47: Transmit Timestamp
        let (transmit_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        Ok((
            PacketV5 {
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
            },
            offset,
        ))
    }
}

impl ToBytes for PacketV5 {
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
        offset += self.timescale.to_bytes(&mut buf[offset..])?;
        buf[offset] = self.era;
        offset += 1;
        offset += self.flags.to_bytes(&mut buf[offset..])?;
        buf[offset..offset + 8].copy_from_slice(&self.server_cookie.to_be_bytes());
        offset += 8;
        buf[offset..offset + 8].copy_from_slice(&self.client_cookie.to_be_bytes());
        offset += 8;
        offset += self.receive_timestamp.to_bytes(&mut buf[offset..])?;
        offset += self.transmit_timestamp.to_bytes(&mut buf[offset..])?;

        Ok(offset)
    }
}

/// A version-dispatched NTP packet: either NTPv4 or NTPv5.
///
/// Peeks at the version field in byte 0 (bits 2-4) to decide which
/// packet type to parse. Useful for servers that accept both versions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionedPacket {
    /// NTPv1-v4 packet.
    V4(Packet),
    /// NTPv5 packet.
    V5(PacketV5),
}

impl FromBytes for VersionedPacket {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        let vn = (buf[0] >> 3) & 0b111;
        if vn == 5 {
            let (pkt, n) = PacketV5::from_bytes(buf)?;
            Ok((VersionedPacket::V5(pkt), n))
        } else {
            let (pkt, n) = Packet::from_bytes(buf)?;
            Ok((VersionedPacket::V4(pkt), n))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Time32 ──────────────────────────────────────────────────────

    #[test]
    fn test_time32_zero() {
        let t = Time32::ZERO;
        assert_eq!(t.to_seconds_f64(), 0.0);
    }

    #[test]
    fn test_time32_one_second() {
        let t = Time32(1 << 28);
        assert!((t.to_seconds_f64() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn test_time32_max() {
        let t = Time32(u32::MAX);
        // Max is just under 16 seconds.
        assert!(t.to_seconds_f64() < 16.0);
        assert!(t.to_seconds_f64() > 15.99);
    }

    #[test]
    fn test_time32_from_seconds_roundtrip() {
        let original = 7.123_456;
        let t = Time32::from_seconds_f64(original);
        let recovered = t.to_seconds_f64();
        // Resolution is ~3.7ns, so f64 round-trip should be very close.
        assert!((recovered - original).abs() < 1e-7);
    }

    #[test]
    fn test_time32_from_short_format() {
        // 1 second, 0 fraction in ShortFormat → 1 second in Time32
        let sf = ShortFormat {
            seconds: 1,
            fraction: 0,
        };
        let t = Time32::from_short_format(sf);
        assert!((t.to_seconds_f64() - 1.0).abs() < 1e-7);

        // 0 seconds, max fraction → almost 1 second (65535/65536)
        let sf = ShortFormat {
            seconds: 0,
            fraction: 0xFFFF,
        };
        let t = Time32::from_short_format(sf);
        assert!(t.to_seconds_f64() > 0.99);
        assert!(t.to_seconds_f64() < 1.0);
    }

    #[test]
    fn test_time32_from_short_format_clamps() {
        let sf = ShortFormat {
            seconds: 100,
            fraction: 0,
        };
        let t = Time32::from_short_format(sf);
        assert_eq!(t, Time32(u32::MAX));
    }

    #[test]
    fn test_time32_from_bytes_roundtrip() {
        let original = Time32(0xABCD_1234);
        let mut buf = [0u8; 4];
        original.to_bytes(&mut buf).unwrap();
        let (parsed, n) = Time32::from_bytes(&buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(parsed, original);
    }

    // ── Timescale ───────────────────────────────────────────────────

    #[test]
    fn test_timescale_values() {
        assert_eq!(Timescale::Utc as u8, 0);
        assert_eq!(Timescale::Tai as u8, 1);
        assert_eq!(Timescale::Ut1 as u8, 2);
        assert_eq!(Timescale::LeapSmearedUtc as u8, 3);
    }

    #[test]
    fn test_timescale_try_from() {
        assert_eq!(Timescale::try_from(0), Ok(Timescale::Utc));
        assert_eq!(Timescale::try_from(3), Ok(Timescale::LeapSmearedUtc));
        assert!(Timescale::try_from(4).is_err());
    }

    #[test]
    fn test_timescale_from_bytes_roundtrip() {
        for ts in [
            Timescale::Utc,
            Timescale::Tai,
            Timescale::Ut1,
            Timescale::LeapSmearedUtc,
        ] {
            let mut buf = [0u8; 1];
            ts.to_bytes(&mut buf).unwrap();
            let (parsed, n) = Timescale::from_bytes(&buf).unwrap();
            assert_eq!(n, 1);
            assert_eq!(parsed, ts);
        }
    }

    // ── NtpV5Flags ──────────────────────────────────────────────────

    #[test]
    fn test_flags_default() {
        let f = NtpV5Flags::default();
        assert!(!f.is_synchronized());
        assert!(!f.is_interleaved());
        assert!(!f.is_auth_nak());
    }

    #[test]
    fn test_flags_synchronized() {
        let f = NtpV5Flags(NtpV5Flags::SYNCHRONIZED);
        assert!(f.is_synchronized());
        assert!(!f.is_interleaved());
    }

    #[test]
    fn test_flags_combined() {
        let f = NtpV5Flags(NtpV5Flags::SYNCHRONIZED | NtpV5Flags::INTERLEAVED);
        assert!(f.is_synchronized());
        assert!(f.is_interleaved());
        assert!(!f.is_auth_nak());
    }

    #[test]
    fn test_flags_from_bytes_roundtrip() {
        let original = NtpV5Flags(0x0003);
        let mut buf = [0u8; 2];
        original.to_bytes(&mut buf).unwrap();
        let (parsed, n) = NtpV5Flags::from_bytes(&buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(parsed, original);
    }

    // ── PacketV5 ────────────────────────────────────────────────────

    fn sample_v5_client() -> PacketV5 {
        PacketV5 {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V5,
            mode: Mode::Client,
            stratum: Stratum::UNSPECIFIED,
            poll: 6,
            precision: -20,
            root_delay: Time32::ZERO,
            root_dispersion: Time32::ZERO,
            timescale: Timescale::Utc,
            era: 0,
            flags: NtpV5Flags::default(),
            server_cookie: 0,
            client_cookie: 0xDEAD_BEEF_CAFE_BABE,
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat::default(),
        }
    }

    fn sample_v5_server() -> PacketV5 {
        PacketV5 {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V5,
            mode: Mode::Server,
            stratum: Stratum(2),
            poll: 6,
            precision: -20,
            root_delay: Time32::from_seconds_f64(0.001),
            root_dispersion: Time32::from_seconds_f64(0.005),
            timescale: Timescale::Utc,
            era: 0,
            flags: NtpV5Flags(NtpV5Flags::SYNCHRONIZED),
            server_cookie: 0x1234_5678_9ABC_DEF0,
            client_cookie: 0xDEAD_BEEF_CAFE_BABE,
            receive_timestamp: TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 500_000_000,
            },
            transmit_timestamp: TimestampFormat {
                seconds: 3_913_056_001,
                fraction: 100_000_000,
            },
        }
    }

    #[test]
    fn test_packet_v5_size() {
        assert_eq!(PacketV5::PACKED_SIZE_BYTES, 48);
    }

    #[test]
    fn test_packet_v5_client_roundtrip() {
        let original = sample_v5_client();
        let mut buf = [0u8; 48];
        let written = original.to_bytes(&mut buf).unwrap();
        assert_eq!(written, 48);

        let (parsed, consumed) = PacketV5::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 48);
        assert_eq!(parsed, original);
    }

    #[test]
    fn test_packet_v5_server_roundtrip() {
        let original = sample_v5_server();
        let mut buf = [0u8; 48];
        original.to_bytes(&mut buf).unwrap();

        let (parsed, _) = PacketV5::from_bytes(&buf).unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.version, Version::V5);
        assert_eq!(parsed.mode, Mode::Server);
        assert!(parsed.flags.is_synchronized());
        assert_eq!(parsed.client_cookie, 0xDEAD_BEEF_CAFE_BABE);
        assert_eq!(parsed.server_cookie, 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_packet_v5_version_field() {
        let pkt = sample_v5_client();
        let mut buf = [0u8; 48];
        pkt.to_bytes(&mut buf).unwrap();

        // VN should be 5 in bits 2-4 of byte 0.
        let vn = (buf[0] >> 3) & 0b111;
        assert_eq!(vn, 5);
    }

    #[test]
    fn test_packet_v5_mode_field() {
        let pkt = sample_v5_client();
        let mut buf = [0u8; 48];
        pkt.to_bytes(&mut buf).unwrap();

        let mode = buf[0] & 0b111;
        assert_eq!(mode, 3); // Client
    }

    #[test]
    fn test_packet_v5_buffer_too_short() {
        let buf = [0u8; 47];
        let result = PacketV5::from_bytes(&buf);
        assert!(result.is_err());
    }

    // ── VersionedPacket ─────────────────────────────────────────────

    #[test]
    fn test_versioned_packet_v4() {
        let v4 = super::super::Packet {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V4,
            mode: Mode::Client,
            stratum: Stratum::UNSPECIFIED,
            poll: 0,
            precision: 0,
            root_delay: ShortFormat::default(),
            root_dispersion: ShortFormat::default(),
            reference_id: super::super::ReferenceIdentifier::PrimarySource(
                super::super::PrimarySource::Null,
            ),
            reference_timestamp: TimestampFormat::default(),
            origin_timestamp: TimestampFormat::default(),
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat {
                seconds: 100,
                fraction: 0,
            },
        };
        let mut buf = [0u8; 48];
        v4.to_bytes(&mut buf).unwrap();

        let (versioned, _) = VersionedPacket::from_bytes(&buf).unwrap();
        assert!(matches!(versioned, VersionedPacket::V4(_)));
        if let VersionedPacket::V4(pkt) = versioned {
            assert_eq!(pkt.version, Version::V4);
        }
    }

    #[test]
    fn test_versioned_packet_v5() {
        let v5 = sample_v5_server();
        let mut buf = [0u8; 48];
        v5.to_bytes(&mut buf).unwrap();

        let (versioned, _) = VersionedPacket::from_bytes(&buf).unwrap();
        assert!(matches!(versioned, VersionedPacket::V5(_)));
        if let VersionedPacket::V5(pkt) = versioned {
            assert_eq!(pkt.version, Version::V5);
            assert_eq!(pkt.client_cookie, 0xDEAD_BEEF_CAFE_BABE);
        }
    }
}
