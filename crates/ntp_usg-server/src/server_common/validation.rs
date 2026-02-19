use std::io;

use crate::error::{NtpServerError, ProtocolError};
use crate::protocol::{self, ConstPackedSizeBytes, ReadBytes};

/// Validate an incoming NTP client request packet.
///
/// Performs the server-side checks required by RFC 5905 Section 8:
/// - Minimum packet size (48 bytes)
/// - Mode is Client (3)
/// - Version is recognized (V3 or V4)
/// - Transmit timestamp is non-zero
///
/// Returns the parsed packet on success.
pub(crate) fn validate_client_request(
    recv_buf: &[u8],
    recv_len: usize,
) -> io::Result<protocol::Packet> {
    if recv_len < protocol::Packet::PACKED_SIZE_BYTES {
        return Err(NtpServerError::Protocol(ProtocolError::RequestTooShort {
            received: recv_len,
        })
        .into());
    }

    let request: protocol::Packet =
        (&recv_buf[..protocol::Packet::PACKED_SIZE_BYTES]).read_bytes()?;

    #[cfg(not(feature = "symmetric"))]
    let valid_mode = request.mode == protocol::Mode::Client;
    #[cfg(feature = "symmetric")]
    let valid_mode =
        request.mode == protocol::Mode::Client || request.mode == protocol::Mode::SymmetricActive;

    if !valid_mode {
        return Err(NtpServerError::Protocol(ProtocolError::Other(format!(
            "unexpected request mode: expected Client, got {:?}",
            request.mode
        )))
        .into());
    }

    if !request.version.is_known() || request.version < protocol::Version::V3 {
        return Err(NtpServerError::Protocol(ProtocolError::Other(
            "unsupported NTP version".to_string(),
        ))
        .into());
    }

    if request.transmit_timestamp.seconds == 0 && request.transmit_timestamp.fraction == 0 {
        return Err(NtpServerError::Protocol(ProtocolError::ZeroTransmitTimestamp).into());
    }

    Ok(request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        ConstPackedSizeBytes, LeapIndicator, Mode, Packet, ShortFormat, Stratum, TimestampFormat,
        ToBytes, Version,
    };

    fn make_valid_client_buf() -> [u8; Packet::PACKED_SIZE_BYTES] {
        let pkt = Packet {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V4,
            mode: Mode::Client,
            stratum: Stratum::UNSPECIFIED,
            poll: 6,
            precision: -20,
            root_delay: ShortFormat::default(),
            root_dispersion: ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::default(),
            reference_timestamp: TimestampFormat::default(),
            origin_timestamp: TimestampFormat::default(),
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat {
                seconds: 1000,
                fraction: 1,
            },
        };
        let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
        pkt.to_bytes(&mut buf).unwrap();
        buf
    }

    #[test]
    fn valid_client_request() {
        let buf = make_valid_client_buf();
        let result = validate_client_request(&buf, buf.len());
        assert!(result.is_ok());
        let pkt = result.unwrap();
        assert_eq!(pkt.mode, Mode::Client);
        assert_eq!(pkt.version, Version::V4);
    }

    #[test]
    fn buffer_too_short_0() {
        let buf = [];
        assert!(validate_client_request(&buf, 0).is_err());
    }

    #[test]
    fn buffer_too_short_47() {
        let buf = [0u8; 47];
        assert!(validate_client_request(&buf, 47).is_err());
    }

    #[test]
    fn buffer_exactly_48() {
        let buf = make_valid_client_buf();
        assert!(validate_client_request(&buf, 48).is_ok());
    }

    #[test]
    fn mode_server_rejected() {
        let mut buf = make_valid_client_buf();
        // Byte 0: LI(2)|VN(3)|Mode(3). Client=3 (0b011), Server=4 (0b100).
        // Original byte0 = 0b00_100_011 = 0x23. Replace mode bits.
        buf[0] = (buf[0] & 0b1111_1000) | 4; // Mode::Server
        let result = validate_client_request(&buf, buf.len());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mode"));
    }

    #[test]
    fn mode_broadcast_rejected() {
        let mut buf = make_valid_client_buf();
        buf[0] = (buf[0] & 0b1111_1000) | 5; // Mode::Broadcast
        assert!(validate_client_request(&buf, buf.len()).is_err());
    }

    #[test]
    fn version_0_rejected() {
        let mut buf = make_valid_client_buf();
        // Byte 0: LI(2)|VN(3)|Mode(3). Set VN=0.
        buf[0] &= 0b1100_0111;
        assert!(validate_client_request(&buf, buf.len()).is_err());
    }

    #[test]
    fn version_2_rejected() {
        let mut buf = make_valid_client_buf();
        buf[0] = (buf[0] & 0b11_000_111) | (2 << 3);
        assert!(validate_client_request(&buf, buf.len()).is_err());
    }

    #[test]
    fn version_3_accepted() {
        let mut buf = make_valid_client_buf();
        buf[0] = (buf[0] & 0b11_000_111) | (3 << 3);
        assert!(validate_client_request(&buf, buf.len()).is_ok());
    }

    #[test]
    fn version_5_accepted() {
        let mut buf = make_valid_client_buf();
        buf[0] = (buf[0] & 0b11_000_111) | (5 << 3);
        assert!(validate_client_request(&buf, buf.len()).is_ok());
    }

    #[test]
    fn zero_transmit_rejected() {
        let mut buf = make_valid_client_buf();
        // Transmit timestamp at offset 40..48 — zero it out.
        buf[40..48].fill(0);
        let result = validate_client_request(&buf, buf.len());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("zero"));
    }
}
