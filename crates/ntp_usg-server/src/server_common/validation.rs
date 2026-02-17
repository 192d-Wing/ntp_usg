use std::io;

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
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "NTP request too short",
        ));
    }

    let request: protocol::Packet =
        (&recv_buf[..protocol::Packet::PACKED_SIZE_BYTES]).read_bytes()?;

    #[cfg(not(feature = "symmetric"))]
    let valid_mode = request.mode == protocol::Mode::Client;
    #[cfg(feature = "symmetric")]
    let valid_mode =
        request.mode == protocol::Mode::Client || request.mode == protocol::Mode::SymmetricActive;

    if !valid_mode {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unexpected request mode: expected Client, got {:?}",
                request.mode
            ),
        ));
    }

    if !request.version.is_known() || request.version < protocol::Version::V3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported NTP version",
        ));
    }

    if request.transmit_timestamp.seconds == 0 && request.transmit_timestamp.fraction == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client transmit timestamp is zero",
        ));
    }

    Ok(request)
}
