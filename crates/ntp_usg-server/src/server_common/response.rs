use std::io;

use crate::protocol::{self, ConstPackedSizeBytes, WriteBytes};
use crate::unix_time;

use super::ServerSystemState;

/// Build an NTP server response packet for a client request.
///
/// Per RFC 5905 Section 8:
/// - `origin_timestamp` is set to the client's `transmit_timestamp` (anti-replay)
/// - `receive_timestamp` is T2 (when the request arrived)
/// - `transmit_timestamp` is left as default (caller patches T3 just before sending)
/// - `version` echoes the client's version
/// - `mode` is `Server`
pub(crate) fn build_server_response(
    request: &protocol::Packet,
    server_state: &ServerSystemState,
    t2: protocol::TimestampFormat,
) -> protocol::Packet {
    protocol::Packet {
        leap_indicator: server_state.leap_indicator,
        version: request.version,
        mode: protocol::Mode::Server,
        stratum: server_state.stratum,
        poll: request.poll,
        precision: server_state.precision,
        root_delay: server_state.root_delay,
        root_dispersion: server_state.root_dispersion,
        reference_id: server_state.reference_id,
        reference_timestamp: server_state.reference_timestamp,
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp: t2,
        transmit_timestamp: protocol::TimestampFormat::default(),
    }
}

/// Build a symmetric passive response (mode 2) for a symmetric active request.
///
/// Per RFC 5905 Section 8, a symmetric passive response is identical to a
/// server response but uses `Mode::SymmetricPassive` instead of `Mode::Server`.
#[cfg(feature = "symmetric")]
pub(crate) fn build_symmetric_passive_response(
    request: &protocol::Packet,
    server_state: &ServerSystemState,
    t2: protocol::TimestampFormat,
) -> protocol::Packet {
    protocol::Packet {
        leap_indicator: server_state.leap_indicator,
        version: request.version,
        mode: protocol::Mode::SymmetricPassive,
        stratum: server_state.stratum,
        poll: request.poll,
        precision: server_state.precision,
        root_delay: server_state.root_delay,
        root_dispersion: server_state.root_dispersion,
        reference_id: server_state.reference_id,
        reference_timestamp: server_state.reference_timestamp,
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp: t2,
        transmit_timestamp: protocol::TimestampFormat::default(),
    }
}

/// Build a Kiss-o'-Death (KoD) response packet.
///
/// Per RFC 5905 Section 7.4, KoD packets have stratum 0 and the reference
/// identifier set to the kiss code.
pub(crate) fn build_kod_response(
    request: &protocol::Packet,
    kod: protocol::KissOfDeath,
) -> protocol::Packet {
    protocol::Packet {
        leap_indicator: protocol::LeapIndicator::Unknown,
        version: request.version,
        mode: protocol::Mode::Server,
        stratum: protocol::Stratum::UNSPECIFIED,
        poll: request.poll,
        precision: 0,
        root_delay: protocol::ShortFormat::default(),
        root_dispersion: protocol::ShortFormat::default(),
        reference_id: protocol::ReferenceIdentifier::KissOfDeath(kod),
        reference_timestamp: protocol::TimestampFormat::default(),
        origin_timestamp: request.transmit_timestamp,
        receive_timestamp: protocol::TimestampFormat::default(),
        transmit_timestamp: protocol::TimestampFormat::default(),
    }
}

/// Serialize a response packet to bytes and patch T3 (transmit timestamp)
/// as late as possible for maximum accuracy.
///
/// Returns the serialized buffer ready to send.
pub(crate) fn serialize_response_with_t3(
    response: &protocol::Packet,
) -> io::Result<[u8; protocol::Packet::PACKED_SIZE_BYTES]> {
    let mut buf = [0u8; protocol::Packet::PACKED_SIZE_BYTES];

    // Serialize the packet with a placeholder T3.
    (&mut buf[..]).write_bytes(*response)?;

    // Patch T3 at offset 40..48 with the current time.
    let t3: protocol::TimestampFormat = unix_time::Instant::now().into();
    let t3_bytes_sec = t3.seconds.to_be_bytes();
    let t3_bytes_frac = t3.fraction.to_be_bytes();
    buf[40..44].copy_from_slice(&t3_bytes_sec);
    buf[44..48].copy_from_slice(&t3_bytes_frac);

    Ok(buf)
}
