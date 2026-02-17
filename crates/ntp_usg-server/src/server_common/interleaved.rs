use log::debug;

use crate::protocol;

use super::{ClientState, ServerSystemState};

/// Attempt to build an interleaved-mode response for the client.
///
/// Returns `Some(packet)` if the client's origin timestamp matches our
/// previous transmit timestamp (indicating interleaved mode), or `None`
/// for basic mode.
pub(crate) fn build_interleaved_response(
    request: &protocol::Packet,
    server_state: &ServerSystemState,
    client_state: &ClientState,
    t2: protocol::TimestampFormat,
) -> Option<protocol::Packet> {
    // A zero last_t3 means we have no previous exchange to interleave with.
    if client_state.last_t3.seconds == 0 && client_state.last_t3.fraction == 0 {
        return None;
    }

    // Check if client's origin timestamp matches our previous T3.
    if request.origin_timestamp != client_state.last_t3 {
        return None;
    }

    debug!(
        "interleaved mode detected for client (origin matches prev T3: {:?})",
        client_state.last_t3
    );

    Some(protocol::Packet {
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
        // Interleaved: origin = client's previous xmt.
        origin_timestamp: client_state.last_client_xmt,
        // Interleaved: T2 from the previous exchange.
        receive_timestamp: client_state.last_t2,
        // T3 will be patched later.
        transmit_timestamp: t2, // Use current T2 as a placeholder; real T3 patched in serialize
    })
}

/// Update per-client state after a successful exchange.
pub(crate) fn update_client_state(
    client: &mut ClientState,
    t2: protocol::TimestampFormat,
    t3: protocol::TimestampFormat,
    client_xmt: protocol::TimestampFormat,
) {
    client.last_t2 = t2;
    client.last_t3 = t3;
    client.last_client_xmt = client_xmt;
}
