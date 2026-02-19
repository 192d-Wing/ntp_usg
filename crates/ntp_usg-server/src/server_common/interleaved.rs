use tracing::debug;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        LeapIndicator, Mode, Packet, ReferenceIdentifier, ShortFormat, Stratum, TimestampFormat,
        Version,
    };

    fn ts(secs: u32, frac: u32) -> TimestampFormat {
        TimestampFormat {
            seconds: secs,
            fraction: frac,
        }
    }

    fn test_request(origin: TimestampFormat, xmt: TimestampFormat) -> Packet {
        Packet {
            leap_indicator: LeapIndicator::NoWarning,
            version: Version::V4,
            mode: Mode::Client,
            stratum: Stratum::UNSPECIFIED,
            poll: 6,
            precision: 0,
            root_delay: ShortFormat::default(),
            root_dispersion: ShortFormat::default(),
            reference_id: ReferenceIdentifier::default(),
            reference_timestamp: TimestampFormat::default(),
            origin_timestamp: origin,
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: xmt,
        }
    }

    fn test_server_state() -> ServerSystemState {
        ServerSystemState::default()
    }

    fn test_client_state(
        last_t2: TimestampFormat,
        last_t3: TimestampFormat,
        last_xmt: TimestampFormat,
    ) -> ClientState {
        let mut cs = ClientState::new(std::time::Instant::now());
        cs.last_t2 = last_t2;
        cs.last_t3 = last_t3;
        cs.last_client_xmt = last_xmt;
        cs
    }

    #[test]
    fn no_history_returns_none() {
        let req = test_request(TimestampFormat::default(), ts(100, 0));
        let state = test_server_state();
        let cs = test_client_state(
            TimestampFormat::default(),
            ts(0, 0),
            TimestampFormat::default(),
        );
        let t2 = ts(200, 0);
        assert!(build_interleaved_response(&req, &state, &cs, t2).is_none());
    }

    #[test]
    fn origin_matches_returns_some() {
        let last_t3 = ts(500, 0);
        let req = test_request(last_t3, ts(600, 0));
        let state = test_server_state();
        let cs = test_client_state(ts(400, 0), last_t3, ts(300, 0));
        let t2 = ts(700, 0);
        assert!(build_interleaved_response(&req, &state, &cs, t2).is_some());
    }

    #[test]
    fn origin_mismatch_returns_none() {
        let last_t3 = ts(500, 0);
        let req = test_request(ts(999, 0), ts(600, 0));
        let state = test_server_state();
        let cs = test_client_state(ts(400, 0), last_t3, ts(300, 0));
        let t2 = ts(700, 0);
        assert!(build_interleaved_response(&req, &state, &cs, t2).is_none());
    }

    #[test]
    fn interleaved_origin_is_last_client_xmt() {
        let last_t3 = ts(500, 0);
        let last_xmt = ts(300, 0);
        let req = test_request(last_t3, ts(600, 0));
        let state = test_server_state();
        let cs = test_client_state(ts(400, 0), last_t3, last_xmt);
        let t2 = ts(700, 0);
        let resp = build_interleaved_response(&req, &state, &cs, t2).unwrap();
        assert_eq!(resp.origin_timestamp, last_xmt);
    }

    #[test]
    fn interleaved_receive_is_last_t2() {
        let last_t3 = ts(500, 0);
        let last_t2 = ts(400, 0);
        let req = test_request(last_t3, ts(600, 0));
        let state = test_server_state();
        let cs = test_client_state(last_t2, last_t3, ts(300, 0));
        let t2 = ts(700, 0);
        let resp = build_interleaved_response(&req, &state, &cs, t2).unwrap();
        assert_eq!(resp.receive_timestamp, last_t2);
    }

    #[test]
    fn update_client_state_sets_fields() {
        let mut cs = ClientState::new(std::time::Instant::now());
        let t2 = ts(100, 1);
        let t3 = ts(200, 2);
        let xmt = ts(300, 3);
        update_client_state(&mut cs, t2, t3, xmt);
        assert_eq!(cs.last_t2, t2);
        assert_eq!(cs.last_t3, t3);
        assert_eq!(cs.last_client_xmt, xmt);
    }
}
