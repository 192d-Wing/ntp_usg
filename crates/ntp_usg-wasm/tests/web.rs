use wasm_bindgen_test::*;

use ntp_usg_wasm::{
    NtpPacket, build_client_request, ntp_timestamp_to_unix_seconds, unix_seconds_to_ntp_timestamp,
};

#[wasm_bindgen_test]
fn parse_client_request() {
    let bytes = build_client_request().unwrap();
    assert_eq!(bytes.len(), 48);

    let pkt = NtpPacket::new(&bytes).unwrap();
    assert_eq!(pkt.version(), 4);
    assert_eq!(pkt.mode(), 3); // Client
    assert_eq!(pkt.stratum(), 0); // Unspecified
    assert_eq!(pkt.leap_indicator(), 0); // NoWarning
}

#[wasm_bindgen_test]
fn roundtrip_packet() {
    let bytes = build_client_request().unwrap();
    let pkt = NtpPacket::new(&bytes).unwrap();
    let bytes2 = pkt.to_bytes_js().unwrap();
    assert_eq!(bytes, bytes2);
}

#[wasm_bindgen_test]
fn timestamp_conversion_roundtrip() {
    // 2024-01-01 00:00:00 UTC
    let unix = 1_704_067_200.0;
    let ntp = unix_seconds_to_ntp_timestamp(unix);
    assert_eq!(ntp.len(), 2);

    let back = ntp_timestamp_to_unix_seconds(ntp[0], ntp[1], unix);
    assert!((back - unix).abs() < 0.001);
}

#[wasm_bindgen_test]
fn packet_field_accessors() {
    let bytes = build_client_request().unwrap();
    let pkt = NtpPacket::new(&bytes).unwrap();

    assert_eq!(pkt.poll(), 0);
    assert_eq!(pkt.precision(), 0);
    assert_eq!(pkt.root_delay(), 0.0);
    assert_eq!(pkt.root_dispersion(), 0.0);
    assert_eq!(pkt.reference_id(), vec![0, 0, 0, 0]);

    let ref_ts = pkt.reference_timestamp();
    assert_eq!(ref_ts, vec![0, 0]);

    let origin_ts = pkt.origin_timestamp();
    assert_eq!(origin_ts, vec![0, 0]);

    let recv_ts = pkt.receive_timestamp();
    assert_eq!(recv_ts, vec![0, 0]);

    let xmit_ts = pkt.transmit_timestamp();
    assert_eq!(xmit_ts, vec![0, 0]);
}

#[wasm_bindgen_test]
fn debug_string() {
    let bytes = build_client_request().unwrap();
    let pkt = NtpPacket::new(&bytes).unwrap();
    let debug = pkt.to_string_js();
    assert!(debug.contains("Client"));
    assert!(debug.contains("V4") || debug.contains("Version(4)"));
}

#[wasm_bindgen_test]
fn parse_too_short() {
    let result = NtpPacket::new(&[0u8; 10]);
    assert!(result.is_err());
}
