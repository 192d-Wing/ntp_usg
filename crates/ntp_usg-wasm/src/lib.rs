// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! WebAssembly bindings for NTP packet parsing and timestamp conversion.
//!
//! This crate provides a thin JavaScript-friendly API over `ntp_usg-proto` for
//! use in browser-based packet inspection tools. Build with `wasm-pack`:
//!
//! ```sh
//! wasm-pack build crates/ntp_usg-wasm --target web
//! ```
//!
//! # Examples (JavaScript)
//!
//! ```js
//! import { NtpPacket, buildClientRequest, ntpTimestampToUnixSeconds } from 'ntp_usg-wasm';
//!
//! // Build an NTP client request
//! const request = buildClientRequest();
//!
//! // Parse a captured packet
//! const packet = new NtpPacket(capturedBytes);
//! console.log(`Version: ${packet.version}, Mode: ${packet.mode}`);
//!
//! // Convert NTP timestamp to Unix seconds
//! const ts = packet.transmitTimestamp;
//! const unixSecs = ntpTimestampToUnixSeconds(ts[0], ts[1], Date.now() / 1000);
//! ```

use wasm_bindgen::prelude::*;

use ntp_proto::extension::iter_extension_fields;
use ntp_proto::protocol::{
    self, ConstPackedSizeBytes, FromBytes, LeapIndicator, Mode, Packet, Stratum, ToBytes, Version,
};
use ntp_proto::unix_time;

/// Returns the packed size of an NTP packet header in bytes (48).
#[wasm_bindgen(js_name = "ntpPacketSize")]
pub fn ntp_packet_size() -> usize {
    Packet::PACKED_SIZE_BYTES
}

/// Parsed NTP packet with JavaScript-friendly accessors.
#[wasm_bindgen]
pub struct NtpPacket {
    inner: Packet,
}

#[wasm_bindgen]
impl NtpPacket {
    /// Parse an NTP packet from raw bytes (e.g., from a pcap capture).
    ///
    /// Expects at least 48 bytes (the NTP header).
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: &[u8]) -> Result<NtpPacket, JsError> {
        let (packet, _consumed) =
            Packet::from_bytes(bytes).map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(NtpPacket { inner: packet })
    }

    /// Leap indicator (0=no warning, 1=+1s, 2=-1s, 3=unsynchronized).
    #[wasm_bindgen(getter, js_name = "leapIndicator")]
    pub fn leap_indicator(&self) -> u8 {
        self.inner.leap_indicator as u8
    }

    /// NTP version number (typically 4).
    #[wasm_bindgen(getter)]
    pub fn version(&self) -> u8 {
        self.inner.version.value()
    }

    /// Association mode (3=client, 4=server, 5=broadcast, etc.).
    #[wasm_bindgen(getter)]
    pub fn mode(&self) -> u8 {
        self.inner.mode as u8
    }

    /// Stratum level (0=unspecified, 1=primary, 2-15=secondary, 16=unsynchronized).
    #[wasm_bindgen(getter)]
    pub fn stratum(&self) -> u8 {
        self.inner.stratum.0
    }

    /// Poll interval exponent (log2 seconds).
    #[wasm_bindgen(getter)]
    pub fn poll(&self) -> i8 {
        self.inner.poll
    }

    /// Precision exponent (log2 seconds, e.g., -18 ~ 1 microsecond).
    #[wasm_bindgen(getter)]
    pub fn precision(&self) -> i8 {
        self.inner.precision
    }

    /// Root delay in seconds.
    #[wasm_bindgen(getter, js_name = "rootDelay")]
    pub fn root_delay(&self) -> f64 {
        let sf = &self.inner.root_delay;
        sf.seconds as f64 + sf.fraction as f64 / 65536.0
    }

    /// Root dispersion in seconds.
    #[wasm_bindgen(getter, js_name = "rootDispersion")]
    pub fn root_dispersion(&self) -> f64 {
        let sf = &self.inner.root_dispersion;
        sf.seconds as f64 + sf.fraction as f64 / 65536.0
    }

    /// Reference identifier (4 bytes).
    #[wasm_bindgen(getter, js_name = "referenceId")]
    pub fn reference_id(&self) -> Vec<u8> {
        self.inner.reference_id.as_bytes().to_vec()
    }

    /// Reference timestamp as `[seconds, fraction]`.
    #[wasm_bindgen(getter, js_name = "referenceTimestamp")]
    pub fn reference_timestamp(&self) -> Vec<u32> {
        let ts = &self.inner.reference_timestamp;
        vec![ts.seconds, ts.fraction]
    }

    /// Origin timestamp as `[seconds, fraction]`.
    #[wasm_bindgen(getter, js_name = "originTimestamp")]
    pub fn origin_timestamp(&self) -> Vec<u32> {
        let ts = &self.inner.origin_timestamp;
        vec![ts.seconds, ts.fraction]
    }

    /// Receive timestamp as `[seconds, fraction]`.
    #[wasm_bindgen(getter, js_name = "receiveTimestamp")]
    pub fn receive_timestamp(&self) -> Vec<u32> {
        let ts = &self.inner.receive_timestamp;
        vec![ts.seconds, ts.fraction]
    }

    /// Transmit timestamp as `[seconds, fraction]`.
    #[wasm_bindgen(getter, js_name = "transmitTimestamp")]
    pub fn transmit_timestamp(&self) -> Vec<u32> {
        let ts = &self.inner.transmit_timestamp;
        vec![ts.seconds, ts.fraction]
    }

    /// Serialize this packet back to 48 bytes.
    #[wasm_bindgen(js_name = "toBytes")]
    pub fn to_bytes_js(&self) -> Result<Vec<u8>, JsError> {
        let mut buf = vec![0u8; Packet::PACKED_SIZE_BYTES];
        self.inner
            .to_bytes(&mut buf)
            .map_err(|e| JsError::new(&format!("{e}")))?;
        Ok(buf)
    }

    /// Human-readable debug string.
    #[wasm_bindgen(js_name = "toString")]
    pub fn to_string_js(&self) -> String {
        format!("{:?}", self.inner)
    }
}

/// Build a minimal NTPv4 client request packet (48 bytes).
#[wasm_bindgen(js_name = "buildClientRequest")]
pub fn build_client_request() -> Result<Vec<u8>, JsError> {
    let request = Packet {
        leap_indicator: LeapIndicator::NoWarning,
        version: Version::V4,
        mode: Mode::Client,
        stratum: Stratum::UNSPECIFIED,
        poll: 0,
        precision: 0,
        root_delay: protocol::ShortFormat::default(),
        root_dispersion: protocol::ShortFormat::default(),
        reference_id: protocol::ReferenceIdentifier::Unknown([0; 4]),
        reference_timestamp: protocol::TimestampFormat::default(),
        origin_timestamp: protocol::TimestampFormat::default(),
        receive_timestamp: protocol::TimestampFormat::default(),
        transmit_timestamp: protocol::TimestampFormat::default(),
    };
    let mut buf = vec![0u8; Packet::PACKED_SIZE_BYTES];
    request
        .to_bytes(&mut buf)
        .map_err(|e| JsError::new(&format!("{e}")))?;
    Ok(buf)
}

/// Convert an NTP timestamp to Unix seconds (with fractional part).
///
/// `ntp_seconds` and `ntp_fraction` are the two 32-bit components of the
/// NTP timestamp. `pivot_unix_seconds` is a reference time (e.g., `Date.now() / 1000`)
/// used for era disambiguation (needed because NTP timestamps wrap every ~136 years).
#[wasm_bindgen(js_name = "ntpTimestampToUnixSeconds")]
pub fn ntp_timestamp_to_unix_seconds(
    ntp_seconds: u32,
    ntp_fraction: u32,
    pivot_unix_seconds: f64,
) -> f64 {
    let pivot = unix_time::Instant::new(pivot_unix_seconds as i64, 0);
    let ts = protocol::TimestampFormat {
        seconds: ntp_seconds,
        fraction: ntp_fraction,
    };
    let instant = unix_time::timestamp_to_instant(ts, &pivot);
    instant.secs() as f64 + (instant.subsec_nanos() as f64 / 1e9)
}

/// Convert Unix seconds to an NTP timestamp.
///
/// Returns `[seconds, fraction]` as a two-element array.
#[wasm_bindgen(js_name = "unixSecondsToNtpTimestamp")]
pub fn unix_seconds_to_ntp_timestamp(unix_seconds: f64) -> Vec<u32> {
    let secs = unix_seconds.trunc() as i64;
    let nanos = ((unix_seconds.fract()) * 1e9) as i32;
    let instant = unix_time::Instant::new(secs, nanos);
    let ts: protocol::TimestampFormat = instant.into();
    vec![ts.seconds, ts.fraction]
}

/// Parse extension fields from bytes following the 48-byte NTP header.
///
/// Returns a JavaScript array of objects: `[{ fieldType: number, value: Uint8Array }, ...]`
#[wasm_bindgen(js_name = "parseExtensionFields")]
pub fn parse_extension_fields_js(data: &[u8]) -> Result<JsValue, JsError> {
    let arr = js_sys::Array::new();
    for result in iter_extension_fields(data) {
        let ef: ntp_proto::extension::ExtensionFieldRef<'_> =
            result.map_err(|e| JsError::new(&format!("{e}")))?;
        let obj = js_sys::Object::new();
        js_sys::Reflect::set(&obj, &"fieldType".into(), &ef.field_type.into())
            .map_err(|e| JsError::new(&format!("{e:?}")))?;
        let value = js_sys::Uint8Array::from(ef.value);
        js_sys::Reflect::set(&obj, &"value".into(), &value.into())
            .map_err(|e| JsError::new(&format!("{e:?}")))?;
        arr.push(&obj.into());
    }
    Ok(arr.into())
}
