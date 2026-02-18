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

    /// Create a default NTPv4 client request packet.
    #[wasm_bindgen(js_name = "clientRequest")]
    pub fn client_request() -> NtpPacket {
        NtpPacket {
            inner: Packet::default(),
        }
    }

    /// Set the NTP version (1-5).
    #[wasm_bindgen(js_name = "setVersion")]
    pub fn set_version(&mut self, v: u8) -> Result<(), JsError> {
        self.inner.version =
            Version::new(v).ok_or_else(|| JsError::new(&format!("invalid version: {v}")))?;
        Ok(())
    }

    /// Set the association mode (0-7).
    #[wasm_bindgen(js_name = "setMode")]
    pub fn set_mode(&mut self, m: u8) -> Result<(), JsError> {
        self.inner.mode = match m {
            0 => Mode::Reserved,
            1 => Mode::SymmetricActive,
            2 => Mode::SymmetricPassive,
            3 => Mode::Client,
            4 => Mode::Server,
            5 => Mode::Broadcast,
            6 => Mode::NtpControlMessage,
            7 => Mode::ReservedForPrivateUse,
            _ => return Err(JsError::new(&format!("invalid mode: {m}"))),
        };
        Ok(())
    }

    /// Set the stratum level (0-255).
    #[wasm_bindgen(js_name = "setStratum")]
    pub fn set_stratum(&mut self, s: u8) {
        self.inner.stratum = Stratum(s);
    }

    /// Set the poll interval exponent (log2 seconds).
    #[wasm_bindgen(js_name = "setPoll")]
    pub fn set_poll(&mut self, p: i8) {
        self.inner.poll = p;
    }

    /// Set the precision exponent (log2 seconds).
    #[wasm_bindgen(js_name = "setPrecision")]
    pub fn set_precision(&mut self, p: i8) {
        self.inner.precision = p;
    }

    /// Set the transmit timestamp from `[seconds, fraction]`.
    #[wasm_bindgen(js_name = "setTransmitTimestamp")]
    pub fn set_transmit_timestamp(&mut self, seconds: u32, fraction: u32) {
        self.inner.transmit_timestamp = protocol::TimestampFormat { seconds, fraction };
    }

    /// Set the origin timestamp from `[seconds, fraction]`.
    #[wasm_bindgen(js_name = "setOriginTimestamp")]
    pub fn set_origin_timestamp(&mut self, seconds: u32, fraction: u32) {
        self.inner.origin_timestamp = protocol::TimestampFormat { seconds, fraction };
    }

    /// Set the receive timestamp from `[seconds, fraction]`.
    #[wasm_bindgen(js_name = "setReceiveTimestamp")]
    pub fn set_receive_timestamp(&mut self, seconds: u32, fraction: u32) {
        self.inner.receive_timestamp = protocol::TimestampFormat { seconds, fraction };
    }

    /// Set the reference timestamp from `[seconds, fraction]`.
    #[wasm_bindgen(js_name = "setReferenceTimestamp")]
    pub fn set_reference_timestamp(&mut self, seconds: u32, fraction: u32) {
        self.inner.reference_timestamp = protocol::TimestampFormat { seconds, fraction };
    }

    /// Set the leap indicator (0-3).
    #[wasm_bindgen(js_name = "setLeapIndicator")]
    pub fn set_leap_indicator(&mut self, li: u8) -> Result<(), JsError> {
        self.inner.leap_indicator = match li {
            0 => LeapIndicator::NoWarning,
            1 => LeapIndicator::AddOne,
            2 => LeapIndicator::SubOne,
            3 => LeapIndicator::Unknown,
            _ => return Err(JsError::new(&format!("invalid leap indicator: {li}"))),
        };
        Ok(())
    }
}

/// Build a minimal NTPv4 client request packet (48 bytes).
#[wasm_bindgen(js_name = "buildClientRequest")]
pub fn build_client_request() -> Result<Vec<u8>, JsError> {
    let request = Packet::default();
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

/// Compute clock offset and round-trip delay from four NTP timestamps.
///
/// Uses the RFC 5905 formulas:
/// - `offset = ((t2 - t1) + (t3 - t4)) / 2`
/// - `delay  = (t4 - t1) - (t3 - t2)`
///
/// Each timestamp is passed as `(seconds, fraction)` pairs in NTP format.
/// `pivot_unix_seconds` is used for era disambiguation (e.g., `Date.now() / 1000`).
///
/// Returns `{ offset: number, delay: number }` in seconds (floating-point).
#[wasm_bindgen(js_name = "computeOffsetDelay")]
#[allow(clippy::too_many_arguments)]
pub fn compute_offset_delay(
    t1_seconds: u32,
    t1_fraction: u32,
    t2_seconds: u32,
    t2_fraction: u32,
    t3_seconds: u32,
    t3_fraction: u32,
    t4_seconds: u32,
    t4_fraction: u32,
    pivot_unix_seconds: f64,
) -> Result<JsValue, JsError> {
    let pivot = unix_time::Instant::new(pivot_unix_seconds as i64, 0);

    let t1 = unix_time::timestamp_to_instant(
        protocol::TimestampFormat {
            seconds: t1_seconds,
            fraction: t1_fraction,
        },
        &pivot,
    );
    let t2 = unix_time::timestamp_to_instant(
        protocol::TimestampFormat {
            seconds: t2_seconds,
            fraction: t2_fraction,
        },
        &pivot,
    );
    let t3 = unix_time::timestamp_to_instant(
        protocol::TimestampFormat {
            seconds: t3_seconds,
            fraction: t3_fraction,
        },
        &pivot,
    );
    let t4 = unix_time::timestamp_to_instant(
        protocol::TimestampFormat {
            seconds: t4_seconds,
            fraction: t4_fraction,
        },
        &pivot,
    );

    // Convert to f64 seconds for arithmetic.
    let t1f = t1.secs() as f64 + t1.subsec_nanos() as f64 / 1e9;
    let t2f = t2.secs() as f64 + t2.subsec_nanos() as f64 / 1e9;
    let t3f = t3.secs() as f64 + t3.subsec_nanos() as f64 / 1e9;
    let t4f = t4.secs() as f64 + t4.subsec_nanos() as f64 / 1e9;

    let offset = ((t2f - t1f) + (t3f - t4f)) / 2.0;
    let delay = (t4f - t1f) - (t3f - t2f);

    let obj = js_sys::Object::new();
    js_sys::Reflect::set(&obj, &"offset".into(), &offset.into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    js_sys::Reflect::set(&obj, &"delay".into(), &delay.into())
        .map_err(|e| JsError::new(&format!("{e:?}")))?;
    Ok(obj.into())
}

/// Validate an NTP server response per RFC 5905 packet sanity checks.
///
/// Returns `null` if the response is valid, or an error string describing the
/// first validation failure found.
///
/// Checks performed:
/// 1. Packet is at least 48 bytes and parses successfully.
/// 2. Mode is Server (4).
/// 3. Stratum is not 0 (unless it's a Kiss-o'-Death).
/// 4. Transmit timestamp is not zero.
/// 5. If `origin_t1_seconds` and `origin_t1_fraction` are provided, the response's
///    origin timestamp must match (echo of client's transmit timestamp).
///
/// Kiss-o'-Death (KoD) packets (stratum=0) are flagged with the reference ID
/// as the kiss code (e.g., "DENY", "RATE", "RSTR").
#[wasm_bindgen(js_name = "validateResponse")]
pub fn validate_response(
    bytes: &[u8],
    origin_t1_seconds: Option<u32>,
    origin_t1_fraction: Option<u32>,
) -> Result<JsValue, JsError> {
    // 1. Parse
    if bytes.len() < Packet::PACKED_SIZE_BYTES {
        return Ok(JsValue::from_str(&format!(
            "packet too short: {} bytes (need {})",
            bytes.len(),
            Packet::PACKED_SIZE_BYTES
        )));
    }
    let (packet, _) = match Packet::from_bytes(bytes) {
        Ok(p) => p,
        Err(e) => return Ok(JsValue::from_str(&format!("parse error: {e}"))),
    };

    // 2. Mode check
    if packet.mode != Mode::Server {
        return Ok(JsValue::from_str(&format!(
            "unexpected mode: {} (expected 4/Server)",
            packet.mode as u8
        )));
    }

    // 3. Stratum / KoD check
    if packet.stratum.0 == 0 {
        let code = packet.reference_id.as_bytes();
        let kiss_code = core::str::from_utf8(&code)
            .unwrap_or("????")
            .trim_end_matches('\0');
        return Ok(JsValue::from_str(&format!("Kiss-o'-Death: {kiss_code}")));
    }

    // 4. Transmit timestamp not zero
    if packet.transmit_timestamp.seconds == 0 && packet.transmit_timestamp.fraction == 0 {
        return Ok(JsValue::from_str("transmit timestamp is zero"));
    }

    // 5. Origin timestamp match (if provided)
    if let (Some(t1s), Some(t1f)) = (origin_t1_seconds, origin_t1_fraction)
        && (packet.origin_timestamp.seconds != t1s || packet.origin_timestamp.fraction != t1f)
    {
        return Ok(JsValue::from_str(&format!(
            "origin timestamp mismatch: expected [{t1s}, {t1f}], got [{}, {}]",
            packet.origin_timestamp.seconds, packet.origin_timestamp.fraction
        )));
    }

    // Valid
    Ok(JsValue::NULL)
}
