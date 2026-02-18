// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTPv5 extension field constants and typed wrappers (`draft-ietf-ntp-ntpv5-07`).
//!
//! NTPv5 defines a provisional range of extension field type codes (0xF5xx)
//! for use during the draft period. Each type code is paired with a typed
//! struct that can be converted to/from the generic [`ExtensionField`](crate::extension::ExtensionField) type.
//!
//! # Required Extension Fields
//!
//! All NTPv5 draft requests MUST include a Draft Identification extension
//! field (0xF5FF) to prevent interop issues between draft versions.

use crate::extension::ExtensionField;
use crate::protocol::TimestampFormat;

// ============================================================================
// Extension field type codes (draft provisional, 0xF5xx range)
// ============================================================================

/// Padding extension field (0xF501).
pub const PADDING: u16 = 0xF501;

/// MAC extension field (0xF502) — AES-CMAC-128 authentication.
pub const MAC: u16 = 0xF502;

/// Reference IDs Request extension field (0xF503).
pub const REFIDS_REQUEST: u16 = 0xF503;

/// Reference IDs Response extension field (0xF504).
pub const REFIDS_RESPONSE: u16 = 0xF504;

/// Server Information extension field (0xF505).
pub const SERVER_INFO: u16 = 0xF505;

/// Correction extension field (0xF506) — PTP-compatible on-path correction.
pub const CORRECTION: u16 = 0xF506;

/// Reference Timestamp extension field (0xF507).
pub const REFERENCE_TIMESTAMP: u16 = 0xF507;

/// Monotonic Receive Timestamp extension field (0xF508).
pub const MONOTONIC_RECV_TS: u16 = 0xF508;

/// Secondary Receive Timestamp extension field (0xF509).
pub const SECONDARY_RECV_TS: u16 = 0xF509;

/// Draft Identification extension field (0xF5FF).
pub const DRAFT_IDENTIFICATION: u16 = 0xF5FF;

// ============================================================================
// Well-known constants
// ============================================================================

/// The draft identification string for `draft-ietf-ntp-ntpv5-07`.
pub const DRAFT_ID: &[u8] = b"draft-ietf-ntp-ntpv5-07";

/// Version negotiation magic for NTPv4 Reference Timestamp field (draft).
///
/// ASCII "NTP5DRFT" = `0x4E54503544524654`. Placed in the NTPv4 Reference
/// Timestamp field to signal NTPv5 support during version negotiation.
pub const NEGOTIATION_MAGIC_DRAFT: u64 = 0x4E54_5035_4452_4654;

/// Version negotiation magic for NTPv4 Reference Timestamp field (final RFC).
///
/// ASCII "NTP5NTP5" = `0x4E5450354E545035`. Used once the draft becomes an RFC.
pub const NEGOTIATION_MAGIC_RFC: u64 = 0x4E54_5035_4E54_5035;

/// NTS-KE Next Protocol ID for NTPv5 (provisional).
pub const NTS_KE_PROTOCOL_NTPV5: u16 = 0x8001;

// ============================================================================
// Typed extension field structs
// ============================================================================

/// Server Information extension field (0xF505).
///
/// Contains a bitfield of NTP versions supported by the server.
/// Bit N is set if the server supports NTP version N.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ServerInfo {
    /// Supported NTP versions bitfield.
    pub supported_versions: u16,
}

impl ServerInfo {
    /// Check if a specific NTP version is supported.
    pub fn supports_version(&self, version: u8) -> bool {
        self.supported_versions & (1 << version) != 0
    }

    /// Convert to a generic extension field.
    pub fn to_extension_field(&self) -> ExtensionField {
        ExtensionField {
            field_type: SERVER_INFO,
            value: self.supported_versions.to_be_bytes().to_vec(),
        }
    }

    /// Try to extract from a generic extension field.
    pub fn from_extension_field(ef: &ExtensionField) -> Option<Self> {
        if ef.field_type != SERVER_INFO || ef.value.len() < 2 {
            return None;
        }
        let supported_versions = u16::from_be_bytes([ef.value[0], ef.value[1]]);
        Some(ServerInfo { supported_versions })
    }
}

/// Reference IDs Request extension field (0xF503).
///
/// Sent by the client to request a chunk of the server's 512-byte Bloom filter
/// starting at the given byte offset.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RefIdsRequest {
    /// Byte offset into the 512-byte Bloom filter.
    pub offset: u16,
}

impl RefIdsRequest {
    /// Convert to a generic extension field.
    pub fn to_extension_field(&self) -> ExtensionField {
        ExtensionField {
            field_type: REFIDS_REQUEST,
            value: self.offset.to_be_bytes().to_vec(),
        }
    }

    /// Try to extract from a generic extension field.
    pub fn from_extension_field(ef: &ExtensionField) -> Option<Self> {
        if ef.field_type != REFIDS_REQUEST || ef.value.len() < 2 {
            return None;
        }
        let offset = u16::from_be_bytes([ef.value[0], ef.value[1]]);
        Some(RefIdsRequest { offset })
    }
}

/// Reference IDs Response extension field (0xF504).
///
/// Contains a chunk of the server's 512-byte Bloom filter. The client
/// assembles the full filter by requesting chunks at successive offsets.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RefIdsResponse {
    /// The Bloom filter chunk data.
    pub data: Vec<u8>,
}

impl RefIdsResponse {
    /// Convert to a generic extension field.
    pub fn to_extension_field(&self) -> ExtensionField {
        ExtensionField {
            field_type: REFIDS_RESPONSE,
            value: self.data.clone(),
        }
    }

    /// Try to extract from a generic extension field.
    pub fn from_extension_field(ef: &ExtensionField) -> Option<Self> {
        if ef.field_type != REFIDS_RESPONSE {
            return None;
        }
        Some(RefIdsResponse {
            data: ef.value.clone(),
        })
    }
}

/// Reference Timestamp extension field (0xF507).
///
/// Contains the server's reference timestamp (moved from the header in NTPv4
/// to an extension field in NTPv5).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ReferenceTimestamp {
    /// The server's reference timestamp.
    pub timestamp: TimestampFormat,
}

impl ReferenceTimestamp {
    /// Convert to a generic extension field.
    pub fn to_extension_field(&self) -> ExtensionField {
        let mut value = Vec::with_capacity(8);
        value.extend_from_slice(&self.timestamp.seconds.to_be_bytes());
        value.extend_from_slice(&self.timestamp.fraction.to_be_bytes());
        ExtensionField {
            field_type: REFERENCE_TIMESTAMP,
            value,
        }
    }

    /// Try to extract from a generic extension field.
    pub fn from_extension_field(ef: &ExtensionField) -> Option<Self> {
        if ef.field_type != REFERENCE_TIMESTAMP || ef.value.len() < 8 {
            return None;
        }
        let seconds = u32::from_be_bytes([ef.value[0], ef.value[1], ef.value[2], ef.value[3]]);
        let fraction = u32::from_be_bytes([ef.value[4], ef.value[5], ef.value[6], ef.value[7]]);
        Some(ReferenceTimestamp {
            timestamp: TimestampFormat { seconds, fraction },
        })
    }
}

/// Draft Identification extension field (0xF5FF).
///
/// MUST be included in all NTPv5 draft implementation requests.
/// Contains the ASCII draft name (e.g., `b"draft-ietf-ntp-ntpv5-07"`).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct DraftIdentification {
    /// The draft identification string.
    pub draft_name: Vec<u8>,
}

impl DraftIdentification {
    /// Create a Draft Identification for the current draft version.
    pub fn current() -> Self {
        DraftIdentification {
            draft_name: DRAFT_ID.to_vec(),
        }
    }

    /// Convert to a generic extension field.
    pub fn to_extension_field(&self) -> ExtensionField {
        ExtensionField {
            field_type: DRAFT_IDENTIFICATION,
            value: self.draft_name.clone(),
        }
    }

    /// Try to extract from a generic extension field.
    pub fn from_extension_field(ef: &ExtensionField) -> Option<Self> {
        if ef.field_type != DRAFT_IDENTIFICATION {
            return None;
        }
        Some(DraftIdentification {
            draft_name: ef.value.clone(),
        })
    }

    /// Check if this matches the current draft version.
    pub fn is_current(&self) -> bool {
        self.draft_name == DRAFT_ID
    }
}

/// Padding extension field (0xF501).
///
/// Used to pad NTPv5 requests so the server has room for response extension
/// fields (response length must equal request length).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct Padding {
    /// The padding size in bytes (value is all zeros).
    pub size: usize,
}

impl Padding {
    /// Convert to a generic extension field.
    pub fn to_extension_field(&self) -> ExtensionField {
        ExtensionField {
            field_type: PADDING,
            value: vec![0u8; self.size],
        }
    }

    /// Try to extract from a generic extension field.
    pub fn from_extension_field(ef: &ExtensionField) -> Option<Self> {
        if ef.field_type != PADDING {
            return None;
        }
        Some(Padding {
            size: ef.value.len(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_draft_identification_current() {
        let di = DraftIdentification::current();
        assert!(di.is_current());
        assert_eq!(di.draft_name, DRAFT_ID);
    }

    #[test]
    fn test_draft_identification_roundtrip() {
        let di = DraftIdentification::current();
        let ef = di.to_extension_field();
        assert_eq!(ef.field_type, DRAFT_IDENTIFICATION);

        let back = DraftIdentification::from_extension_field(&ef).unwrap();
        assert_eq!(back, di);
        assert!(back.is_current());
    }

    #[test]
    fn test_draft_identification_wrong_type() {
        let ef = ExtensionField {
            field_type: 0x1234,
            value: DRAFT_ID.to_vec(),
        };
        assert!(DraftIdentification::from_extension_field(&ef).is_none());
    }

    #[test]
    fn test_server_info_roundtrip() {
        // Server supports V4 and V5.
        let si = ServerInfo {
            supported_versions: (1 << 4) | (1 << 5),
        };
        assert!(si.supports_version(4));
        assert!(si.supports_version(5));
        assert!(!si.supports_version(3));

        let ef = si.to_extension_field();
        assert_eq!(ef.field_type, SERVER_INFO);

        let back = ServerInfo::from_extension_field(&ef).unwrap();
        assert_eq!(back, si);
    }

    #[test]
    fn test_refids_request_roundtrip() {
        let req = RefIdsRequest { offset: 256 };
        let ef = req.to_extension_field();
        assert_eq!(ef.field_type, REFIDS_REQUEST);

        let back = RefIdsRequest::from_extension_field(&ef).unwrap();
        assert_eq!(back, req);
    }

    #[test]
    fn test_refids_response_roundtrip() {
        let resp = RefIdsResponse {
            data: vec![0xAA; 64],
        };
        let ef = resp.to_extension_field();
        assert_eq!(ef.field_type, REFIDS_RESPONSE);

        let back = RefIdsResponse::from_extension_field(&ef).unwrap();
        assert_eq!(back, resp);
    }

    #[test]
    fn test_reference_timestamp_roundtrip() {
        let rt = ReferenceTimestamp {
            timestamp: TimestampFormat {
                seconds: 3_913_056_000,
                fraction: 500_000_000,
            },
        };
        let ef = rt.to_extension_field();
        assert_eq!(ef.field_type, REFERENCE_TIMESTAMP);

        let back = ReferenceTimestamp::from_extension_field(&ef).unwrap();
        assert_eq!(back, rt);
    }

    #[test]
    fn test_padding_roundtrip() {
        let pad = Padding { size: 100 };
        let ef = pad.to_extension_field();
        assert_eq!(ef.field_type, PADDING);
        assert_eq!(ef.value.len(), 100);
        assert!(ef.value.iter().all(|&b| b == 0));

        let back = Padding::from_extension_field(&ef).unwrap();
        assert_eq!(back.size, 100);
    }

    #[test]
    fn test_negotiation_magic_values() {
        // Verify the magic values are correct ASCII.
        let draft_bytes = NEGOTIATION_MAGIC_DRAFT.to_be_bytes();
        assert_eq!(&draft_bytes, b"NTP5DRFT");

        let rfc_bytes = NEGOTIATION_MAGIC_RFC.to_be_bytes();
        assert_eq!(&rfc_bytes, b"NTP5NTP5");
    }

    #[test]
    fn test_extension_type_codes() {
        // Verify all codes are in the 0xF5xx range.
        assert_eq!(PADDING & 0xFF00, 0xF500);
        assert_eq!(MAC & 0xFF00, 0xF500);
        assert_eq!(REFIDS_REQUEST & 0xFF00, 0xF500);
        assert_eq!(REFIDS_RESPONSE & 0xFF00, 0xF500);
        assert_eq!(SERVER_INFO & 0xFF00, 0xF500);
        assert_eq!(CORRECTION & 0xFF00, 0xF500);
        assert_eq!(REFERENCE_TIMESTAMP & 0xFF00, 0xF500);
        assert_eq!(MONOTONIC_RECV_TS & 0xFF00, 0xF500);
        assert_eq!(SECONDARY_RECV_TS & 0xFF00, 0xF500);
        assert_eq!(DRAFT_IDENTIFICATION & 0xFF00, 0xF500);
    }
}
