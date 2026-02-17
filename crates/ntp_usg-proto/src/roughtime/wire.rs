// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! Roughtime tag-value map wire format codec.
//!
//! Roughtime messages are encoded as tag-value maps: a header with tag count,
//! cumulative offsets, sorted tags, followed by concatenated values.
//!
//! Layout:
//! ```text
//! num_tags: u32 LE
//! offsets:  [u32 LE; N-1]   (cumulative byte offsets into value region)
//! tags:     [[u8; 4]; N]    (sorted ascending by LE u32 value)
//! values:   [u8]            (concatenated, 4-byte aligned)
//! ```
//!
//! Envelopes wrap messages with an 8-byte magic (`ROUGHTIM` as LE u64)
//! and a 4-byte length field.

use super::error::RoughtimeError;

/// Magic bytes for a Roughtime envelope: `"ROUGHTIM"` read as a LE u64.
const ENVELOPE_MAGIC: u64 = 0x4d49_5448_4755_4f52;

/// Minimum envelope size: 8 (magic) + 4 (length) = 12 bytes.
const ENVELOPE_HEADER_LEN: usize = 12;

/// A zero-copy parsed tag-value map referencing borrowed data.
#[derive(Debug, PartialEq)]
pub struct TagValueMap<'a> {
    num_tags: u32,
    offsets: &'a [u8],
    tags: &'a [u8],
    values: &'a [u8],
}

impl<'a> TagValueMap<'a> {
    /// Parse a tag-value map from raw bytes.
    pub fn parse(buf: &'a [u8]) -> Result<Self, RoughtimeError> {
        if buf.len() < 4 {
            return Err(RoughtimeError::MessageTooShort {
                needed: 4,
                available: buf.len(),
            });
        }

        let num_tags = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);

        if num_tags == 0 {
            return Ok(TagValueMap {
                num_tags: 0,
                offsets: &[],
                tags: &[],
                values: &[],
            });
        }

        // Header: 4 (num_tags) + 4*(N-1) (offsets) + 4*N (tags)
        let offsets_len = (num_tags as usize).saturating_sub(1) * 4;
        let tags_len = num_tags as usize * 4;
        let header_len = 4 + offsets_len + tags_len;

        if buf.len() < header_len {
            return Err(RoughtimeError::MessageTooShort {
                needed: header_len,
                available: buf.len(),
            });
        }

        let offsets = &buf[4..4 + offsets_len];
        let tags = &buf[4 + offsets_len..header_len];
        let values = &buf[header_len..];

        // Verify tags are in ascending LE u32 order.
        for i in 1..num_tags as usize {
            let prev = tag_to_u32(&tags[(i - 1) * 4..i * 4]);
            let curr = tag_to_u32(&tags[i * 4..(i + 1) * 4]);
            if prev >= curr {
                return Err(RoughtimeError::InvalidTagOrder);
            }
        }

        // Verify offsets are monotonically increasing and in bounds.
        let mut prev_offset = 0u32;
        for i in 0..offsets_len / 4 {
            let off = u32::from_le_bytes([
                offsets[i * 4],
                offsets[i * 4 + 1],
                offsets[i * 4 + 2],
                offsets[i * 4 + 3],
            ]);
            if off < prev_offset || off as usize > values.len() {
                return Err(RoughtimeError::OffsetOutOfBounds);
            }
            prev_offset = off;
        }

        Ok(TagValueMap {
            num_tags,
            offsets,
            tags,
            values,
        })
    }

    /// Look up a tag's value. Returns `None` if the tag is not present.
    pub fn get(&self, tag: &[u8; 4]) -> Option<&'a [u8]> {
        let target = tag_to_u32(tag);

        for i in 0..self.num_tags as usize {
            let t = tag_to_u32(&self.tags[i * 4..(i + 1) * 4]);
            if t == target {
                let start = if i == 0 {
                    0
                } else {
                    self.offset_at(i - 1) as usize
                };
                let end = if i == self.num_tags as usize - 1 {
                    self.values.len()
                } else {
                    self.offset_at(i) as usize
                };
                return Some(&self.values[start..end]);
            }
        }
        None
    }

    /// Look up a required tag. Returns `MissingTag` error if not found.
    pub fn require(&self, tag: &[u8; 4]) -> Result<&'a [u8], RoughtimeError> {
        self.get(tag)
            .ok_or(RoughtimeError::MissingTag { tag: *tag })
    }

    /// Parse a nested tag-value map from a tag's value.
    pub fn get_nested(&self, tag: &[u8; 4]) -> Result<TagValueMap<'a>, RoughtimeError> {
        let data = self.require(tag)?;
        TagValueMap::parse(data)
    }

    fn offset_at(&self, idx: usize) -> u32 {
        u32::from_le_bytes([
            self.offsets[idx * 4],
            self.offsets[idx * 4 + 1],
            self.offsets[idx * 4 + 2],
            self.offsets[idx * 4 + 3],
        ])
    }
}

/// Decode a Roughtime envelope, returning the inner message bytes.
pub fn decode_envelope(buf: &[u8]) -> Result<&[u8], RoughtimeError> {
    if buf.len() < ENVELOPE_HEADER_LEN {
        return Err(RoughtimeError::MessageTooShort {
            needed: ENVELOPE_HEADER_LEN,
            available: buf.len(),
        });
    }

    let magic = u64::from_le_bytes([
        buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
    ]);
    if magic != ENVELOPE_MAGIC {
        return Err(RoughtimeError::InvalidMagic);
    }

    let length = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]) as usize;
    let total = ENVELOPE_HEADER_LEN + length;

    if buf.len() < total {
        return Err(RoughtimeError::MessageTooShort {
            needed: total,
            available: buf.len(),
        });
    }

    Ok(&buf[ENVELOPE_HEADER_LEN..total])
}

/// Encode a message into a Roughtime envelope.
pub fn encode_envelope(message: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ENVELOPE_HEADER_LEN + message.len());
    buf.extend_from_slice(&ENVELOPE_MAGIC.to_le_bytes());
    buf.extend_from_slice(&(message.len() as u32).to_le_bytes());
    buf.extend_from_slice(message);
    buf
}

/// Build a serialized tag-value map from sorted tag-value pairs.
///
/// # Panics
///
/// Panics if tags are not sorted in ascending LE u32 order or if values
/// are not 4-byte aligned (except the last).
pub fn build_tag_value_map(entries: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let num_tags = entries.len() as u32;
    if num_tags == 0 {
        return 0u32.to_le_bytes().to_vec();
    }

    // Debug: verify sort order.
    for i in 1..entries.len() {
        assert!(
            tag_to_u32(entries[i - 1].0) < tag_to_u32(entries[i].0),
            "tags must be sorted in ascending LE u32 order"
        );
    }

    // All values except the last must be 4-byte aligned.
    for entry in entries.iter().take(entries.len().saturating_sub(1)) {
        assert!(
            entry.1.len() % 4 == 0,
            "all values except the last must be 4-byte aligned"
        );
    }

    // Calculate total size.
    let offsets_len = (num_tags as usize - 1) * 4;
    let tags_len = num_tags as usize * 4;
    let values_len: usize = entries.iter().map(|e| e.1.len()).sum();
    let total = 4 + offsets_len + tags_len + values_len;

    let mut buf = Vec::with_capacity(total);

    // num_tags
    buf.extend_from_slice(&num_tags.to_le_bytes());

    // Cumulative offsets (N-1 entries).
    let mut cumulative = 0u32;
    for entry in entries.iter().take(entries.len() - 1) {
        cumulative += entry.1.len() as u32;
        buf.extend_from_slice(&cumulative.to_le_bytes());
    }

    // Tags.
    for entry in entries {
        buf.extend_from_slice(entry.0);
    }

    // Values.
    for entry in entries {
        buf.extend_from_slice(entry.1);
    }

    buf
}

/// Convert a 4-byte tag to a u32 for ordering comparison.
fn tag_to_u32(tag: &[u8]) -> u32 {
    u32::from_le_bytes([tag[0], tag[1], tag[2], tag[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_map() {
        let data = build_tag_value_map(&[]);
        let map = TagValueMap::parse(&data).unwrap();
        assert!(map.get(b"NONC").is_none());
    }

    #[test]
    fn test_single_tag() {
        let value = b"hello world!"; // 12 bytes
        let data = build_tag_value_map(&[(b"NONC", value)]);
        let map = TagValueMap::parse(&data).unwrap();
        assert_eq!(map.get(b"NONC"), Some(value.as_slice()));
        assert!(map.get(b"SIG\0").is_none());
    }

    #[test]
    fn test_multiple_tags() {
        // Tags must be sorted by LE u32 value.
        // CERT = 0x54524543, NONC = 0x434e4f4e, SIG\0 = 0x00474953
        // Sorted: SIG\0 < NONC < CERT
        let sig = [0u8; 64];
        let nonc = [1u8; 32];
        let cert = [2u8; 16];
        let data = build_tag_value_map(&[(b"SIG\0", &sig), (b"NONC", &nonc), (b"CERT", &cert)]);
        let map = TagValueMap::parse(&data).unwrap();
        assert_eq!(map.get(b"SIG\0"), Some(sig.as_slice()));
        assert_eq!(map.get(b"NONC"), Some(nonc.as_slice()));
        assert_eq!(map.get(b"CERT"), Some(cert.as_slice()));
    }

    #[test]
    fn test_envelope_roundtrip() {
        let msg = b"test message";
        let envelope = encode_envelope(msg);
        let decoded = decode_envelope(&envelope).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_envelope_invalid_magic() {
        let mut envelope = encode_envelope(b"test");
        envelope[0] = 0xFF;
        assert_eq!(
            decode_envelope(&envelope),
            Err(RoughtimeError::InvalidMagic)
        );
    }

    #[test]
    fn test_envelope_too_short() {
        assert_eq!(
            decode_envelope(&[0; 4]),
            Err(RoughtimeError::MessageTooShort {
                needed: 12,
                available: 4
            })
        );
    }

    #[test]
    fn test_invalid_tag_order() {
        // Manually build a map with tags in wrong order.
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // num_tags = 2
        data.extend_from_slice(&4u32.to_le_bytes()); // offset[0] = 4
        data.extend_from_slice(b"NONC"); // tag 0 (larger LE value)
        data.extend_from_slice(b"CERT"); // tag 1 — wrong, should be before NONC
        data.extend_from_slice(&[0; 8]); // values

        // Need to check actual tag ordering. NONC and CERT LE values:
        // NONC = 0x434e4f4e, CERT = 0x54524543
        // Actually CERT (0x54524543) > NONC (0x434e4f4e), so NONC first is correct.
        // Let's use tags where the order is genuinely wrong.
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes()); // num_tags = 2
        data.extend_from_slice(&4u32.to_le_bytes()); // offset[0] = 4
        data.extend_from_slice(b"CERT"); // tag 0 (0x54524543)
        data.extend_from_slice(b"NONC"); // tag 1 (0x434e4f4e) — wrong, smaller value
        data.extend_from_slice(&[0; 8]); // values

        assert_eq!(
            TagValueMap::parse(&data),
            Err(RoughtimeError::InvalidTagOrder)
        );
    }

    #[test]
    fn test_require_missing_tag() {
        let data = build_tag_value_map(&[(b"NONC", &[0; 32])]);
        let map = TagValueMap::parse(&data).unwrap();
        assert_eq!(
            map.require(b"SIG\0"),
            Err(RoughtimeError::MissingTag { tag: *b"SIG\0" })
        );
    }

    #[test]
    fn test_nested_map() {
        // Build an inner map.
        let inner = build_tag_value_map(&[(b"NONC", &[42u8; 32])]);

        // Pad inner to 4-byte alignment (should already be aligned).
        let data = build_tag_value_map(&[(b"CERT", &inner)]);
        let outer = TagValueMap::parse(&data).unwrap();
        let nested = outer.get_nested(b"CERT").unwrap();
        assert_eq!(nested.get(b"NONC"), Some([42u8; 32].as_slice()));
    }
}
