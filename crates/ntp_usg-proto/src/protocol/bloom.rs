// Copyright 2026 U.S. Federal Government (in countries where recognized)
// SPDX-License-Identifier: Apache-2.0

//! NTPv5 Bloom filter for loop detection (`draft-ietf-ntp-ntpv5-07`).
//!
//! Each NTPv5 server has a 120-bit reference ID. The set of all upstream
//! reference IDs is encoded in a 4096-bit (512-byte) Bloom filter that is
//! transferred to clients via Reference IDs extension fields (0xF503/0xF504).
//!
//! A 120-bit reference ID is split into 10 × 12-bit indices, each selecting
//! one bit in the 4096-bit array. False positive rate: ~1e-12 at 26 IDs,
//! ~1e-6 at 118 IDs.

/// 4096-bit (512-byte) Bloom filter for NTPv5 loop detection.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct BloomFilter {
    bits: [u8; 512],
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl BloomFilter {
    /// Create a new empty Bloom filter (all bits zero).
    pub fn new() -> Self {
        BloomFilter { bits: [0u8; 512] }
    }

    /// Insert a 120-bit reference ID into the filter.
    ///
    /// The 15-byte ID is interpreted as 120 bits and split into 10 × 12-bit
    /// indices, each selecting one bit in the 4096-bit array.
    pub fn insert(&mut self, id: &[u8; 15]) {
        for idx in indices_from_id(id) {
            let byte_idx = (idx / 8) as usize;
            let bit_idx = idx % 8;
            self.bits[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Check if a 120-bit reference ID is (probably) present in the filter.
    ///
    /// Returns `false` for definite absence, `true` for probable presence.
    pub fn contains(&self, id: &[u8; 15]) -> bool {
        indices_from_id(id).iter().all(|&idx| {
            let byte_idx = (idx / 8) as usize;
            let bit_idx = idx % 8;
            self.bits[byte_idx] & (1 << bit_idx) != 0
        })
    }

    /// Raw bytes for wire transfer via extension fields.
    pub fn as_bytes(&self) -> &[u8; 512] {
        &self.bits
    }

    /// Construct a Bloom filter from raw 512 bytes.
    pub fn from_bytes(bytes: [u8; 512]) -> Self {
        BloomFilter { bits: bytes }
    }

    /// Get a chunk of the filter at the given byte offset.
    ///
    /// Used by the server to respond to Reference IDs Response extension fields.
    /// Returns an empty slice if `offset` is beyond the end of the filter.
    pub fn chunk(&self, offset: u16, len: usize) -> &[u8] {
        let start = offset as usize;
        if start >= self.bits.len() {
            return &[];
        }
        let end = (start + len).min(self.bits.len());
        &self.bits[start..end]
    }

    /// Set a chunk at the given byte offset (used by client assembling filter).
    ///
    /// Data that would extend beyond the 512-byte filter is silently truncated.
    pub fn set_chunk(&mut self, offset: u16, data: &[u8]) {
        let start = offset as usize;
        if start >= self.bits.len() {
            return;
        }
        let end = (start + data.len()).min(self.bits.len());
        let copy_len = end - start;
        self.bits[start..end].copy_from_slice(&data[..copy_len]);
    }

    /// Returns `true` if all bits are zero (empty filter).
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }

    /// Returns the number of bits set in the filter.
    pub fn popcount(&self) -> u32 {
        self.bits.iter().map(|b| b.count_ones()).sum()
    }
}

/// Extract 10 × 12-bit indices from a 120-bit (15-byte) reference ID.
///
/// Interprets the 15 bytes as a 120-bit big-endian integer, then extracts
/// bits `[i*12..(i+1)*12]` for each of the 10 indices (i = 0..9).
fn indices_from_id(id: &[u8; 15]) -> [u16; 10] {
    let mut result = [0u16; 10];
    for (i, slot) in result.iter_mut().enumerate() {
        let bit_offset = i * 12;
        *slot = extract_12_bits(id, bit_offset);
    }
    result
}

/// Extract a 12-bit value starting at the given bit offset within the 15-byte array.
fn extract_12_bits(data: &[u8; 15], bit_offset: usize) -> u16 {
    let byte_idx = bit_offset / 8;
    let bit_idx = bit_offset % 8;

    // We need at most 3 bytes to extract 12 bits starting at an arbitrary bit offset.
    let b0 = data[byte_idx] as u32;
    let b1 = if byte_idx + 1 < 15 {
        data[byte_idx + 1] as u32
    } else {
        0
    };
    let b2 = if byte_idx + 2 < 15 {
        data[byte_idx + 2] as u32
    } else {
        0
    };

    // Assemble 24 bits starting at byte_idx, then shift and mask.
    let combined = (b0 << 16) | (b1 << 8) | b2;
    let shift = 24 - bit_idx - 12;
    ((combined >> shift) & 0xFFF) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_empty() {
        let filter = BloomFilter::new();
        assert!(filter.is_empty());
        assert_eq!(filter.popcount(), 0);
    }

    #[test]
    fn test_bloom_insert_and_contains() {
        let mut filter = BloomFilter::new();
        let id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
            0x0F,
        ];

        assert!(!filter.contains(&id));
        filter.insert(&id);
        assert!(filter.contains(&id));
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_bloom_different_ids() {
        let mut filter = BloomFilter::new();
        let id1 = [0xFF; 15];

        filter.insert(&id1);
        assert!(filter.contains(&id1));
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_bloom_multiple_inserts() {
        let mut filter = BloomFilter::new();
        for i in 0..20u8 {
            let mut id = [0u8; 15];
            id[0] = i;
            filter.insert(&id);
        }

        for i in 0..20u8 {
            let mut id = [0u8; 15];
            id[0] = i;
            assert!(filter.contains(&id));
        }
    }

    #[test]
    fn test_bloom_from_bytes_roundtrip() {
        let mut filter = BloomFilter::new();
        let id = [0xAB; 15];
        filter.insert(&id);

        let bytes = *filter.as_bytes();
        let restored = BloomFilter::from_bytes(bytes);
        assert_eq!(filter, restored);
        assert!(restored.contains(&id));
    }

    #[test]
    fn test_bloom_chunk_get_set() {
        let mut filter = BloomFilter::new();
        let data = [0xAA, 0xBB, 0xCC, 0xDD];

        filter.set_chunk(100, &data);
        let chunk = filter.chunk(100, 4);
        assert_eq!(chunk, &data);
    }

    #[test]
    fn test_bloom_chunk_at_end() {
        let mut filter = BloomFilter::new();
        let data = [0xFF; 8];

        // Set chunk at the boundary — only 4 bytes should fit.
        filter.set_chunk(508, &data);
        let chunk = filter.chunk(508, 8);
        assert_eq!(chunk.len(), 4);
        assert_eq!(chunk, &[0xFF; 4]);
    }

    #[test]
    fn test_bloom_chunk_beyond_end() {
        let filter = BloomFilter::new();
        let chunk = filter.chunk(600, 4);
        assert!(chunk.is_empty());
    }

    #[test]
    fn test_indices_from_id() {
        // All zeros → all 10 indices should be 0.
        let id = [0u8; 15];
        let indices = indices_from_id(&id);
        assert!(indices.iter().all(|&i| i == 0));

        // All ones → all 10 indices should be 0xFFF (4095).
        let id = [0xFF; 15];
        let indices = indices_from_id(&id);
        assert!(indices.iter().all(|&i| i == 0xFFF));
    }

    #[test]
    fn test_extract_12_bits_aligned() {
        // First 12 bits of [0xAB, 0xC0, ...] = 0xABC
        let mut data = [0u8; 15];
        data[0] = 0xAB;
        data[1] = 0xC0;
        assert_eq!(extract_12_bits(&data, 0), 0xABC);
    }

    #[test]
    fn test_extract_12_bits_unaligned() {
        // Starting at bit 4: [0x0A, 0xBC, ...] → bits 4..16 = 0xABC
        let mut data = [0u8; 15];
        data[0] = 0x0A;
        data[1] = 0xBC;
        assert_eq!(extract_12_bits(&data, 4), 0xABC);
    }

    #[test]
    fn test_bloom_popcount() {
        let mut filter = BloomFilter::new();
        assert_eq!(filter.popcount(), 0);
        filter.bits[0] = 0xFF;
        assert_eq!(filter.popcount(), 8);
    }
}
