#[cfg(feature = "std")]
use byteorder::{ReadBytesExt, WriteBytesExt};
#[cfg(feature = "std")]
use std::io;

use crate::error::ParseError;

/// A trait for writing any of the Network Time Protocol types to network-endian bytes.
///
/// A blanket implementation is provided for all types that implement `byteorder::WriteBytesExt`.
/// Requires the `std` feature.
#[cfg(feature = "std")]
pub trait WriteBytes {
    /// Writes an NTP protocol type to this writer in network byte order.
    fn write_bytes<P: WriteToBytes>(&mut self, protocol: P) -> io::Result<()>;
}

/// A trait for reading any of the Network Time Protocol types from network-endian bytes.
///
/// A blanket implementation is provided for all types that implement `byteorder::ReadBytesExt`.
/// Requires the `std` feature.
#[cfg(feature = "std")]
pub trait ReadBytes {
    /// Reads an NTP protocol type from this reader in network byte order.
    fn read_bytes<P: ReadFromBytes>(&mut self) -> io::Result<P>;
}

/// Network Time Protocol types that may be written to network endian bytes.
/// Requires the `std` feature.
#[cfg(feature = "std")]
pub trait WriteToBytes {
    /// Write the command to bytes.
    fn write_to_bytes<W: WriteBytesExt>(&self, writer: W) -> io::Result<()>;
}

/// Network Time Protocol types that may be read from network endian bytes.
/// Requires the `std` feature.
#[cfg(feature = "std")]
pub trait ReadFromBytes: Sized {
    /// Read the command from bytes.
    fn read_from_bytes<R: ReadBytesExt>(reader: R) -> io::Result<Self>;
}

/// Types that have a constant size when written to or read from bytes.
pub trait ConstPackedSizeBytes {
    /// The constant size in bytes when this type is packed for network transmission.
    const PACKED_SIZE_BYTES: usize;
}

/// Parse a type from a byte slice, returning the parsed value and the number
/// of bytes consumed.
///
/// Unlike [`ReadFromBytes`], this trait does not require `std::io` or the `byteorder` crate.
/// It operates directly on `&[u8]` slices, making it suitable for `no_std` environments
/// and packet capture analysis.
pub trait FromBytes: Sized {
    /// Parse from the given byte slice. Returns the parsed value and the
    /// number of bytes consumed from the front of `buf`.
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError>;
}

/// Serialize a type into a byte slice, returning the number of bytes written.
///
/// Unlike [`WriteToBytes`], this trait does not require `std::io` or the `byteorder` crate.
/// It operates directly on `&mut [u8]` slices, making it suitable for `no_std` environments.
pub trait ToBytes {
    /// Write this value into the given byte slice. Returns the number of bytes
    /// written. Fails with [`ParseError::BufferTooShort`] if `buf` is too short.
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError>;
}
