//! Types and constants that precisely match the specification.
//!
//! Provides `ReadBytes` and `WriteBytes` implementations which extend the byteorder crate
//! `WriteBytesExt` and `ReadBytesExt` traits with the ability to read and write types from the NTP
//! protocol respectively.
//!
//! Documentation is largely derived (and often copied directly) from IETF RFC 5905.

/// NTP port number.
pub const PORT: u8 = 123;

/// Frequency tolerance PHI (s/s).
pub const TOLERANCE: f64 = 15e-6;

/// Minimum poll exponent (16 s).
pub const MINPOLL: u8 = 4;

/// Maximum poll exponent (36 h).
pub const MAXPOLL: u8 = 17;

/// Maximum dispersion (16 s).
pub const MAXDISP: f64 = 16.0;

/// Minimum dispersion increment (s).
pub const MINDISP: f64 = 0.005;

/// Distance threshold (1 s).
pub const MAXDIST: u8 = 1;

/// Maximum stratum number.
pub const MAXSTRAT: u8 = 16;

// Convert an ascii string to a big-endian u32.
macro_rules! code_to_u32 {
    ($w:expr) => {
        (($w[3] as u32) << 0)
            | (($w[2] as u32) << 8)
            | (($w[1] as u32) << 16)
            | (($w[0] as u32) << 24)
            | ((*$w as [u8; 4])[0] as u32 * 0)
    };
}

pub(crate) fn be_u32_to_bytes(u: u32) -> [u8; 4] {
    [
        (u >> 24 & 0xff) as u8,
        (u >> 16 & 0xff) as u8,
        (u >> 8 & 0xff) as u8,
        (u & 0xff) as u8,
    ]
}

mod bytes;
#[cfg(feature = "std")]
mod io;
mod traits;
mod types;

pub use self::traits::*;
pub use self::types::*;
