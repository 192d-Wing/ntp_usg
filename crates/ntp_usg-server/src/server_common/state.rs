use crate::protocol;
use crate::unix_time;

#[cfg(feature = "ntpv5")]
use ntp_proto::protocol::bloom::BloomFilter;
#[cfg(feature = "ntpv5")]
use ntp_proto::protocol::ntpv5::Timescale;

/// Server-wide system variables (RFC 5905 Section 11).
///
/// These values are populated from the server's reference clock or upstream
/// source and are included in every response packet. They can be updated at
/// runtime (e.g., when the server synchronizes to a new upstream source) by
/// obtaining a write lock on the `Arc<RwLock<ServerSystemState>>`.
#[derive(Clone, Debug)]
pub struct ServerSystemState {
    /// Leap indicator warning of impending leap second.
    pub leap_indicator: protocol::LeapIndicator,
    /// Stratum level of this server.
    pub stratum: protocol::Stratum,
    /// Precision of the server's clock, in log2 seconds (e.g., -20 ≈ 1μs).
    pub precision: i8,
    /// Total round-trip delay to the primary reference source.
    pub root_delay: protocol::ShortFormat,
    /// Total dispersion to the primary reference source.
    pub root_dispersion: protocol::ShortFormat,
    /// Reference clock identifier (e.g., GPS, LOCL, or upstream server IP).
    pub reference_id: protocol::ReferenceIdentifier,
    /// Time when the system clock was last set or corrected.
    pub reference_timestamp: protocol::TimestampFormat,

    /// NTPv5 timescale for this server.
    #[cfg(feature = "ntpv5")]
    pub timescale: Timescale,
    /// NTPv5 era number.
    #[cfg(feature = "ntpv5")]
    pub era: u8,
    /// NTPv5 Bloom filter containing upstream reference IDs for loop detection.
    #[cfg(feature = "ntpv5")]
    pub bloom_filter: BloomFilter,
    /// This server's 120-bit NTPv5 reference ID.
    #[cfg(feature = "ntpv5")]
    pub v5_reference_id: [u8; 15],
}

impl Default for ServerSystemState {
    fn default() -> Self {
        ServerSystemState {
            leap_indicator: protocol::LeapIndicator::NoWarning,
            stratum: protocol::Stratum::PRIMARY,
            precision: -20,
            root_delay: protocol::ShortFormat::default(),
            root_dispersion: protocol::ShortFormat::default(),
            reference_id: protocol::ReferenceIdentifier::PrimarySource(
                protocol::PrimarySource::Locl,
            ),
            reference_timestamp: unix_time::Instant::now().into(),
            #[cfg(feature = "ntpv5")]
            timescale: Timescale::Utc,
            #[cfg(feature = "ntpv5")]
            era: 0,
            #[cfg(feature = "ntpv5")]
            bloom_filter: BloomFilter::new(),
            #[cfg(feature = "ntpv5")]
            v5_reference_id: [0u8; 15],
        }
    }
}
