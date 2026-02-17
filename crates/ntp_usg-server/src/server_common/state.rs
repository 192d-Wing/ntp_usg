use crate::protocol;
use crate::unix_time;

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
        }
    }
}
