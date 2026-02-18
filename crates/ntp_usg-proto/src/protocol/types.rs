use core::fmt;

use super::ConstPackedSizeBytes;
use super::be_u32_to_bytes;

/// **NTP Short Format** - Used in delay and dispersion header fields where the full resolution and
/// range of the other formats are not justified. It includes a 16-bit unsigned seconds field and a
/// 16-bit fraction field.
///
/// ### Layout
///
/// ```ignore
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Seconds              |           Fraction            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ShortFormat {
    /// Seconds component (16-bit unsigned).
    pub seconds: u16,
    /// Fractional seconds component (16-bit unsigned).
    pub fraction: u16,
}

/// **NTP Timestamp Format** - Used in packet headers and other places with limited word size. It
/// includes a 32-bit unsigned seconds field spanning 136 years and a 32-bit fraction field
/// resolving 232 picoseconds.
///
/// The prime epoch is 0 h 1 January 1900 UTC, when all bits are zero.
///
/// ### Layout
///
/// ```ignore
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Seconds                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                            Fraction                           |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct TimestampFormat {
    /// Seconds since 1900-01-01 00:00:00 UTC (32-bit unsigned).
    pub seconds: u32,
    /// Fractional seconds (32-bit unsigned, resolution of ~232 picoseconds).
    pub fraction: u32,
}

/// **NTP Date Format** - The prime epoch, or base date of era 0, is 0 h 1 January 1900 UTC, when all
/// bits are zero. Dates are relative to the prime epoch; values greater than zero represent times
/// after that date; values less than zero represent times before it.
///
/// Note that the `era_offset` field has the same interpretation as the `seconds` field of the
/// `TimestampFormat` type.
///
/// ```ignore
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Era Number                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                           Era Offset                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                           Fraction                            |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DateFormat {
    /// Era number (signed 32-bit integer).
    pub era_number: i32,
    /// Offset within the era in seconds (32-bit unsigned).
    pub era_offset: u32,
    /// Fractional seconds (64-bit unsigned).
    pub fraction: u64,
}

/// A 2-bit integer warning of an impending leap second to be inserted or deleted in the last
/// minute of the current month with values defined below:
///
/// Note that this field is packed in the actual header.
///
/// As the only constructors are via associated constants, it should be impossible to create an
/// invalid `LeapIndicator`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub enum LeapIndicator {
    /// No leap required.
    #[default]
    NoWarning = 0,
    /// Last minute of the day has 61 seconds.
    AddOne = 1,
    /// Last minute of the day has 59 seconds.
    SubOne = 2,
    /// Clock unsynchronized.
    Unknown = 3,
}

impl TryFrom<u8> for LeapIndicator {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(LeapIndicator::NoWarning),
            1 => Ok(LeapIndicator::AddOne),
            2 => Ok(LeapIndicator::SubOne),
            3 => Ok(LeapIndicator::Unknown),
            _ => Err(()),
        }
    }
}

/// A 3-bit integer representing the NTP version number, currently 4.
///
/// Note that while this struct is 8-bits, this field is packed to 3 in the actual header.
///
/// As the only constructors are via associated constants, it should be impossible to create an
/// invalid `Version`.
#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Version(pub(super) u8);

/// A 3-bit integer representing the mode.
///
/// Note that while this struct is 8-bits, this field is packed to 3 in the actual header.
///
/// As the only constructors are via associated constants, it should be impossible to create an
/// invalid `Mode`.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, PartialEq)]
pub enum Mode {
    /// Reserved mode (value 0).
    Reserved = 0,
    /// Symmetric active mode (value 1).
    SymmetricActive = 1,
    /// Symmetric passive mode (value 2).
    SymmetricPassive = 2,
    /// Client mode (value 3).
    #[default]
    Client = 3,
    /// Server mode (value 4).
    Server = 4,
    /// Broadcast mode (value 5).
    Broadcast = 5,
    /// NTP control message mode (value 6).
    NtpControlMessage = 6,
    /// Reserved for private use (value 7).
    ReservedForPrivateUse = 7,
}

impl TryFrom<u8> for Mode {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Mode::Reserved),
            1 => Ok(Mode::SymmetricActive),
            2 => Ok(Mode::SymmetricPassive),
            3 => Ok(Mode::Client),
            4 => Ok(Mode::Server),
            5 => Ok(Mode::Broadcast),
            6 => Ok(Mode::NtpControlMessage),
            7 => Ok(Mode::ReservedForPrivateUse),
            _ => Err(()),
        }
    }
}

/// An 8-bit integer representing the stratum.
///
/// ```ignore
/// +--------+-----------------------------------------------------+
/// | Value  | Meaning                                             |
/// +--------+-----------------------------------------------------+
/// | 0      | unspecified or invalid                              |
/// | 1      | primary server (e.g., equipped with a GPS receiver) |
/// | 2-15   | secondary server (via NTP)                          |
/// | 16     | unsynchronized                                      |
/// | 17-255 | reserved                                            |
/// +--------+-----------------------------------------------------+
/// ```
///
/// It is customary to map the stratum value 0 in received packets to `MAXSTRAT` in the peer
/// variable p.stratum and to map p.stratum values of `MAXSTRAT` or greater to 0 in transmitted
/// packets. This allows reference clocks, which normally appear at stratum 0, to be conveniently
/// mitigated using the same clock selection algorithms used for external sources.
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Stratum(pub u8);

/// A 32-bit code identifying the particular server or reference clock.
///
/// The interpretation depends on the value in the stratum field:
///
/// - For packet stratum 0 (unspecified or invalid), this is a four-character ASCII \[RFC1345\]
///   string, called the "kiss code", used for debugging and monitoring purposes.
/// - For stratum 1 (reference clock), this is a four-octet, left-justified, zero-padded ASCII
///   string assigned to the reference clock.
///
/// The authoritative list of Reference Identifiers is maintained by IANA; however, any string
/// beginning with the ASCII character "X" is reserved for unregistered experimentation and
/// development.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ReferenceIdentifier {
    /// Primary reference source (stratum 1) identifier.
    PrimarySource(PrimarySource),
    /// The reference identifier of the secondary or client server. Can be used to detect timing
    /// loops.
    ///
    /// If using the IPv4 address family, the identifier is the four-octet IPv4 address.
    ///
    /// If using the IPv6 address family, it is the first four octets of the MD5 hash of the IPv6
    /// address. Note that when using the IPv6 address family on a NTPv4 server with a NTPv3
    /// client, the Reference Identifier field appears to be a random value and a timing loop might
    /// not be detected.
    SecondaryOrClient([u8; 4]),
    /// Kiss-o'-Death packet code (stratum 0).
    KissOfDeath(KissOfDeath),
    /// An unrecognized 4-byte reference identifier.
    ///
    /// Used for stratum 0 packets with non-standard kiss codes, stratum 1 packets with
    /// unrecognized reference source identifiers, and stratum 16+ (unsynchronized/reserved)
    /// packets.
    Unknown([u8; 4]),
}

/// A four-octet, left-justified, zero-padded ASCII string assigned to the reference clock.
///
/// The authoritative list of Reference Identifiers is maintained by IANA; however, any string
/// beginning with the ASCII character "X" is reserved for unregistered experimentation and
/// development.
///
/// All variants represent standard reference clock identifiers as four-character ASCII codes.
/// See the [IANA NTP Parameters](https://www.iana.org/assignments/ntp-parameters/) registry
/// for the complete list of reference identifiers.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(missing_docs)]
pub enum PrimarySource {
    /// Geosynchronous Orbit Environment Satellite.
    Goes = code_to_u32!(b"GOES"),
    /// Global Position System.
    Gps = code_to_u32!(b"GPS\0"),
    /// Code Division Multiple Access.
    Cdma = code_to_u32!(b"CDMA"),
    Gal = code_to_u32!(b"GAL\0"),
    Pps = code_to_u32!(b"PPS\0"),
    Irig = code_to_u32!(b"IRIG"),
    Wwvb = code_to_u32!(b"WWVB"),
    Dcf = code_to_u32!(b"DCF\0"),
    Hgb = code_to_u32!(b"HGB\0"),
    Msf = code_to_u32!(b"MSF\0"),
    Jjy = code_to_u32!(b"JJY\0"),
    Lorc = code_to_u32!(b"LORC"),
    Tdf = code_to_u32!(b"TDF\0"),
    Chu = code_to_u32!(b"CHU\0"),
    Wwv = code_to_u32!(b"WWV\0"),
    Wwvh = code_to_u32!(b"WWVH"),
    Nist = code_to_u32!(b"NIST"),
    Acts = code_to_u32!(b"ACTS"),
    Usno = code_to_u32!(b"USNO"),
    Ptb = code_to_u32!(b"PTB\0"),
    Goog = code_to_u32!(b"GOOG"),
    Locl = code_to_u32!(b"LOCL"),
    Cesm = code_to_u32!(b"CESM"),
    Rbdm = code_to_u32!(b"RBDM"),
    Omeg = code_to_u32!(b"OMEG"),
    Dcn = code_to_u32!(b"DCN\0"),
    Tsp = code_to_u32!(b"TSP\0"),
    Dts = code_to_u32!(b"DTS\0"),
    Atom = code_to_u32!(b"ATOM"),
    Vlf = code_to_u32!(b"VLF\0"),
    Opps = code_to_u32!(b"OPPS"),
    Free = code_to_u32!(b"FREE"),
    Init = code_to_u32!(b"INIT"),
    Null = 0,
}

impl TryFrom<u32> for PrimarySource {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            v if v == code_to_u32!(b"GOES") => Ok(PrimarySource::Goes),
            v if v == code_to_u32!(b"GPS\0") => Ok(PrimarySource::Gps),
            v if v == code_to_u32!(b"CDMA") => Ok(PrimarySource::Cdma),
            v if v == code_to_u32!(b"GAL\0") => Ok(PrimarySource::Gal),
            v if v == code_to_u32!(b"PPS\0") => Ok(PrimarySource::Pps),
            v if v == code_to_u32!(b"IRIG") => Ok(PrimarySource::Irig),
            v if v == code_to_u32!(b"WWVB") => Ok(PrimarySource::Wwvb),
            v if v == code_to_u32!(b"DCF\0") => Ok(PrimarySource::Dcf),
            v if v == code_to_u32!(b"HGB\0") => Ok(PrimarySource::Hgb),
            v if v == code_to_u32!(b"MSF\0") => Ok(PrimarySource::Msf),
            v if v == code_to_u32!(b"JJY\0") => Ok(PrimarySource::Jjy),
            v if v == code_to_u32!(b"LORC") => Ok(PrimarySource::Lorc),
            v if v == code_to_u32!(b"TDF\0") => Ok(PrimarySource::Tdf),
            v if v == code_to_u32!(b"CHU\0") => Ok(PrimarySource::Chu),
            v if v == code_to_u32!(b"WWV\0") => Ok(PrimarySource::Wwv),
            v if v == code_to_u32!(b"WWVH") => Ok(PrimarySource::Wwvh),
            v if v == code_to_u32!(b"NIST") => Ok(PrimarySource::Nist),
            v if v == code_to_u32!(b"ACTS") => Ok(PrimarySource::Acts),
            v if v == code_to_u32!(b"USNO") => Ok(PrimarySource::Usno),
            v if v == code_to_u32!(b"PTB\0") => Ok(PrimarySource::Ptb),
            v if v == code_to_u32!(b"GOOG") => Ok(PrimarySource::Goog),
            v if v == code_to_u32!(b"LOCL") => Ok(PrimarySource::Locl),
            v if v == code_to_u32!(b"CESM") => Ok(PrimarySource::Cesm),
            v if v == code_to_u32!(b"RBDM") => Ok(PrimarySource::Rbdm),
            v if v == code_to_u32!(b"OMEG") => Ok(PrimarySource::Omeg),
            v if v == code_to_u32!(b"DCN\0") => Ok(PrimarySource::Dcn),
            v if v == code_to_u32!(b"TSP\0") => Ok(PrimarySource::Tsp),
            v if v == code_to_u32!(b"DTS\0") => Ok(PrimarySource::Dts),
            v if v == code_to_u32!(b"ATOM") => Ok(PrimarySource::Atom),
            v if v == code_to_u32!(b"VLF\0") => Ok(PrimarySource::Vlf),
            v if v == code_to_u32!(b"OPPS") => Ok(PrimarySource::Opps),
            v if v == code_to_u32!(b"FREE") => Ok(PrimarySource::Free),
            v if v == code_to_u32!(b"INIT") => Ok(PrimarySource::Init),
            0 => Ok(PrimarySource::Null),
            _ => Err(()),
        }
    }
}

/// If the Stratum field is 0, which implies unspecified or invalid, the Reference Identifier
/// field can be used to convey messages useful for status reporting and access control. These
/// are called **Kiss-o'-Death** (KoD) packets and the ASCII messages they convey are called
/// kiss codes.
///
/// The KoD packets got their name because an early use was to tell clients to stop sending
/// packets that violate server access controls. The kiss codes can provide useful information
/// for an intelligent client, either NTPv4 or SNTPv4. Kiss codes are encoded in four-character
/// ASCII strings that are left justified and zero filled. The strings are designed for
/// character displays and log files.
///
/// Recipients of kiss codes MUST inspect them and, in the following cases, take the actions
/// described.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum KissOfDeath {
    /// The client MUST demobilize any associations to that server and stop sending packets to it.
    Deny = code_to_u32!(b"DENY"),
    /// The client MUST demobilize any associations to that server and stop sending packets to it.
    Rstr = code_to_u32!(b"RSTR"),
    /// The client MUST immediately reduce its polling interval to that server and continue to
    /// reduce it each time it receives a RATE kiss code.
    Rate = code_to_u32!(b"RATE"),
}

impl TryFrom<u32> for KissOfDeath {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            v if v == code_to_u32!(b"DENY") => Ok(KissOfDeath::Deny),
            v if v == code_to_u32!(b"RSTR") => Ok(KissOfDeath::Rstr),
            v if v == code_to_u32!(b"RATE") => Ok(KissOfDeath::Rate),
            _ => Err(()),
        }
    }
}

/// **Packet Header** - The most important state variables from an external point of view are the
/// packet header variables described here.
///
/// The NTP packet header consists of an integral number of 32-bit (4 octet) words in network byte
/// order. The packet format consists of three components: the header itself, one or more optional
/// extension fields, and an optional message authentication code (MAC).
///
/// ```ignore
/// +-----------+------------+-----------------------+
/// | Name      | Formula    | Description           |
/// +-----------+------------+-----------------------+
/// | leap      | leap       | leap indicator (LI)   |
/// | version   | version    | version number (VN)   |
/// | mode      | mode       | mode                  |
/// | stratum   | stratum    | stratum               |
/// | poll      | poll       | poll exponent         |
/// | precision | rho        | precision exponent    |
/// | rootdelay | delta_r    | root delay            |
/// | rootdisp  | epsilon_r  | root dispersion       |
/// | refid     | refid      | reference ID          |
/// | reftime   | reftime    | reference timestamp   |
/// | org       | T1         | origin timestamp      |
/// | rec       | T2         | receive timestamp     |
/// | xmt       | T3         | transmit timestamp    |
/// | dst       | T4         | destination timestamp |
/// | keyid     | keyid      | key ID                |
/// | dgst      | dgst       | message digest        |
/// +-----------+------------+-----------------------+
/// ```
///
/// ### Format
///
/// The NTP packet is a UDP datagram \[RFC0768\]. Some fields use multiple words and others are
/// packed in smaller fields within a word. The NTP packet header shown below has 12 words followed
/// by optional extension fields and finally an optional message authentication code (MAC)
/// consisting of the Key Identifier field and Message Digest field.
///
/// ```ignore
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |LI | VN  |Mode |    Stratum     |     Poll      |  Precision   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Root Delay                            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Root Dispersion                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Reference ID                         |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                     Reference Timestamp (64)                  +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                      Origin Timestamp (64)                    +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                      Receive Timestamp (64)                   +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                      Transmit Timestamp (64)                  +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                    Extension Field 1 (variable)               .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// .                                                               .
/// .                    Extension Field 2 (variable)               .
/// .                                                               .
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Key Identifier                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                            dgst (128)                         |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Packet {
    /// Leap indicator warning of impending leap second.
    pub leap_indicator: LeapIndicator,
    /// NTP protocol version number (1-4).
    pub version: Version,
    /// Association mode (client, server, broadcast, etc.).
    pub mode: Mode,
    /// Stratum level of the time source (0-15).
    pub stratum: Stratum,
    /// 8-bit signed integer representing the maximum interval between successive messages, in log2
    /// seconds. Suggested default limits for minimum and maximum poll intervals are 6 and 10,
    /// respectively.
    pub poll: i8,
    /// 8-bit signed integer representing the precision of the system clock, in log2 seconds. For
    /// instance, a value of -18 corresponds to a precision of about one microsecond. The precision
    /// can be determined when the service first starts up as the minimum time of several
    /// iterations to read the system clock.
    pub precision: i8,
    /// Total round-trip delay to the reference clock, in NTP short format.
    pub root_delay: ShortFormat,
    /// Total dispersion to the reference clock, in NTP short format.
    pub root_dispersion: ShortFormat,
    /// Reference identifier (clock source or server address).
    pub reference_id: ReferenceIdentifier,
    /// Time when the system clock was last set or corrected.
    pub reference_timestamp: TimestampFormat,
    /// Time at the client when the request departed for the server.
    pub origin_timestamp: TimestampFormat,
    /// Time at the server when the request arrived from the client.
    pub receive_timestamp: TimestampFormat,
    /// Time at the server when the response left for the client.
    pub transmit_timestamp: TimestampFormat,
}

/// The consecutive types within the first packed byte in the NTP packet.
pub type PacketByte1 = (LeapIndicator, Version, Mode);

// Inherent implementations.

impl ReferenceIdentifier {
    /// Returns the raw 4-byte representation of the reference identifier.
    pub fn as_bytes(&self) -> [u8; 4] {
        match *self {
            ReferenceIdentifier::PrimarySource(src) => src.bytes(),
            ReferenceIdentifier::SecondaryOrClient(arr) => arr,
            ReferenceIdentifier::KissOfDeath(kod) => be_u32_to_bytes(kod as u32),
            ReferenceIdentifier::Unknown(arr) => arr,
        }
    }

    /// Returns true if this is a Kiss-o'-Death reference identifier.
    pub fn is_kiss_of_death(&self) -> bool {
        matches!(self, ReferenceIdentifier::KissOfDeath(_))
    }

    /// Construct a reference identifier from an IPv4 address.
    ///
    /// For stratum 2+ servers, the reference identifier is the upstream
    /// server's IPv4 address (RFC 5905 Section 7.3).
    #[cfg(feature = "std")]
    pub fn from_ipv4(addr: std::net::Ipv4Addr) -> Self {
        ReferenceIdentifier::SecondaryOrClient(addr.octets())
    }

    /// Construct a reference identifier from an IPv6 address.
    ///
    /// Per RFC 5905, the reference identifier for IPv6 peers is the first
    /// 4 bytes of `MD5(IPv6_address)`.
    ///
    /// # Collision Risk
    ///
    /// This 4-byte hash may coincidentally match an IPv4 address, causing
    /// false positive loop detection. `draft-ietf-ntp-refid-updates-05`
    /// proposes a fix but is stalled. NTPv5's 120-bit Bloom filter
    /// Reference IDs eliminate this problem entirely.
    #[cfg(feature = "std")]
    pub fn from_ipv6(addr: std::net::Ipv6Addr) -> Self {
        let hash = super::md5::md5_first4(&addr.octets());
        ReferenceIdentifier::SecondaryOrClient(hash)
    }

    /// Check if this reference identifier matches an IPv4 address.
    ///
    /// Used for loop detection: if the upstream server's reference ID
    /// matches our own IPv4 address, a timing loop exists.
    #[cfg(feature = "std")]
    pub fn matches_ipv4(&self, addr: std::net::Ipv4Addr) -> bool {
        matches!(self, ReferenceIdentifier::SecondaryOrClient(bytes) if *bytes == addr.octets())
    }
}

impl PrimarySource {
    /// The bytestring representation of the primary source.
    pub fn bytes(&self) -> [u8; 4] {
        be_u32_to_bytes(*self as u32)
    }
}

impl Version {
    /// NTP version 1.
    pub const V1: Self = Version(1);
    /// NTP version 2.
    pub const V2: Self = Version(2);
    /// NTP version 3.
    pub const V3: Self = Version(3);
    /// NTP version 4 (current standard).
    pub const V4: Self = Version(4);
    /// NTP version 5 (`draft-ietf-ntp-ntpv5`).
    pub const V5: Self = Version(5);

    /// Create a `Version` from a raw version number.
    ///
    /// Returns `None` if the value is outside the valid range (1-5).
    pub fn new(v: u8) -> Option<Self> {
        if (1..=5).contains(&v) {
            Some(Version(v))
        } else {
            None
        }
    }

    /// Returns the raw version number as a `u8`.
    pub fn value(&self) -> u8 {
        self.0
    }

    /// Whether or not the version is a known, valid version.
    pub fn is_known(&self) -> bool {
        self.0 >= 1 && self.0 <= 5
    }
}

impl Stratum {
    /// Unspecified or invalid.
    pub const UNSPECIFIED: Self = Stratum(0);
    /// The primary server (e.g. equipped with a GPS receiver.
    pub const PRIMARY: Self = Stratum(1);
    /// The minimum value specifying a secondary server (via NTP).
    pub const SECONDARY_MIN: Self = Stratum(2);
    /// The maximum value specifying a secondary server (via NTP).
    pub const SECONDARY_MAX: Self = Stratum(15);
    /// An unsynchronized stratum.
    pub const UNSYNCHRONIZED: Self = Stratum(16);
    /// The maximum valid stratum value.
    pub const MAX: Self = Stratum(16);

    /// Whether or not the stratum represents a secondary server.
    pub fn is_secondary(&self) -> bool {
        Self::SECONDARY_MIN <= *self && *self <= Self::SECONDARY_MAX
    }

    /// Whether or not the stratum is in the reserved range.
    pub fn is_reserved(&self) -> bool {
        *self > Self::MAX
    }
}

// Size implementations.

impl ConstPackedSizeBytes for ShortFormat {
    const PACKED_SIZE_BYTES: usize = 4;
}

impl ConstPackedSizeBytes for TimestampFormat {
    const PACKED_SIZE_BYTES: usize = 8;
}

impl ConstPackedSizeBytes for DateFormat {
    const PACKED_SIZE_BYTES: usize = 16;
}

impl ConstPackedSizeBytes for Stratum {
    const PACKED_SIZE_BYTES: usize = 1;
}

impl ConstPackedSizeBytes for ReferenceIdentifier {
    const PACKED_SIZE_BYTES: usize = 4;
}

impl ConstPackedSizeBytes for PacketByte1 {
    const PACKED_SIZE_BYTES: usize = 1;
}

impl ConstPackedSizeBytes for Packet {
    const PACKED_SIZE_BYTES: usize = PacketByte1::PACKED_SIZE_BYTES
        + Stratum::PACKED_SIZE_BYTES
        + 2
        + ShortFormat::PACKED_SIZE_BYTES * 2
        + ReferenceIdentifier::PACKED_SIZE_BYTES
        + TimestampFormat::PACKED_SIZE_BYTES * 4;
}

// Default implementations.

impl Default for Version {
    /// Defaults to NTPv4, the current standard (RFC 5905).
    fn default() -> Self {
        Version::V4
    }
}

impl Default for ReferenceIdentifier {
    /// Defaults to `Unknown([0; 4])` (unset reference identifier).
    fn default() -> Self {
        ReferenceIdentifier::Unknown([0; 4])
    }
}

impl Default for Packet {
    /// Defaults to a valid NTPv4 client request template.
    ///
    /// All timestamp and delay fields are zeroed. Set `transmit_timestamp`
    /// before sending.
    fn default() -> Self {
        Packet {
            leap_indicator: LeapIndicator::default(),
            version: Version::default(),
            mode: Mode::default(),
            stratum: Stratum::default(),
            poll: 0,
            precision: 0,
            root_delay: ShortFormat::default(),
            root_dispersion: ShortFormat::default(),
            reference_id: ReferenceIdentifier::default(),
            reference_timestamp: TimestampFormat::default(),
            origin_timestamp: TimestampFormat::default(),
            receive_timestamp: TimestampFormat::default(),
            transmit_timestamp: TimestampFormat::default(),
        }
    }
}

// Display implementations.

impl fmt::Display for PrimarySource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bytes = self.bytes();
        for &b in &bytes {
            if b == 0 {
                break;
            }
            if b.is_ascii() {
                write!(f, "{}", b as char)?;
            } else {
                write!(f, "?")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ConstPackedSizeBytes, FromBytes, ToBytes};

    // ── TimestampFormat ─────────────────────────────────────────────

    #[test]
    fn timestamp_format_roundtrip() {
        let ts = TimestampFormat {
            seconds: 3_913_056_000,
            fraction: 0xABCD_1234,
        };
        let mut buf = [0u8; TimestampFormat::PACKED_SIZE_BYTES];
        ts.to_bytes(&mut buf).unwrap();
        let (parsed, consumed) = TimestampFormat::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 8);
        assert_eq!(parsed, ts);
    }

    #[test]
    fn timestamp_format_buffer_too_short() {
        let buf = [0u8; 7];
        assert!(TimestampFormat::from_bytes(&buf).is_err());
    }

    #[test]
    fn timestamp_format_edge_values() {
        for (secs, frac) in [(0u32, 0u32), (u32::MAX, u32::MAX)] {
            let ts = TimestampFormat {
                seconds: secs,
                fraction: frac,
            };
            let mut buf = [0u8; 8];
            ts.to_bytes(&mut buf).unwrap();
            let (parsed, _) = TimestampFormat::from_bytes(&buf).unwrap();
            assert_eq!(parsed, ts);
        }
    }

    #[test]
    fn timestamp_format_packed_size() {
        assert_eq!(TimestampFormat::PACKED_SIZE_BYTES, 8);
    }

    // ── ShortFormat ─────────────────────────────────────────────────

    #[test]
    fn short_format_roundtrip() {
        let sf = ShortFormat {
            seconds: 1234,
            fraction: 5678,
        };
        let mut buf = [0u8; ShortFormat::PACKED_SIZE_BYTES];
        sf.to_bytes(&mut buf).unwrap();
        let (parsed, consumed) = ShortFormat::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(parsed, sf);
    }

    #[test]
    fn short_format_buffer_too_short() {
        let buf = [0u8; 3];
        assert!(ShortFormat::from_bytes(&buf).is_err());
    }

    #[test]
    fn short_format_edge_values() {
        for (secs, frac) in [(0u16, 0u16), (u16::MAX, u16::MAX)] {
            let sf = ShortFormat {
                seconds: secs,
                fraction: frac,
            };
            let mut buf = [0u8; 4];
            sf.to_bytes(&mut buf).unwrap();
            let (parsed, _) = ShortFormat::from_bytes(&buf).unwrap();
            assert_eq!(parsed, sf);
        }
    }

    // ── DateFormat ──────────────────────────────────────────────────

    #[test]
    fn date_format_roundtrip() {
        let df = DateFormat {
            era_number: -1,
            era_offset: 100_000,
            fraction: 0xDEAD_BEEF_CAFE_BABE,
        };
        let mut buf = [0u8; DateFormat::PACKED_SIZE_BYTES];
        df.to_bytes(&mut buf).unwrap();
        let (parsed, consumed) = DateFormat::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 16);
        assert_eq!(parsed, df);
    }

    #[test]
    fn date_format_buffer_too_short() {
        let buf = [0u8; 15];
        assert!(DateFormat::from_bytes(&buf).is_err());
    }

    #[test]
    fn date_format_era_number_preserved() {
        let df = DateFormat {
            era_number: 1,
            era_offset: 0,
            fraction: 0,
        };
        let mut buf = [0u8; 16];
        df.to_bytes(&mut buf).unwrap();
        let (parsed, _) = DateFormat::from_bytes(&buf).unwrap();
        assert_eq!(parsed.era_number, 1);
    }

    // ── LeapIndicator ───────────────────────────────────────────────

    #[test]
    fn leap_indicator_try_from_valid() {
        assert_eq!(LeapIndicator::try_from(0), Ok(LeapIndicator::NoWarning));
        assert_eq!(LeapIndicator::try_from(1), Ok(LeapIndicator::AddOne));
        assert_eq!(LeapIndicator::try_from(2), Ok(LeapIndicator::SubOne));
        assert_eq!(LeapIndicator::try_from(3), Ok(LeapIndicator::Unknown));
    }

    #[test]
    fn leap_indicator_try_from_invalid() {
        assert!(LeapIndicator::try_from(4).is_err());
        assert!(LeapIndicator::try_from(255).is_err());
    }

    #[test]
    fn leap_indicator_default() {
        assert_eq!(LeapIndicator::default(), LeapIndicator::NoWarning);
    }

    // ── Version ─────────────────────────────────────────────────────

    #[test]
    fn version_new_valid() {
        for v in 1..=5 {
            assert!(Version::new(v).is_some());
            assert_eq!(Version::new(v).unwrap().value(), v);
        }
    }

    #[test]
    fn version_new_invalid() {
        assert!(Version::new(0).is_none());
        assert!(Version::new(6).is_none());
        assert!(Version::new(255).is_none());
    }

    #[test]
    fn version_is_known() {
        assert!(Version::V1.is_known());
        assert!(Version::V4.is_known());
        assert!(Version::V5.is_known());
        assert!(!Version(0).is_known());
        assert!(!Version(6).is_known());
    }

    #[test]
    fn version_value() {
        assert_eq!(Version::V1.value(), 1);
        assert_eq!(Version::V4.value(), 4);
        assert_eq!(Version::V5.value(), 5);
    }

    #[test]
    fn version_default() {
        assert_eq!(Version::default(), Version::V4);
    }

    // ── Mode ────────────────────────────────────────────────────────

    #[test]
    fn mode_try_from_all_valid() {
        let expected = [
            Mode::Reserved,
            Mode::SymmetricActive,
            Mode::SymmetricPassive,
            Mode::Client,
            Mode::Server,
            Mode::Broadcast,
            Mode::NtpControlMessage,
            Mode::ReservedForPrivateUse,
        ];
        for (i, &mode) in expected.iter().enumerate() {
            assert_eq!(Mode::try_from(i as u8), Ok(mode));
        }
    }

    #[test]
    fn mode_try_from_invalid() {
        assert!(Mode::try_from(8).is_err());
        assert!(Mode::try_from(255).is_err());
    }

    #[test]
    fn mode_default() {
        assert_eq!(Mode::default(), Mode::Client);
    }

    // ── Stratum ─────────────────────────────────────────────────────

    #[test]
    fn stratum_is_secondary_boundaries() {
        assert!(!Stratum(0).is_secondary());
        assert!(!Stratum(1).is_secondary());
        assert!(Stratum(2).is_secondary());
        assert!(Stratum(15).is_secondary());
        assert!(!Stratum(16).is_secondary());
    }

    #[test]
    fn stratum_is_reserved() {
        assert!(!Stratum(0).is_reserved());
        assert!(!Stratum(16).is_reserved());
        assert!(Stratum(17).is_reserved());
        assert!(Stratum(255).is_reserved());
    }

    #[test]
    fn stratum_constants() {
        assert_eq!(Stratum::UNSPECIFIED.0, 0);
        assert_eq!(Stratum::PRIMARY.0, 1);
        assert_eq!(Stratum::SECONDARY_MIN.0, 2);
        assert_eq!(Stratum::SECONDARY_MAX.0, 15);
        assert_eq!(Stratum::UNSYNCHRONIZED.0, 16);
        assert_eq!(Stratum::MAX.0, 16);
    }

    #[test]
    fn stratum_packed_size() {
        assert_eq!(Stratum::PACKED_SIZE_BYTES, 1);
    }

    // ── ReferenceIdentifier ─────────────────────────────────────────

    #[test]
    fn refid_from_bytes_stratum0_kod() {
        let bytes = b"DENY";
        let refid = ReferenceIdentifier::from_bytes_with_stratum(*bytes, Stratum::UNSPECIFIED);
        assert_eq!(refid, ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny));
    }

    #[test]
    fn refid_from_bytes_stratum0_unknown() {
        let bytes = *b"XXXX";
        let refid = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum::UNSPECIFIED);
        assert_eq!(refid, ReferenceIdentifier::Unknown(bytes));
    }

    #[test]
    fn refid_from_bytes_stratum1_gps() {
        let bytes = *b"GPS\0";
        let refid = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum::PRIMARY);
        assert_eq!(
            refid,
            ReferenceIdentifier::PrimarySource(PrimarySource::Gps)
        );
    }

    #[test]
    fn refid_from_bytes_stratum1_unknown() {
        let bytes = *b"ZZZZ";
        let refid = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum::PRIMARY);
        assert_eq!(refid, ReferenceIdentifier::Unknown(bytes));
    }

    #[test]
    fn refid_from_bytes_stratum2_secondary() {
        let bytes = [192, 168, 1, 1];
        let refid = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum(2));
        assert_eq!(refid, ReferenceIdentifier::SecondaryOrClient(bytes));
    }

    #[test]
    fn refid_from_bytes_stratum15_secondary() {
        let bytes = [10, 0, 0, 1];
        let refid = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum(15));
        assert_eq!(refid, ReferenceIdentifier::SecondaryOrClient(bytes));
    }

    #[test]
    fn refid_from_bytes_stratum16_unknown() {
        let bytes = [1, 2, 3, 4];
        let refid = ReferenceIdentifier::from_bytes_with_stratum(bytes, Stratum(16));
        assert_eq!(refid, ReferenceIdentifier::Unknown(bytes));
    }

    #[test]
    fn refid_as_bytes_roundtrip() {
        let src = ReferenceIdentifier::PrimarySource(PrimarySource::Gps);
        let bytes = src.as_bytes();
        assert_eq!(&bytes, b"GPS\0");
    }

    #[test]
    fn refid_is_kiss_of_death() {
        assert!(ReferenceIdentifier::KissOfDeath(KissOfDeath::Deny).is_kiss_of_death());
        assert!(!ReferenceIdentifier::PrimarySource(PrimarySource::Gps).is_kiss_of_death());
        assert!(!ReferenceIdentifier::SecondaryOrClient([1, 2, 3, 4]).is_kiss_of_death());
        assert!(!ReferenceIdentifier::Unknown([0; 4]).is_kiss_of_death());
    }

    #[cfg(feature = "std")]
    #[test]
    fn refid_from_ipv4_and_matches() {
        let addr = std::net::Ipv4Addr::new(192, 168, 1, 1);
        let refid = ReferenceIdentifier::from_ipv4(addr);
        assert!(refid.matches_ipv4(addr));
        assert!(!refid.matches_ipv4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn refid_packed_size() {
        assert_eq!(ReferenceIdentifier::PACKED_SIZE_BYTES, 4);
    }

    // ── PrimarySource ───────────────────────────────────────────────

    #[test]
    fn primary_source_try_from_known() {
        assert_eq!(
            PrimarySource::try_from(u32::from_be_bytes(*b"GPS\0")),
            Ok(PrimarySource::Gps)
        );
        assert_eq!(
            PrimarySource::try_from(u32::from_be_bytes(*b"GOES")),
            Ok(PrimarySource::Goes)
        );
        assert_eq!(
            PrimarySource::try_from(u32::from_be_bytes(*b"PPS\0")),
            Ok(PrimarySource::Pps)
        );
    }

    #[test]
    fn primary_source_try_from_unknown() {
        assert!(PrimarySource::try_from(u32::from_be_bytes(*b"ZZZZ")).is_err());
    }

    #[test]
    fn primary_source_bytes_roundtrip() {
        let src = PrimarySource::Gps;
        let bytes = src.bytes();
        let u = u32::from_be_bytes(bytes);
        assert_eq!(PrimarySource::try_from(u), Ok(PrimarySource::Gps));
    }

    #[test]
    fn primary_source_display() {
        assert_eq!(format!("{}", PrimarySource::Gps), "GPS");
        assert_eq!(format!("{}", PrimarySource::Goes), "GOES");
        assert_eq!(format!("{}", PrimarySource::Pps), "PPS");
        assert_eq!(format!("{}", PrimarySource::Null), "");
    }

    // ── KissOfDeath ─────────────────────────────────────────────────

    #[test]
    fn kod_try_from_all_codes() {
        assert_eq!(
            KissOfDeath::try_from(u32::from_be_bytes(*b"DENY")),
            Ok(KissOfDeath::Deny)
        );
        assert_eq!(
            KissOfDeath::try_from(u32::from_be_bytes(*b"RSTR")),
            Ok(KissOfDeath::Rstr)
        );
        assert_eq!(
            KissOfDeath::try_from(u32::from_be_bytes(*b"RATE")),
            Ok(KissOfDeath::Rate)
        );
    }

    #[test]
    fn kod_try_from_unknown() {
        assert!(KissOfDeath::try_from(u32::from_be_bytes(*b"XXXX")).is_err());
        assert!(KissOfDeath::try_from(0).is_err());
    }

    // ── Packet ──────────────────────────────────────────────────────

    #[test]
    fn packet_packed_size() {
        assert_eq!(Packet::PACKED_SIZE_BYTES, 48);
    }

    #[test]
    fn packet_default_is_client_template() {
        let pkt = Packet::default();
        assert_eq!(pkt.leap_indicator, LeapIndicator::NoWarning);
        assert_eq!(pkt.version, Version::V4);
        assert_eq!(pkt.mode, Mode::Client);
        assert_eq!(pkt.stratum, Stratum::UNSPECIFIED);
    }

    #[test]
    fn packet_roundtrip() {
        let pkt = Packet {
            leap_indicator: LeapIndicator::AddOne,
            version: Version::V4,
            mode: Mode::Server,
            stratum: Stratum::PRIMARY,
            poll: 6,
            precision: -20,
            root_delay: ShortFormat {
                seconds: 1,
                fraction: 2,
            },
            root_dispersion: ShortFormat {
                seconds: 3,
                fraction: 4,
            },
            reference_id: ReferenceIdentifier::PrimarySource(PrimarySource::Gps),
            reference_timestamp: TimestampFormat {
                seconds: 100,
                fraction: 200,
            },
            origin_timestamp: TimestampFormat {
                seconds: 300,
                fraction: 400,
            },
            receive_timestamp: TimestampFormat {
                seconds: 500,
                fraction: 600,
            },
            transmit_timestamp: TimestampFormat {
                seconds: 700,
                fraction: 800,
            },
        };
        let mut buf = [0u8; Packet::PACKED_SIZE_BYTES];
        pkt.to_bytes(&mut buf).unwrap();
        let (parsed, consumed) = Packet::from_bytes(&buf).unwrap();
        assert_eq!(consumed, 48);
        assert_eq!(parsed.leap_indicator, pkt.leap_indicator);
        assert_eq!(parsed.version, pkt.version);
        assert_eq!(parsed.mode, pkt.mode);
        assert_eq!(parsed.stratum, pkt.stratum);
        assert_eq!(parsed.poll, pkt.poll);
        assert_eq!(parsed.precision, pkt.precision);
        assert_eq!(parsed.root_delay, pkt.root_delay);
        assert_eq!(parsed.root_dispersion, pkt.root_dispersion);
        assert_eq!(parsed.reference_id, pkt.reference_id);
        assert_eq!(parsed.reference_timestamp, pkt.reference_timestamp);
        assert_eq!(parsed.origin_timestamp, pkt.origin_timestamp);
        assert_eq!(parsed.receive_timestamp, pkt.receive_timestamp);
        assert_eq!(parsed.transmit_timestamp, pkt.transmit_timestamp);
    }

    #[test]
    fn packet_buffer_too_short() {
        let buf = [0u8; 47];
        assert!(Packet::from_bytes(&buf).is_err());
    }

    #[test]
    fn packet_to_bytes_buffer_too_short() {
        let pkt = Packet::default();
        let mut buf = [0u8; 47];
        assert!(pkt.to_bytes(&mut buf).is_err());
    }

    // ── PacketByte1 packed size ─────────────────────────────────────

    #[test]
    fn packet_byte1_packed_size() {
        assert_eq!(<(LeapIndicator, Version, Mode)>::PACKED_SIZE_BYTES, 1);
    }
}
