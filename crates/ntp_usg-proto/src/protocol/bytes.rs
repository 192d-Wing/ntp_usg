use crate::error::ParseError;

use super::{
    ConstPackedSizeBytes, DateFormat, FromBytes, KissOfDeath, LeapIndicator, Mode, Packet,
    PrimarySource, ReferenceIdentifier, ShortFormat, Stratum, TimestampFormat, ToBytes, Version,
};

impl FromBytes for ShortFormat {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let seconds = u16::from_be_bytes([buf[0], buf[1]]);
        let fraction = u16::from_be_bytes([buf[2], buf[3]]);
        Ok((ShortFormat { seconds, fraction }, Self::PACKED_SIZE_BYTES))
    }
}

impl FromBytes for TimestampFormat {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let seconds = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let fraction = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        Ok((
            TimestampFormat { seconds, fraction },
            Self::PACKED_SIZE_BYTES,
        ))
    }
}

impl FromBytes for DateFormat {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let era_number = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let era_offset = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let fraction = u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        Ok((
            DateFormat {
                era_number,
                era_offset,
                fraction,
            },
            Self::PACKED_SIZE_BYTES,
        ))
    }
}

impl FromBytes for Stratum {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        Ok((Stratum(buf[0]), 1))
    }
}

impl FromBytes for (LeapIndicator, Version, Mode) {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        let li_vn_mode = buf[0];
        let li_u8 = li_vn_mode >> 6;
        let vn_u8 = (li_vn_mode >> 3) & 0b111;
        let mode_u8 = li_vn_mode & 0b111;
        let li = LeapIndicator::try_from(li_u8).map_err(|_| ParseError::InvalidField {
            field: "leap indicator",
            value: li_u8 as u32,
        })?;
        let vn = Version(vn_u8);
        let mode = Mode::try_from(mode_u8).map_err(|_| ParseError::InvalidField {
            field: "association mode",
            value: mode_u8 as u32,
        })?;
        Ok(((li, vn, mode), 1))
    }
}

impl ReferenceIdentifier {
    /// Parse a reference identifier from 4 bytes, using stratum for disambiguation.
    ///
    /// The interpretation of the reference identifier depends on the stratum:
    /// - Stratum 0: Kiss-o'-Death code
    /// - Stratum 1: Primary source identifier
    /// - Stratum 2-15: Secondary/client reference (IPv4 or IPv6 hash)
    /// - Stratum 16+: Unknown
    pub fn from_bytes_with_stratum(bytes: [u8; 4], stratum: Stratum) -> Self {
        let u = u32::from_be_bytes(bytes);
        if stratum == Stratum::UNSPECIFIED {
            match KissOfDeath::try_from(u) {
                Ok(kod) => ReferenceIdentifier::KissOfDeath(kod),
                Err(_) => ReferenceIdentifier::Unknown(bytes),
            }
        } else if stratum == Stratum::PRIMARY {
            match PrimarySource::try_from(u) {
                Ok(src) => ReferenceIdentifier::PrimarySource(src),
                Err(_) => ReferenceIdentifier::Unknown(bytes),
            }
        } else if stratum.is_secondary() {
            ReferenceIdentifier::SecondaryOrClient(bytes)
        } else {
            ReferenceIdentifier::Unknown(bytes)
        }
    }
}

impl FromBytes for Packet {
    fn from_bytes(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }

        let mut offset = 0;

        let ((leap_indicator, version, mode), n) =
            <(LeapIndicator, Version, Mode)>::from_bytes(&buf[offset..])?;
        offset += n;

        let (stratum, n) = Stratum::from_bytes(&buf[offset..])?;
        offset += n;

        let poll = buf[offset] as i8;
        offset += 1;

        let precision = buf[offset] as i8;
        offset += 1;

        let (root_delay, n) = ShortFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let (root_dispersion, n) = ShortFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let ref_id_bytes = [
            buf[offset],
            buf[offset + 1],
            buf[offset + 2],
            buf[offset + 3],
        ];
        let reference_id = ReferenceIdentifier::from_bytes_with_stratum(ref_id_bytes, stratum);
        offset += 4;

        let (reference_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let (origin_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let (receive_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        let (transmit_timestamp, n) = TimestampFormat::from_bytes(&buf[offset..])?;
        offset += n;

        Ok((
            Packet {
                leap_indicator,
                version,
                mode,
                stratum,
                poll,
                precision,
                root_delay,
                root_dispersion,
                reference_id,
                reference_timestamp,
                origin_timestamp,
                receive_timestamp,
                transmit_timestamp,
            },
            offset,
        ))
    }
}

// Buffer-based writer implementations (io-independent).

impl ToBytes for ShortFormat {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let s = self.seconds.to_be_bytes();
        let f = self.fraction.to_be_bytes();
        buf[0] = s[0];
        buf[1] = s[1];
        buf[2] = f[0];
        buf[3] = f[1];
        Ok(Self::PACKED_SIZE_BYTES)
    }
}

impl ToBytes for TimestampFormat {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let s = self.seconds.to_be_bytes();
        let f = self.fraction.to_be_bytes();
        buf[..4].copy_from_slice(&s);
        buf[4..8].copy_from_slice(&f);
        Ok(Self::PACKED_SIZE_BYTES)
    }
}

impl ToBytes for DateFormat {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        buf[..4].copy_from_slice(&self.era_number.to_be_bytes());
        buf[4..8].copy_from_slice(&self.era_offset.to_be_bytes());
        buf[8..16].copy_from_slice(&self.fraction.to_be_bytes());
        Ok(Self::PACKED_SIZE_BYTES)
    }
}

impl ToBytes for Stratum {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        buf[0] = self.0;
        Ok(1)
    }
}

impl ToBytes for (LeapIndicator, Version, Mode) {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.is_empty() {
            return Err(ParseError::BufferTooShort {
                needed: 1,
                available: 0,
            });
        }
        let (li, vn, mode) = *self;
        let mut li_vn_mode = 0u8;
        li_vn_mode |= (li as u8) << 6;
        li_vn_mode |= vn.0 << 3;
        li_vn_mode |= mode as u8;
        buf[0] = li_vn_mode;
        Ok(1)
    }
}

impl ToBytes for ReferenceIdentifier {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }
        let bytes = self.as_bytes();
        buf[..4].copy_from_slice(&bytes);
        Ok(Self::PACKED_SIZE_BYTES)
    }
}

impl ToBytes for Packet {
    fn to_bytes(&self, buf: &mut [u8]) -> Result<usize, ParseError> {
        if buf.len() < Self::PACKED_SIZE_BYTES {
            return Err(ParseError::BufferTooShort {
                needed: Self::PACKED_SIZE_BYTES,
                available: buf.len(),
            });
        }

        let mut offset = 0;

        let li_vn_mode = (self.leap_indicator, self.version, self.mode);
        offset += li_vn_mode.to_bytes(&mut buf[offset..])?;
        offset += self.stratum.to_bytes(&mut buf[offset..])?;
        buf[offset] = self.poll as u8;
        offset += 1;
        buf[offset] = self.precision as u8;
        offset += 1;
        offset += self.root_delay.to_bytes(&mut buf[offset..])?;
        offset += self.root_dispersion.to_bytes(&mut buf[offset..])?;
        offset += self.reference_id.to_bytes(&mut buf[offset..])?;
        offset += self.reference_timestamp.to_bytes(&mut buf[offset..])?;
        offset += self.origin_timestamp.to_bytes(&mut buf[offset..])?;
        offset += self.receive_timestamp.to_bytes(&mut buf[offset..])?;
        offset += self.transmit_timestamp.to_bytes(&mut buf[offset..])?;

        Ok(offset)
    }
}
