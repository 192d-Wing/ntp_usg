use byteorder::{BE, ReadBytesExt, WriteBytesExt};
use std::io;

use super::{
    DateFormat, KissOfDeath, LeapIndicator, Mode, Packet, PrimarySource, ReadBytes, ReadFromBytes,
    ReferenceIdentifier, ShortFormat, Stratum, TimestampFormat, Version, WriteBytes, WriteToBytes,
    be_u32_to_bytes,
};

// Writer implementations.

impl<W> WriteBytes for W
where
    W: WriteBytesExt,
{
    fn write_bytes<P: WriteToBytes>(&mut self, protocol: P) -> io::Result<()> {
        protocol.write_to_bytes(self)
    }
}

impl<P> WriteToBytes for &P
where
    P: WriteToBytes,
{
    fn write_to_bytes<W: WriteBytesExt>(&self, writer: W) -> io::Result<()> {
        (*self).write_to_bytes(writer)
    }
}

impl WriteToBytes for ShortFormat {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u16::<BE>(self.seconds)?;
        writer.write_u16::<BE>(self.fraction)?;
        Ok(())
    }
}

impl WriteToBytes for TimestampFormat {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u32::<BE>(self.seconds)?;
        writer.write_u32::<BE>(self.fraction)?;
        Ok(())
    }
}

impl WriteToBytes for DateFormat {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_i32::<BE>(self.era_number)?;
        writer.write_u32::<BE>(self.era_offset)?;
        writer.write_u64::<BE>(self.fraction)?;
        Ok(())
    }
}

impl WriteToBytes for Stratum {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        writer.write_u8(self.0)?;
        Ok(())
    }
}

impl WriteToBytes for ReferenceIdentifier {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        match *self {
            ReferenceIdentifier::KissOfDeath(kod) => {
                writer.write_u32::<BE>(kod as u32)?;
            }
            ReferenceIdentifier::PrimarySource(src) => {
                writer.write_u32::<BE>(src as u32)?;
            }
            ReferenceIdentifier::SecondaryOrClient(arr) => {
                writer.write_u32::<BE>(code_to_u32!(&arr))?;
            }
            ReferenceIdentifier::Unknown(arr) => {
                writer.write_u32::<BE>(code_to_u32!(&arr))?;
            }
        }
        Ok(())
    }
}

impl WriteToBytes for (LeapIndicator, Version, Mode) {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        let (li, vn, mode) = *self;
        let mut li_vn_mode = 0;
        li_vn_mode |= (li as u8) << 6;
        li_vn_mode |= vn.0 << 3;
        li_vn_mode |= mode as u8;
        writer.write_u8(li_vn_mode)?;
        Ok(())
    }
}

impl WriteToBytes for Packet {
    fn write_to_bytes<W: WriteBytesExt>(&self, mut writer: W) -> io::Result<()> {
        let li_vn_mode = (self.leap_indicator, self.version, self.mode);
        writer.write_bytes(li_vn_mode)?;
        writer.write_bytes(self.stratum)?;
        writer.write_i8(self.poll)?;
        writer.write_i8(self.precision)?;
        writer.write_bytes(self.root_delay)?;
        writer.write_bytes(self.root_dispersion)?;
        writer.write_bytes(self.reference_id)?;
        writer.write_bytes(self.reference_timestamp)?;
        writer.write_bytes(self.origin_timestamp)?;
        writer.write_bytes(self.receive_timestamp)?;
        writer.write_bytes(self.transmit_timestamp)?;
        Ok(())
    }
}

// Reader implementations.

impl<R> ReadBytes for R
where
    R: ReadBytesExt,
{
    fn read_bytes<P: ReadFromBytes>(&mut self) -> io::Result<P> {
        P::read_from_bytes(self)
    }
}

impl ReadFromBytes for ShortFormat {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let seconds = reader.read_u16::<BE>()?;
        let fraction = reader.read_u16::<BE>()?;
        let short_format = ShortFormat { seconds, fraction };
        Ok(short_format)
    }
}

impl ReadFromBytes for TimestampFormat {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let seconds = reader.read_u32::<BE>()?;
        let fraction = reader.read_u32::<BE>()?;
        let timestamp_format = TimestampFormat { seconds, fraction };
        Ok(timestamp_format)
    }
}

impl ReadFromBytes for DateFormat {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let era_number = reader.read_i32::<BE>()?;
        let era_offset = reader.read_u32::<BE>()?;
        let fraction = reader.read_u64::<BE>()?;
        let date_format = DateFormat {
            era_number,
            era_offset,
            fraction,
        };
        Ok(date_format)
    }
}

impl ReadFromBytes for Stratum {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let stratum = Stratum(reader.read_u8()?);
        Ok(stratum)
    }
}

impl ReadFromBytes for (LeapIndicator, Version, Mode) {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let li_vn_mode = reader.read_u8()?;
        let li_u8 = li_vn_mode >> 6;
        let vn_u8 = (li_vn_mode >> 3) & 0b111;
        let mode_u8 = li_vn_mode & 0b111;
        let li = match LeapIndicator::try_from(li_u8).ok() {
            Some(li) => li,
            None => {
                let err_msg = "unknown leap indicator";
                return Err(io::Error::new(io::ErrorKind::InvalidData, err_msg));
            }
        };
        let vn = Version(vn_u8);
        let mode = match Mode::try_from(mode_u8).ok() {
            Some(mode) => mode,
            None => {
                let err_msg = "unknown association mode";
                return Err(io::Error::new(io::ErrorKind::InvalidData, err_msg));
            }
        };
        Ok((li, vn, mode))
    }
}

impl ReadFromBytes for Packet {
    fn read_from_bytes<R: ReadBytesExt>(mut reader: R) -> io::Result<Self> {
        let (leap_indicator, version, mode) = reader.read_bytes()?;
        let stratum = reader.read_bytes::<Stratum>()?;
        let poll = reader.read_i8()?;
        let precision = reader.read_i8()?;
        let root_delay = reader.read_bytes()?;
        let root_dispersion = reader.read_bytes()?;
        let reference_id = {
            let u = reader.read_u32::<BE>()?;
            let raw_bytes = be_u32_to_bytes(u);
            if stratum == Stratum::UNSPECIFIED {
                // Stratum 0: Kiss-o'-Death packet (RFC 5905 Section 7.4).
                match KissOfDeath::try_from(u) {
                    Ok(kod) => ReferenceIdentifier::KissOfDeath(kod),
                    Err(_) => ReferenceIdentifier::Unknown(raw_bytes),
                }
            } else if stratum == Stratum::PRIMARY {
                // Stratum 1: primary reference source (4-char ASCII).
                match PrimarySource::try_from(u) {
                    Ok(src) => ReferenceIdentifier::PrimarySource(src),
                    Err(_) => ReferenceIdentifier::Unknown(raw_bytes),
                }
            } else if stratum.is_secondary() {
                // Stratum 2-15: IPv4 address or first 4 octets of MD5 hash of IPv6 address.
                ReferenceIdentifier::SecondaryOrClient(raw_bytes)
            } else {
                // Stratum 16 (unsynchronized) or 17-255 (reserved).
                ReferenceIdentifier::Unknown(raw_bytes)
            }
        };
        let reference_timestamp = reader.read_bytes()?;
        let origin_timestamp = reader.read_bytes()?;
        let receive_timestamp = reader.read_bytes()?;
        let transmit_timestamp = reader.read_bytes()?;
        Ok(Packet {
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
        })
    }
}
