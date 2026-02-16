// NMEA 0183 sentence parser for GPS receivers
//
// Supports the most common NMEA sentences used for time synchronization:
// - $GPGGA - Global Positioning System Fix Data
// - $GPRMC - Recommended Minimum Specific GPS Data
// - $GPZDA - Date & Time (preferred for NTP)

use std::io;

/// GPS fix quality
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FixQuality {
    /// No fix available
    NoFix = 0,
    /// GPS fix
    Gps = 1,
    /// Differential GPS fix
    DGps = 2,
    /// PPS fix
    Pps = 3,
    /// Real-time kinematic
    Rtk = 4,
    /// Float RTK
    FloatRtk = 5,
    /// Estimated/Dead reckoning
    Estimated = 6,
    /// Manual input
    Manual = 7,
    /// Simulation
    Simulation = 8,
}

impl FixQuality {
    /// Convert a numeric value to FixQuality
    pub fn from_u8(val: u8) -> Self {
        match val {
            0 => FixQuality::NoFix,
            1 => FixQuality::Gps,
            2 => FixQuality::DGps,
            3 => FixQuality::Pps,
            4 => FixQuality::Rtk,
            5 => FixQuality::FloatRtk,
            6 => FixQuality::Estimated,
            7 => FixQuality::Manual,
            8 => FixQuality::Simulation,
            _ => FixQuality::NoFix,
        }
    }

    /// Check if this fix quality is valid for time synchronization
    pub fn is_valid(&self) -> bool {
        !matches!(
            self,
            FixQuality::NoFix | FixQuality::Simulation | FixQuality::Manual
        )
    }
}

/// GPS time and position fix
#[derive(Debug, Clone)]
pub struct GpsFix {
    /// UTC time (hours, minutes, seconds)
    pub time: (u8, u8, f64),

    /// UTC date (year, month, day) - may be None for GGA sentences
    pub date: Option<(u16, u8, u8)>,

    /// Fix quality
    pub quality: FixQuality,

    /// Number of satellites in use
    pub satellites: u8,

    /// Horizontal dilution of precision
    pub hdop: Option<f64>,

    /// Altitude above sea level (meters)
    pub altitude: Option<f64>,

    /// Latitude (decimal degrees, positive = North)
    pub latitude: Option<f64>,

    /// Longitude (decimal degrees, positive = East)
    pub longitude: Option<f64>,
}

impl GpsFix {
    /// Check if this GPS fix is valid for time synchronization
    pub fn is_valid(&self) -> bool {
        self.quality.is_valid() && self.satellites >= 3
    }

    /// Convert GPS time to Unix timestamp
    ///
    /// Returns None if date is not available or if the fix is invalid
    pub fn to_unix_timestamp(&self) -> Option<f64> {
        if !self.is_valid() {
            return None;
        }

        let (year, month, day) = self.date?;
        let (hour, minute, second) = self.time;

        // Simple conversion (not accounting for leap seconds)
        // For production use, consider a proper datetime library
        let days_since_epoch = days_since_unix_epoch(year as i32, month, day)?;
        let seconds_today = hour as f64 * 3600.0 + minute as f64 * 60.0 + second;

        Some(days_since_epoch as f64 * 86400.0 + seconds_today)
    }
}

/// Parse NMEA sentence
pub fn parse_sentence(sentence: &str) -> io::Result<Option<GpsFix>> {
    let sentence = sentence.trim();

    // Validate checksum if present
    if let Some(star_pos) = sentence.rfind('*') {
        let data = &sentence[..star_pos];
        let expected_checksum = &sentence[star_pos + 1..];

        let calculated = calculate_checksum(&data[1..]); // Skip '$'
        let expected = u8::from_str_radix(expected_checksum, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid checksum format"))?;

        if calculated != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Checksum mismatch: expected {:02X}, got {:02X}",
                    expected, calculated
                ),
            ));
        }
    }

    // Remove checksum for parsing
    let data = if let Some(pos) = sentence.find('*') {
        &sentence[..pos]
    } else {
        sentence
    };

    let fields: Vec<&str> = data.split(',').collect();
    if fields.is_empty() {
        return Ok(None);
    }

    match fields[0] {
        "$GPGGA" | "$GNGGA" => parse_gga(&fields),
        "$GPRMC" | "$GNRMC" => parse_rmc(&fields),
        "$GPZDA" | "$GNZDA" => parse_zda(&fields),
        _ => Ok(None), // Unsupported sentence
    }
}

fn parse_gga(fields: &[&str]) -> io::Result<Option<GpsFix>> {
    if fields.len() < 15 {
        return Ok(None);
    }

    let time = parse_time(fields[1])?;
    let quality = FixQuality::from_u8(fields[6].parse().unwrap_or(0));
    let satellites = fields[7].parse().unwrap_or(0);
    let hdop = fields[8].parse().ok();
    let altitude = fields[9].parse().ok();

    // Parse position
    let latitude = parse_coordinate(fields[2], fields[3]);
    let longitude = parse_coordinate(fields[4], fields[5]);

    Ok(Some(GpsFix {
        time,
        date: None, // GGA doesn't include date
        quality,
        satellites,
        hdop,
        altitude,
        latitude,
        longitude,
    }))
}

fn parse_rmc(fields: &[&str]) -> io::Result<Option<GpsFix>> {
    if fields.len() < 10 {
        return Ok(None);
    }

    let time = parse_time(fields[1])?;
    let status = fields[2];
    let date = if fields.len() > 9 {
        parse_date(fields[9]).ok()
    } else {
        None
    };

    // RMC status: A = valid, V = invalid
    let quality = if status == "A" {
        FixQuality::Gps
    } else {
        FixQuality::NoFix
    };

    let latitude = parse_coordinate(fields[3], fields[4]);
    let longitude = parse_coordinate(fields[5], fields[6]);

    Ok(Some(GpsFix {
        time,
        date,
        quality,
        satellites: 0, // RMC doesn't include satellite count
        hdop: None,
        altitude: None,
        latitude,
        longitude,
    }))
}

fn parse_zda(fields: &[&str]) -> io::Result<Option<GpsFix>> {
    if fields.len() < 7 {
        return Ok(None);
    }

    let time = parse_time(fields[1])?;

    let day: u8 = fields[2]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid day"))?;
    let month: u8 = fields[3]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid month"))?;
    let year: u16 = fields[4]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid year"))?;

    Ok(Some(GpsFix {
        time,
        date: Some((year, month, day)),
        quality: FixQuality::Gps, // ZDA doesn't include quality
        satellites: 0,
        hdop: None,
        altitude: None,
        latitude: None,
        longitude: None,
    }))
}

fn parse_time(s: &str) -> io::Result<(u8, u8, f64)> {
    if s.len() < 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid time format",
        ));
    }

    let hour: u8 = s[0..2]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid hour"))?;
    let minute: u8 = s[2..4]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid minute"))?;
    let second: f64 = s[4..]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid second"))?;

    Ok((hour, minute, second))
}

fn parse_date(s: &str) -> io::Result<(u16, u8, u8)> {
    if s.len() != 6 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid date format",
        ));
    }

    let day: u8 = s[0..2]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid day"))?;
    let month: u8 = s[2..4]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid month"))?;
    let year: u8 = s[4..6]
        .parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid year"))?;

    let full_year = if year >= 80 {
        1900 + year as u16
    } else {
        2000 + year as u16
    };

    Ok((full_year, month, day))
}

fn parse_coordinate(value: &str, direction: &str) -> Option<f64> {
    if value.is_empty() || direction.is_empty() {
        return None;
    }

    // Format: DDMM.MMMM or DDDMM.MMMM
    let dot_pos = value.find('.')?;
    if dot_pos < 2 {
        return None;
    }

    let degrees: f64 = value[..dot_pos - 2].parse().ok()?;
    let minutes: f64 = value[dot_pos - 2..].parse().ok()?;

    let mut coord = degrees + minutes / 60.0;

    // Apply direction
    if direction == "S" || direction == "W" {
        coord = -coord;
    }

    Some(coord)
}

fn calculate_checksum(data: &str) -> u8 {
    data.bytes().fold(0u8, |acc, b| acc ^ b)
}

fn days_since_unix_epoch(year: i32, month: u8, day: u8) -> Option<i32> {
    // Simple day calculation (doesn't account for leap seconds)
    // Based on: https://en.wikipedia.org/wiki/Julian_day

    let a = (14 - month as i32) / 12;
    let y = year + 4800 - a;
    let m = month as i32 + 12 * a - 3;

    let jdn = day as i32 + (153 * m + 2) / 5 + 365 * y + y / 4 - y / 100 + y / 400 - 32045;

    // Unix epoch is JDN 2440588
    Some(jdn - 2440588)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gga() {
        let sentence = "$GPGGA,123519.000,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*59";
        let fix = parse_sentence(sentence).unwrap().unwrap();

        assert_eq!(fix.time, (12, 35, 19.0));
        assert_eq!(fix.quality, FixQuality::Gps);
        assert_eq!(fix.satellites, 8);
        assert!((fix.hdop.unwrap() - 0.9).abs() < 0.001);
        assert!((fix.altitude.unwrap() - 545.4).abs() < 0.001);
    }

    #[test]
    fn test_parse_rmc() {
        let sentence = "$GPRMC,123519.000,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*74";
        let fix = parse_sentence(sentence).unwrap().unwrap();

        assert_eq!(fix.time, (12, 35, 19.0));
        assert_eq!(fix.quality, FixQuality::Gps);
        assert_eq!(fix.date, Some((1994, 3, 23)));
    }

    #[test]
    fn test_parse_zda() {
        let sentence = "$GPZDA,123519.000,23,03,1994,00,00*5C";
        let fix = parse_sentence(sentence).unwrap().unwrap();

        assert_eq!(fix.time, (12, 35, 19.0));
        assert_eq!(fix.date, Some((1994, 3, 23)));
    }

    #[test]
    fn test_checksum() {
        let data = "GPGGA,123519.000,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,";
        assert_eq!(calculate_checksum(data), 0x59);
    }

    #[test]
    fn test_invalid_checksum() {
        let sentence = "$GPGGA,123519.000,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*99";
        assert!(parse_sentence(sentence).is_err());
    }

    #[test]
    fn test_parse_coordinate() {
        assert_eq!(parse_coordinate("4807.038", "N"), Some(48.1173));
        assert_eq!(parse_coordinate("01131.000", "E"), Some(11.516666666666667));
        assert_eq!(parse_coordinate("4807.038", "S"), Some(-48.1173));
        assert_eq!(
            parse_coordinate("01131.000", "W"),
            Some(-11.516666666666667)
        );
    }

    #[test]
    fn test_days_since_epoch() {
        // 1970-01-01 should be 0
        assert_eq!(days_since_unix_epoch(1970, 1, 1), Some(0));

        // 2000-01-01 should be 10957
        assert_eq!(days_since_unix_epoch(2000, 1, 1), Some(10957));

        // 2024-01-01
        assert_eq!(days_since_unix_epoch(2024, 1, 1), Some(19723));
    }
}
