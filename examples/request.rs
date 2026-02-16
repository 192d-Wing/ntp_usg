//! How to request an NTP packet from an NTP server.

use chrono::TimeZone;

fn local_time(timestamp: ntp::protocol::TimestampFormat) -> chrono::DateTime<chrono::Local> {
    let unix_time = ntp::unix_time::Instant::from(timestamp);
    chrono::Local
        .timestamp_opt(unix_time.secs(), unix_time.subsec_nanos() as _)
        .unwrap()
}

fn main() {
    let address = "time.nist.gov:123";
    let result = ntp::request(address).unwrap();
    println!("Timestamps in local time:");
    println!("  reference: {}", local_time(result.reference_timestamp));
    println!("  origin:    {}", local_time(result.origin_timestamp));
    println!("  receive:   {}", local_time(result.receive_timestamp));
    println!("  transmit:  {}", local_time(result.transmit_timestamp));
    println!("\nTiming:");
    println!("  offset: {:.6} seconds", result.offset_seconds);
    println!("  delay:  {:.6} seconds", result.delay_seconds);
}
