# Integration Tests

This directory contains integration tests that verify `ntp_usg-client` behavior against real NTP infrastructure.

## Test Categories

### Basic Integration Tests ([integration.rs](integration.rs))

Tests against public NTP servers without authentication:

- **Individual Server Tests**: NIST, Cloudflare, Google Public NTP, NTP Pool
- **Multi-Server Consistency**: Verifies multiple servers agree on time within tolerance
- **Continuous Client Convergence**: Tests adaptive polling and selection algorithms
- **SNTP API**: Validates RFC 4330 Simple NTP client
- **IPv6 Support**: Tests dual-stack operation
- **Rapid Queries**: Verifies consistency under repeated queries
- **Stratum Validation**: Checks server quality metrics

**Run all basic integration tests:**
```bash
cargo test --test integration --features ntp_usg-client/tokio
```

**Run specific test:**
```bash
cargo test --test integration --features ntp_usg-client/tokio -- test_nist_time_server
```

### NTS Integration Tests ([nts_integration.rs](nts_integration.rs))

Tests Network Time Security (RFC 8915) authenticated time synchronization:

- **NTS-KE (Key Establishment)**: TLS 1.3 handshake with public NTS servers
- **Authenticated Requests**: AEAD-encrypted NTP queries
- **Cookie Rotation**: Verifies cookie management and replenishment
- **Continuous NTS Client**: Long-running authenticated sessions
- **Mixed Deployment**: Combined NTS + standard NTP for resilience
- **Timeout Handling**: Validates proper error behavior

**Run all NTS integration tests:**
```bash
cargo test --test nts_integration --features ntp_usg-client/nts
```

**Run specific NTS test:**
```bash
cargo test --test nts_integration --features ntp_usg-client/nts -- test_nts_cloudflare
```

## Network Requirements

These tests require:
- **Internet connectivity** to reach public NTP servers
- **UDP port 123** access for NTP queries
- **TCP port 4460** access for NTS-KE (NTS tests only)
- **Firewall rules** allowing outbound NTP and NTS-KE traffic

### Tested Public Infrastructure

#### Standard NTP Servers
- **NIST** (time.nist.gov, time-a-g.nist.gov) - US Government
- **Cloudflare** (time.cloudflare.com) - Global CDN, anycast
- **Google Public NTP** (time.google.com) - Global infrastructure
- **NTP Pool** (pool.ntp.org) - Community volunteer pool

#### NTS Servers
- **Cloudflare** (time.cloudflare.com) - Production NTS deployment

## Running in CI/CD

To skip network tests in restricted environments:

```bash
export SKIP_NETWORK_TESTS=1
cargo test --features ntp_usg-client/tokio
```

Tests will gracefully skip when network is unavailable and log:
```
Skipping test_nist_time_server: network unreachable
```

## Test Tolerances

The tests use relaxed tolerances to accommodate various network conditions:

| Metric | Tolerance | Typical Real-World |
|--------|-----------|-------------------|
| Clock offset | ±5 seconds | ±100 milliseconds |
| Round-trip delay | < 2 seconds | < 100 milliseconds |
| Server agreement | < 1 second | < 10 milliseconds |
| Successive query spread | < 100 milliseconds | < 10 milliseconds |

These tolerances are intentionally loose to prevent spurious CI failures while still catching real bugs.

## Troubleshooting

### Tests timeout or fail with "network unreachable"

**Cause**: Firewall, VPN, or no internet connectivity

**Solution**:
1. Check internet connection
2. Verify UDP port 123 and TCP port 4460 (NTS) are not blocked
3. Try running a single test with `--nocapture` to see detailed error messages:
   ```bash
   cargo test --test integration --features ntp_usg-client/tokio -- --nocapture test_nist_time_server
   ```
4. Set `SKIP_NETWORK_TESTS=1` if running in restricted environment

### NTS tests fail with "Connection reset"

**Cause**: Rate limiting, transient network issues, or TLS handshake failures

**Solution**:
- Retry the test (NTS servers may rate-limit aggressive testing)
- Check if TLS 1.3 is supported by your system
- Verify system time is approximately correct (TLS certificates require valid time)

### Tests pass but show large offsets

**Cause**: Local system clock is significantly wrong

**Solution**:
- Check your system time: `date`
- Synchronize system clock: `sudo ntpdate -u time.nist.gov` (macOS/Linux)
- Tests will still pass if offset is < 5 seconds (tolerance threshold)

### Continuous client tests timeout

**Cause**: Servers not responding, or min_poll interval too long

**Solution**:
- Tests use min_poll=4 (16 seconds) for faster convergence
- Timeout is set to 60-90 seconds to allow for initial queries
- Check server availability with `ntpdate -q time.nist.gov`

## Performance Expectations

Typical test run times:

| Test Suite | Duration | Network Queries |
|------------|----------|----------------|
| Basic integration (10 tests) | ~5 seconds | ~15-20 queries |
| NTS integration (6 tests) | ~10 seconds | ~10 NTS-KE + ~15 NTP |
| Full test suite | ~15 seconds | ~35 total |

Times may vary based on network latency and server response times.

## Adding New Integration Tests

When adding new integration tests:

1. **Use appropriate timeouts**: 10-15 seconds for one-shot queries, 60-90 seconds for continuous clients
2. **Handle network errors gracefully**: Check for `TimedOut`, `ConnectionReset`, `ConnectionRefused`
3. **Use relaxed tolerances**: Allow for network variability
4. **Test against multiple servers**: Avoid dependency on a single server
5. **Log useful information**: Use `println!()` for diagnostic output (visible with `--nocapture`)
6. **Respect rate limits**: Avoid aggressive loops that could trigger server-side rate limiting

Example template:

```rust
#[tokio::test]
async fn test_new_feature() {
    if !is_network_available() {
        return;
    }

    match ntp_client::async_ntp::request_with_timeout("time.nist.gov:123", QUERY_TIMEOUT).await {
        Ok(result) => {
            println!("Test: offset={:.6}s", result.offset_seconds);
            assert!(result.offset_seconds.abs() < MAX_OFFSET);
            // Additional assertions...
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut
                || e.kind() == std::io::ErrorKind::ConnectionReset => {
            eprintln!("Skipping test: network unreachable");
        }
        Err(e) => panic!("Unexpected error: {e}"),
    }
}
```

## Resources

- [RFC 5905: Network Time Protocol Version 4](https://www.rfc-editor.org/rfc/rfc5905.html)
- [RFC 8915: Network Time Security for NTP](https://www.rfc-editor.org/rfc/rfc8915.html)
- [RFC 4330: Simple Network Time Protocol (SNTP)](https://www.rfc-editor.org/rfc/rfc4330.html)
- [NTP Pool Project](https://www.ntppool.org/)
- [Cloudflare Time Services](https://www.cloudflare.com/time/)
- [Google Public NTP](https://developers.google.com/time/)
