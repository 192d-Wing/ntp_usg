# Docker Testing Environment

This directory contains Docker configurations for testing `ntp_usg` in isolated environments.

## Overview

The Docker Compose setup provides:
- **NTP Server**: Standard NTPv4 server for basic integration tests
- **NTS Server**: NTS-authenticated server with TLS certificate generation
- **Test Runner**: Container that runs integration tests against local servers
- **Network Isolation**: Private Docker network for reproducible testing

## Quick Start

### Run Integration Tests

```bash
cd docker
docker compose up --build test-runner
```

This will:
1. Generate self-signed TLS certificates for NTS
2. Start NTP and NTS servers
3. Run all integration tests against local servers
4. Display test results

### Start Servers Only

To run servers in the background for manual testing:

```bash
docker compose up -d ntp-server nts-server
```

Then test from your host:

```bash
# Test NTP server (mapped to port 8123)
cargo run -p ntp_usg-client --example request -- localhost:8123

# Test NTS server (requires accepting self-signed cert)
RUST_LOG=debug cargo run -p ntp_usg-client --example nts_request \
    --features ntp_usg-client/nts -- localhost
```

### Stop All Services

```bash
docker compose down
```

## Services

### ntp-server

Standard NTPv4 server running on port 123 (mapped to 8123 on host).

**Configuration:**
- Stratum: 2
- Listen: 0.0.0.0:123
- Features: Basic NTP v4

**Health Check:** UDP connectivity test

**Logs:**
```bash
docker compose logs -f ntp-server
```

### nts-server

NTS-authenticated server with NTS-KE on port 4460 and NTP on port 123.

**Configuration:**
- NTP Port: 123 (mapped to 8123 on host)
- NTS-KE Port: 4460
- Stratum: 2
- TLS: Self-signed certificate (generated automatically)

**Health Check:** TCP connectivity to NTS-KE port

**Logs:**
```bash
docker compose logs -f nts-server
```

**Note**: Self-signed certificates are generated in `./certs/` and mounted read-only.

### test-runner

Runs integration tests against the local servers.

**Features Tested:**
- Basic NTP client/server communication
- Multi-peer selection and clustering
- NTS key establishment and authentication
- Clock offset and delay calculations

**Override test command:**
```bash
docker compose run test-runner cargo test --test integration -- --nocapture
```

## Certificate Management

### Generated Certificates

The `generate-certs` service creates:
- `./certs/server.crt` - Self-signed X.509 certificate
- `./certs/server.key` - Private RSA key (4096-bit)

**Properties:**
- CN: nts-test-server
- Validity: 365 days
- SANs: nts-test-server, localhost, 127.0.0.1

### Regenerate Certificates

```bash
rm -rf certs/
docker compose up generate-certs
```

### Using Custom Certificates

Replace files in `./certs/` with your own:

```bash
cp /path/to/your/cert.pem certs/server.crt
cp /path/to/your/key.pem certs/server.key
docker compose restart nts-server
```

## Network Configuration

All services run in an isolated bridge network (`ntp-test-net`):

- Subnet: 172.28.0.0/16
- DNS: Service name resolution (ntp-server, nts-server)
- Isolation: No access to host network except exposed ports

**Port Mapping:**

| Service | Internal Port | Host Port | Protocol |
|---------|--------------|-----------|----------|
| ntp-server | 123 | 8123 | UDP |
| nts-server | 123 | 8123 | UDP |
| nts-server | 4460 | 4460 | TCP |

**Note**: Only one server at a time can bind to host port 8123.

## Troubleshooting

### Port already in use

**Error**: `Bind for 0.0.0.0:8123 failed: port is already allocated`

**Solution**:
```bash
# Check what's using the port
lsof -i :8123

# Stop conflicting service or change port mapping in docker-compose.yml
```

### Health check failing

**Error**: `ntp-server is unhealthy`

**Solution**:
```bash
# Check server logs
docker compose logs ntp-server

# Verify container is running
docker ps | grep ntp

# Restart the service
docker compose restart ntp-server
```

### Certificate errors in NTS tests

**Error**: `certificate verify failed`

**Solution**:
Self-signed certificates are expected. Tests should handle this gracefully. If not:

```bash
# Regenerate certificates
rm -rf certs/
docker compose up generate-certs
docker compose restart nts-server
```

### Build errors

**Error**: Build failures due to missing dependencies

**Solution**:
```bash
# Clean build cache
docker compose build --no-cache

# Or remove all images and rebuild
docker compose down --rmi all
docker compose up --build
```

## Development Workflow

### Iterative Testing

```bash
# Terminal 1: Start servers
docker compose up ntp-server nts-server

# Terminal 2: Run tests on host (faster iteration)
cargo test --test integration --features ntp_usg-client/tokio

# Make changes to code...

# Re-run specific test
cargo test --test integration --features ntp_usg-client/tokio -- test_name
```

### Full Integration Test

```bash
# Full test including Docker build
docker compose up --build --abort-on-container-exit test-runner
```

### Manual Server Interaction

```bash
# Start server
docker compose up -d ntp-server

# Query with ntpdate (if installed)
ntpdate -q localhost -p 8123

# Query with ntp_usg-client
cargo run -p ntp_usg-client --example request -- localhost:8123

# Inspect packets with tcpdump
sudo tcpdump -i any -vv port 8123
```

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Docker Integration Tests

on: [push, pull_request]

jobs:
  docker-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Docker integration tests
        run: |
          cd docker
          docker compose up --build --abort-on-container-exit test-runner
          docker compose down
```

### GitLab CI Example

```yaml
docker-integration:
  image: docker:latest
  services:
    - docker:dind
  script:
    - cd docker
    - docker compose up --build --abort-on-container-exit test-runner
  after_script:
    - docker compose down
```

## Performance

### Build Times

| Component | First Build | Cached Build |
|-----------|-------------|--------------|
| ntp-server | ~2-3 min | ~10 sec |
| nts-server | ~2-3 min | ~10 sec |
| test-runner | ~3-4 min | ~15 sec |

**Optimization**: Layer caching significantly speeds up rebuilds. Only changed code layers are rebuilt.

### Test Execution

| Test Suite | Duration |
|------------|----------|
| Integration tests | ~5 sec |
| NTS integration tests | ~10 sec |
| Full suite | ~15 sec |

**Note**: Faster than public server tests due to low network latency.

## Cleanup

### Remove containers and networks

```bash
docker compose down
```

### Remove volumes and certificates

```bash
docker compose down -v
rm -rf certs/
```

### Remove images

```bash
docker compose down --rmi all
```

### Full cleanup

```bash
docker compose down -v --rmi all
rm -rf certs/
```

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network                       │
│                  (172.28.0.0/16)                       │
│                                                         │
│  ┌──────────────┐    ┌──────────────┐   ┌───────────┐ │
│  │  ntp-server  │    │  nts-server  │   │   test-   │ │
│  │              │    │              │   │  runner   │ │
│  │   UDP 123    │◄───┤  UDP 123     │◄──┤           │ │
│  │              │    │  TCP 4460    │◄──┤  Tests    │ │
│  └──────┬───────┘    └──────┬───────┘   └───────────┘ │
│         │                   │                           │
│         │            ┌──────▼───────┐                   │
│         │            │   Certs      │                   │
│         │            │  (volume)    │                   │
│         │            └──────────────┘                   │
└─────────┼──────────────────┼─────────────────────────────┘
          │                  │
          │  Host Port       │  Host Port
          │  8123/udp        │  4460/tcp
          ▼                  ▼
    ┌──────────────────────────────┐
    │       Host Machine           │
    └──────────────────────────────┘
```

## Resources

- [Docker Compose Documentation](https://docs.docker.com/compose/)
- [Dockerfile Best Practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
- [Multi-stage Builds](https://docs.docker.com/build/building/multi-stage/)
- [RFC 5905: NTP](https://www.rfc-editor.org/rfc/rfc5905.html)
- [RFC 8915: NTS](https://www.rfc-editor.org/rfc/rfc8915.html)
