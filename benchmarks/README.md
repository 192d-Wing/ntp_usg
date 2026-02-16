# NTP Performance Benchmarks

This directory contains scripts and tools for benchmarking ntp_usg against chrony and ntpd.

## Quick Start

```bash
# Install dependencies
./setup.sh

# Run all benchmarks (requires root and ~3 hours)
sudo ./run-all.sh

# Generate markdown report
./generate-report.sh > ../docs/BENCHMARK-RESULTS.md
```

## Individual Tests

### Client Accuracy Test

Measures synchronization accuracy (offset and jitter):

```bash
sudo ./test-client-accuracy.sh ntp_usg
sudo ./test-client-accuracy.sh chrony
sudo ./test-client-accuracy.sh ntpd
```

**Duration**: 1 hour per implementation
**Output**: `results/client-accuracy-{impl}.csv`

### Server Throughput Test

Measures maximum queries per second:

```bash
# On server machine
sudo ./start-server.sh ntp_usg

# On client machine(s)
./load-test.sh <server-ip>
```

**Duration**: 30 minutes per implementation
**Output**: `results/server-throughput-{impl}.csv`

### Stratum 1 Accuracy Test

Measures GPS+PPS reference clock accuracy (requires hardware):

```bash
sudo ./test-stratum1.sh ntp_usg
sudo ./test-stratum1.sh chrony
sudo ./test-stratum1.sh ntpd
```

**Duration**: 24 hours per implementation
**Output**: `results/stratum1-{impl}.csv`

### Resource Usage Test

Measures memory and CPU under load:

```bash
sudo ./test-resources.sh ntp_usg
```

**Duration**: 1 hour
**Output**: `results/resources-{impl}.csv`

## Data Analysis

```bash
# Generate summary statistics
python3 analyze.py results/client-accuracy-*.csv

# Create plots
python3 plot.py results/throughput-*.csv \
  --output plots/throughput-comparison.png

# Full report
./generate-report.sh
```

## Requirements

### Software

- Linux (kernel 4.19+ for PPS)
- Python 3.8+ with pandas, matplotlib, numpy
- ntp_usg (built from source)
- chrony 4.x (`apt install chrony`)
- ntpd 4.2.8+ (`apt install ntp`)
- ntpdate, ntpq tools
- Root access (for binding port 123)

### Hardware (for Stratum 1 tests)

- GPS receiver with NMEA output (e.g., u-blox NEO-M8N)
- PPS signal source (GPS PPS output or equivalent)
- GPIO or serial port for PPS
- Clear sky view for GPS antenna

## Output Format

All CSV files use the same format:

```csv
timestamp,implementation,metric,value,unit
1707234567,ntp_usg,offset,45.2,us
1707234567,chrony,offset,38.1,us
1707234567,ntpd,offset,52.7,us
```

## Scripts

| Script | Purpose | Duration |
|--------|---------|----------|
| `setup.sh` | Install dependencies | 5 min |
| `run-all.sh` | Run all benchmarks | 3-27 hours* |
| `test-client-accuracy.sh` | Client accuracy test | 1 hour |
| `test-server-throughput.sh` | Server QPS test | 30 min |
| `test-stratum1.sh` | GPS+PPS accuracy | 24 hours |
| `test-resources.sh` | Memory/CPU usage | 1 hour |
| `load-test.sh` | Generate NTP load | Variable |
| `start-server.sh` | Start NTP server | N/A |
| `analyze.py` | Statistical analysis | 1 min |
| `plot.py` | Create visualizations | 1 min |
| `generate-report.sh` | Generate markdown | 1 min |

*Without Stratum 1 tests: ~3 hours
*With Stratum 1 tests: ~27 hours (24h + 3h)

## Customization

Edit benchmark parameters in `config.sh`:

```bash
# Client accuracy test
CLIENT_DURATION=3600          # 1 hour
CLIENT_SERVERS="time.nist.gov time.google.com"

# Server throughput test
THROUGHPUT_CLIENTS=10         # Parallel clients
THROUGHPUT_DURATION=1800      # 30 minutes

# Stratum 1 test
STRATUM1_DURATION=86400       # 24 hours
GPS_DEVICE="/dev/ttyAMA0"
PPS_DEVICE="/dev/pps0"

# Resource test
RESOURCE_SAMPLES=3600         # 1 hour of samples
RESOURCE_INTERVAL=1           # Sample every 1s
```

## Troubleshooting

### "Permission denied" on /dev/pps0

```bash
sudo usermod -a -G gpio $USER
# Log out and back in
```

### chrony won't start

```bash
sudo systemctl stop systemd-timesyncd
sudo systemctl disable systemd-timesyncd
```

### Load test shows high packet loss

```bash
# Increase UDP buffer sizes
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
```

### GPS not getting fix

```bash
# Check GPS reception
cgps -s /dev/ttyAMA0

# Ensure clear sky view - GPS won't work indoors
```

## Contributing

Improvements welcome! Areas to enhance:

1. **More implementations** - Add OpenNTPD, systemd-timesyncd
2. **More platforms** - Test on ARM, RISC-V, BSD
3. **Better load generation** - More realistic traffic patterns
4. **Statistical rigor** - Confidence intervals, significance tests
5. **Automation** - CI/CD integration

Submit PRs to: https://github.com/192d-Wing/ntp_usg

## License

Benchmark scripts: MIT License
Data and results: CC BY 4.0
