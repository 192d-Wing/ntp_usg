# Stratum 1 NTP Server - Production Deployment Guide

**Version**: 3.3.0
**Last Updated**: 2026-02-16
**Target Audience**: System administrators deploying high-precision NTP infrastructure

---

## Table of Contents

1. [Overview](#overview)
2. [Hardware Requirements](#hardware-requirements)
3. [System Requirements](#system-requirements)
4. [Installation](#installation)
5. [GPS Configuration](#gps-configuration)
6. [PPS Configuration](#pps-configuration)
7. [Server Configuration](#server-configuration)
8. [Testing and Validation](#testing-and-validation)
9. [Production Hardening](#production-hardening)
10. [Monitoring](#monitoring)
11. [Troubleshooting](#troubleshooting)
12. [Performance Tuning](#performance-tuning)

---

## Overview

This guide covers deploying a production Stratum 1 NTP server using `ntp_usg` with hardware reference clocks (GPS, PPS, or both). A properly configured Stratum 1 server can provide sub-microsecond accuracy to downstream clients.

### Architecture Options

| Configuration | Accuracy | Hardware Required | Complexity |
|--------------|----------|-------------------|------------|
| **GPS Only** | 100µs - 1ms | GPS receiver with NMEA output | Low |
| **PPS Only** | < 1µs* | PPS signal source | Low |
| **GPS + PPS** | < 1µs | GPS with PPS output | Medium |
| **Atomic + PPS** | < 100ns | Atomic clock with PPS | High |

*PPS alone requires another time source for initial synchronization.

---

## Hardware Requirements

### Recommended GPS Receivers

#### Budget Option: u-blox NEO-6M/7M/8M
- **Cost**: $10-30
- **Accuracy**: 2.5m CEP (GPS), 100ns PPS (with fix)
- **Interface**: UART (3.3V)
- **Features**: NMEA output, PPS output
- **Best for**: Development, testing, small deployments

#### Mid-Range: u-blox ZED-F9P
- **Cost**: $100-200
- **Accuracy**: 0.01m CEP (RTK), 10ns PPS
- **Interface**: UART, I2C, SPI
- **Features**: Multi-band GNSS, RTK support
- **Best for**: Production deployments

#### Enterprise: Trimble Thunderbolt E
- **Cost**: $200-500 (used market)
- **Accuracy**: < 1ns PPS (disciplined oscillator)
- **Interface**: RS-232
- **Features**: GPS-disciplined OCXO, excellent holdover
- **Best for**: Critical infrastructure, data centers

### Platform Options

#### Raspberry Pi 4/5 (Recommended)
- **Pros**: Low cost, GPIO for PPS, wide support
- **Cons**: Limited to ~1µs accuracy (software timestamps)
- **Best for**: GPS+PPS deployments up to Stratum 1
- **Cost**: $35-75

#### Intel NUC with i210/i350 NIC
- **Pros**: Hardware timestamping, higher performance
- **Cons**: Higher cost, more power
- **Best for**: High-traffic servers, data centers
- **Cost**: $300-600

#### Dedicated Server with PTP-capable NIC
- **Pros**: Maximum performance, hardware timestamps
- **Cons**: Expensive, overkill for most use cases
- **Best for**: Financial services, telecom
- **Cost**: $1000+

---

## System Requirements

### Operating System

**Supported**:
- Ubuntu 22.04 LTS or later
- Debian 11+ (Bullseye)
- RHEL/Rocky/Alma Linux 8+
- Arch Linux (latest)

**Kernel Requirements**:
- Linux kernel 4.19+ (for GPS/basic PPS)
- Linux kernel 5.10+ (recommended for hardware timestamping)
- `CONFIG_PPS=y` (for PPS support)
- `CONFIG_PPS_CLIENT_GPIO=y` (for GPIO PPS on Raspberry Pi)

### Software Dependencies

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libssl-dev

# RHEL/Rocky/Alma
sudo dnf groupinstall "Development Tools"
sudo dnf install openssl-devel

# Arch
sudo pacman -S base-devel openssl
```

### Rust Toolchain

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Verify version (1.70+ required)
rustc --version
```

---

## Installation

### Option 1: Build from Source (Recommended)

```bash
# Clone repository
git clone https://github.com/192d-Wing/ntp_usg.git
cd ntp_usg

# Build with GPS and PPS support
cargo build --release -p ntp_usg-server --features refclock,gps,pps

# Install binary
sudo install -m 755 target/release/ntp_usg_server /usr/local/bin/
```

### Option 2: Install from crates.io

```bash
# Install with all features
cargo install ntp_usg-server --features refclock,gps,pps

# Binary installed to ~/.cargo/bin/ntp_usg-server
```

---

## GPS Configuration

### 1. Connect GPS Receiver

#### Raspberry Pi (UART)

```bash
# Disable console on serial port
sudo raspi-config
# → Interface Options → Serial Port
# → "Would you like a login shell accessible over serial?" → No
# → "Would you like the serial port hardware enabled?" → Yes

# Reboot
sudo reboot

# Verify UART is available
ls -l /dev/ttyAMA0  # Should exist
```

#### USB GPS Receiver

```bash
# Find device (usually /dev/ttyUSB0 or /dev/ttyACM0)
sudo dmesg | grep tty

# Set permissions
sudo usermod -a -G dialout $USER
# Log out and back in for group change to take effect
```

### 2. Test GPS Reception

```bash
# Install test utilities
sudo apt-get install gpsd gpsd-clients

# Test raw NMEA output
sudo cat /dev/ttyAMA0
# Should see: $GPGGA,$GPRMC,$GPZDA sentences

# Or use cgps for interactive display
sudo cgps -s /dev/ttyAMA0

# Look for:
# - Status: 3D FIX
# - Satellites used: 4+
# - HDOP: < 2.0 (lower is better)
```

### 3. GPS Configuration File

Create `/etc/ntp_usg/gps.conf`:

```toml
[gps]
device = "/dev/ttyAMA0"
baud_rate = 9600
min_satellites = 4
min_quality = "Gps"  # Options: NoFix, Gps, DifferentialGps, Pps, Rtk
reference_id = "GPS\0"
poll_interval_secs = 1
```

---

## PPS Configuration

### 1. Enable Kernel PPS Support

#### Raspberry Pi (GPIO)

```bash
# Edit boot config
sudo nano /boot/firmware/config.txt

# Add PPS overlay (GPIO 18 is common, change as needed)
dtoverlay=pps-gpio,gpiopin=18

# Save and reboot
sudo reboot

# Verify PPS device exists
ls -l /dev/pps0

# Load pps_ldisc module (if not auto-loaded)
sudo modprobe pps_ldisc
```

#### x86 System with Serial PPS

```bash
# Enable PPS on serial port
sudo ldattach PPS /dev/ttyS0

# Or add to /etc/rc.local for persistence
echo "ldattach PPS /dev/ttyS0" | sudo tee -a /etc/rc.local
```

### 2. Test PPS Signal

```bash
# Install pps-tools
sudo apt-get install pps-tools

# Monitor PPS events
sudo ppstest /dev/pps0

# Expected output (once per second):
# trying PPS source "/dev/pps0"
# found PPS source "/dev/pps0"
# ok, found 1 source(s), now start fetching data...
# source 0 - assert 1707234567.000000000, sequence: 1234 - clear  0.000000000, sequence: 0
# source 0 - assert 1707234568.000000000, sequence: 1235 - clear  0.000000000, sequence: 0
```

### 3. PPS Configuration File

Create `/etc/ntp_usg/pps.conf`:

```toml
[pps]
device = "/dev/pps0"
capture_mode = "Assert"  # Options: Assert, Clear, Both
reference_id = "PPS\0"
timeout_secs = 2
dispersion = 0.000001  # 1 microsecond
```

---

## Server Configuration

### Basic Stratum 1 Server (GPS Only)

Create `/usr/local/bin/ntp_server.sh`:

```bash
#!/bin/bash

/usr/local/bin/ntp_usg_server \
  --listen "0.0.0.0:123" \
  --gps-device "/dev/ttyAMA0" \
  --gps-baud 9600 \
  --stratum 1 \
  --enable-interleaved \
  --max-clients 10000
```

### Advanced Configuration (GPS + PPS)

Create `/etc/ntp_usg/server.toml`:

```toml
[server]
listen_addr = "0.0.0.0:123"
enable_interleaved = true
max_clients = 100000

[refclock]
type = "gps_pps"  # Use both GPS and PPS
gps_device = "/dev/ttyAMA0"
gps_baud = 9600
pps_device = "/dev/pps0"

# Rate limiting (RFC 8633)
[rate_limit]
enabled = true
packets_per_second = 100
burst_size = 200

# Access control
[access]
allow = [
  "10.0.0.0/8",      # Private networks
  "172.16.0.0/12",
  "192.168.0.0/16"
]
deny = []
```

### Systemd Service

Create `/etc/systemd/system/ntp-server.service`:

```ini
[Unit]
Description=ntp_usg Stratum 1 NTP Server
After=network.target gpsd.service
Wants=gpsd.service

[Service]
Type=simple
User=ntp
Group=ntp
ExecStart=/usr/local/bin/ntp_usg_server
Restart=always
RestartSec=5

# Capabilities instead of running as root
AmbientCapabilities=CAP_SYS_TIME CAP_NET_BIND_SERVICE
NoNewPrivileges=true

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/ntp
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ntp-server

[Install]
WantedBy=multi-user.target
```

### Create NTP User

```bash
# Create dedicated user
sudo useradd -r -s /bin/false -d /var/lib/ntp ntp

# Create data directory
sudo mkdir -p /var/lib/ntp
sudo chown ntp:ntp /var/lib/ntp

# Grant device permissions
sudo usermod -a -G dialout,gpio ntp  # Raspberry Pi
sudo usermod -a -G dialout ntp       # x86 with USB GPS
```

### Enable and Start Service

```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service
sudo systemctl enable ntp-server

# Start service
sudo systemctl start ntp-server

# Check status
sudo systemctl status ntp-server

# View logs
sudo journalctl -u ntp-server -f
```

---

## Testing and Validation

### 1. Verify Server is Running

```bash
# Check listening port
sudo ss -ulnp | grep :123

# Expected output:
# UNCONN 0 0 0.0.0.0:123 0.0.0.0:* users:(("ntp_usg_server",pid=1234,fd=5))
```

### 2. Test from Localhost

```bash
# Install NTP client tools
sudo apt-get install ntp ntpdate

# Query server
ntpdate -q localhost

# Expected output:
# server 127.0.0.1, stratum 1, offset -0.000123, delay 0.00012
# 16 Feb 12:34:56 ntpdate[1234]: adjust time server 127.0.0.1 offset -0.000123 sec
```

### 3. Check Stratum and Reference ID

```bash
# Install ntpq
sudo apt-get install ntp

# Query server details
ntpq -p localhost

# Expected output:
#      remote           refid      st t when poll reach   delay   offset  jitter
# ==============================================================================
# *GPS_NMEA(0)     .GPS.            0 l    1   16  377    0.000    0.000   0.001
```

### 4. Verify Reference Clock Health

```bash
# Check logs for GPS fix
sudo journalctl -u ntp-server | grep GPS

# Look for:
# GPS fix acquired! Offset: 0.000123s, Satellites: 8, Quality: GPS

# Check for PPS pulses
sudo journalctl -u ntp-server | grep PPS

# Look for:
# PPS pulse detected! Offset: 0.000000123s
```

### 5. Monitor Accuracy

```bash
# Create monitoring script
cat > /usr/local/bin/ntp-monitor.sh << 'EOF'
#!/bin/bash
while true; do
  echo "=== $(date) ==="
  ntpdate -q localhost | grep offset
  echo ""
  sleep 10
done
EOF

chmod +x /usr/local/bin/ntp-monitor.sh

# Run monitoring
/usr/local/bin/ntp-monitor.sh
```

---

## Production Hardening

### 1. Firewall Configuration

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 123/udp comment "NTP server"

# iptables
sudo iptables -A INPUT -p udp --dport 123 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4

# firewalld (RHEL/Rocky)
sudo firewall-cmd --permanent --add-service=ntp
sudo firewall-cmd --reload
```

### 2. Rate Limiting (Application Level)

Already configured in `server.toml`. Additional kernel-level protection:

```bash
# Limit NTP packets per IP (iptables)
sudo iptables -A INPUT -p udp --dport 123 -m state --state NEW \
  -m recent --set --name NTP

sudo iptables -A INPUT -p udp --dport 123 -m state --state NEW \
  -m recent --update --seconds 1 --hitcount 100 --name NTP -j DROP
```

### 3. System Tuning

```bash
# Increase UDP buffer sizes
sudo sysctl -w net.core.rmem_max=26214400
sudo sysctl -w net.core.wmem_max=26214400
sudo sysctl -w net.core.rmem_default=26214400
sudo sysctl -w net.core.wmem_default=26214400

# Make persistent
cat | sudo tee -a /etc/sysctl.d/99-ntp.conf << EOF
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
net.core.rmem_default = 26214400
net.core.wmem_default = 26214400
EOF
```

### 4. Time Zone and Clock Settings

```bash
# Set timezone to UTC (recommended for NTP servers)
sudo timedatectl set-timezone UTC

# Disable systemd-timesyncd (conflicts with NTP server)
sudo systemctl stop systemd-timesyncd
sudo systemctl disable systemd-timesyncd
sudo systemctl mask systemd-timesyncd

# Verify no other NTP daemons running
sudo systemctl list-units | grep -E 'ntp|chrony'
```

### 5. Secure Boot Configuration

```bash
# Raspberry Pi: Prevent system clock drift on boot
echo "dtparam=act_led_trigger=default-on" | sudo tee -a /boot/firmware/config.txt

# Save hardware clock before shutdown
cat | sudo tee /etc/systemd/system/save-hwclock.service << EOF
[Unit]
Description=Save system time to hardware clock
DefaultDependencies=no
Before=shutdown.target

[Service]
Type=oneshot
ExecStart=/sbin/hwclock --systohc

[Install]
WantedBy=shutdown.target
EOF

sudo systemctl enable save-hwclock
```

---

## Monitoring

### 1. Prometheus Metrics

Install web dashboard for Prometheus-compatible metrics:

```bash
# Build with dashboard support
cargo build --release -p ntp_usg-server \
  --features refclock,gps,pps,web-dashboard

# Metrics available at http://localhost:8080/metrics
```

Scrape configuration (`prometheus.yml`):

```yaml
scrape_configs:
  - job_name: 'ntp_server'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 10s
```

### 2. Grafana Dashboard

Import dashboard template from `docs/grafana-dashboard.json` (to be created).

Key metrics to monitor:
- **Clock Offset**: Should be < 1µs for GPS+PPS
- **Jitter**: Should be < 100µs
- **Satellites Tracked**: Should be 4+ (GPS)
- **PPS Pulse Rate**: Should be 1 Hz
- **Client Query Rate**: Monitor for DoS
- **Reference Clock Health**: GPS fix status, PPS signal presence

### 3. Email Alerts

```bash
# Install monitoring script
cat > /usr/local/bin/ntp-health-check.sh << 'EOF'
#!/bin/bash
OFFSET=$(ntpdate -q localhost 2>&1 | grep offset | awk '{print $6}')
THRESHOLD=0.001  # 1ms

if (( $(echo "$OFFSET > $THRESHOLD" | bc -l) )); then
  echo "NTP offset $OFFSET exceeds threshold $THRESHOLD" | \
    mail -s "NTP Server Alert" admin@example.com
fi
EOF

chmod +x /usr/local/bin/ntp-health-check.sh

# Add to cron (every 5 minutes)
echo "*/5 * * * * /usr/local/bin/ntp-health-check.sh" | sudo crontab -
```

### 4. Logging Best Practices

```bash
# Increase log retention
sudo mkdir -p /var/log/ntp
sudo chown ntp:ntp /var/log/ntp

# Configure journald persistence
sudo mkdir -p /var/log/journal
sudo systemctl restart systemd-journald

# Adjust log levels in server config
export RUST_LOG=info,ntp_server=debug
```

---

## Troubleshooting

### GPS Not Working

**Problem**: No GPS fix, no NMEA sentences

**Solutions**:

```bash
# 1. Check antenna connection
# GPS receivers need clear sky view - indoor won't work

# 2. Verify device permissions
sudo chmod 666 /dev/ttyAMA0
sudo cat /dev/ttyAMA0
# Should see NMEA sentences like $GPGGA,...

# 3. Check baud rate
# Try different rates: 4800, 9600, 115200
sudo stty -F /dev/ttyAMA0 9600

# 4. Test with gpsd
sudo gpsd -D 5 -N -n /dev/ttyAMA0
# Look for "GPS fix" messages

# 5. Check for UART conflicts (Raspberry Pi)
sudo raspi-config
# Ensure Bluetooth is disabled if using GPIO UART
```

### PPS Not Working

**Problem**: `/dev/pps0` doesn't exist

**Solutions**:

```bash
# 1. Check kernel module
lsmod | grep pps
# Should see: pps_gpio, pps_core

# If missing:
sudo modprobe pps-gpio
sudo modprobe pps-ldisc

# 2. Verify GPIO connection (Raspberry Pi)
# PPS signal should be on GPIO 18 (or configured pin)
# Use oscilloscope or logic analyzer to verify 1Hz pulse

# 3. Check device tree overlay
dtoverlay -l
# Should see pps-gpio

# 4. Manual device creation (last resort)
sudo mknod /dev/pps0 c 248 0

# 5. Check dmesg for errors
dmesg | grep pps
```

### High Offset/Jitter

**Problem**: Offset > 1ms, jitter > 100µs

**Solutions**:

```bash
# 1. Check GPS fix quality
cgps -s /dev/ttyAMA0
# Ensure: Status=3D FIX, Satellites≥4, HDOP<2

# 2. Verify PPS signal quality
sudo ppstest /dev/pps0
# Pulses should be exactly 1 second apart

# 3. Check system load
top
# High CPU usage can affect timing

# 4. Disable power management (Raspberry Pi)
echo "performance" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# 5. Check for NTP loops (server querying itself)
ntpq -p localhost
# Should only show local GPS/PPS, not other servers
```

### Permission Denied Errors

**Problem**: Server can't access devices

**Solutions**:

```bash
# 1. Add user to correct groups
sudo usermod -a -G dialout,gpio,tty ntp

# 2. Set udev rules
cat | sudo tee /etc/udev/rules.d/99-ntp.rules << EOF
KERNEL=="ttyAMA0", GROUP="dialout", MODE="0660"
KERNEL=="pps0", GROUP="gpio", MODE="0660"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger

# 3. Verify capabilities
sudo getcap /usr/local/bin/ntp_usg_server
# Should see: cap_net_bind_service,cap_sys_time+eip

# If missing:
sudo setcap 'cap_net_bind_service,cap_sys_time=+eip' \
  /usr/local/bin/ntp_usg_server
```

### Service Won't Start

**Problem**: systemd service fails

**Solutions**:

```bash
# 1. Check service status
sudo systemctl status ntp-server -l

# 2. View full logs
sudo journalctl -u ntp-server -xe

# 3. Test binary manually
sudo -u ntp /usr/local/bin/ntp_usg_server --help

# 4. Check configuration files
sudo -u ntp cat /etc/ntp_usg/server.toml

# 5. Verify dependencies
systemctl list-dependencies ntp-server
```

---

## Performance Tuning

### 1. CPU Affinity

```bash
# Pin server to specific CPU cores (reduce jitter)
sudo systemctl edit ntp-server

# Add:
[Service]
CPUAffinity=0 1
```

### 2. Real-Time Priority

```bash
# Enable real-time scheduling
sudo systemctl edit ntp-server

# Add:
[Service]
CPUSchedulingPolicy=fifo
CPUSchedulingPriority=50
```

### 3. Disable CPU Frequency Scaling

```bash
# Set performance governor
for cpu in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  echo "performance" | sudo tee $cpu
done

# Make persistent
sudo apt-get install cpufrequtils
echo 'GOVERNOR="performance"' | sudo tee /etc/default/cpufrequtils
sudo systemctl restart cpufrequtils
```

### 4. Hardware Timestamping (Intel NICs)

```bash
# Check NIC support
sudo ethtool -T eth0

# Enable in server config
[server]
enable_hardware_timestamps = true
timestamp_interface = "eth0"
```

### 5. Kernel Parameters

```bash
# Add to /etc/sysctl.d/99-ntp-tuning.conf
cat | sudo tee /etc/sysctl.d/99-ntp-tuning.conf << EOF
# Reduce timer tick for better precision
kernel.timer_migration = 0

# Increase max UDP queue
net.core.netdev_max_backlog = 5000

# Reduce scheduling latency
kernel.sched_latency_ns = 1000000
kernel.sched_min_granularity_ns = 100000

# Disable swap
vm.swappiness = 0
EOF

sudo sysctl -p /etc/sysctl.d/99-ntp-tuning.conf
```

---

## Deployment Checklist

Before going live:

- [ ] GPS receiver has clear sky view
- [ ] GPS shows 3D fix with 4+ satellites
- [ ] PPS signal verified with `ppstest`
- [ ] `/dev/ttyAMA0` and `/dev/pps0` accessible by `ntp` user
- [ ] Server starts successfully: `sudo systemctl status ntp-server`
- [ ] Firewall allows UDP port 123
- [ ] ntpdate test shows Stratum 1: `ntpdate -q localhost`
- [ ] Offset < 1ms: Check with `ntpq -p localhost`
- [ ] Monitoring configured (Prometheus/Grafana)
- [ ] Email alerts configured
- [ ] Log rotation configured
- [ ] Backup power for GPS (if critical)
- [ ] Documentation updated with local details

---

## Production Examples

### Example 1: Raspberry Pi 4 + NEO-6M GPS

**Hardware**:
- Raspberry Pi 4 (4GB RAM)
- u-blox NEO-6M GPS module
- Active GPS antenna
- GPIO connections: TX→GPIO15, RX→GPIO14, PPS→GPIO18

**Performance**:
- Offset: 50-200µs (typical)
- Jitter: 10-50µs
- Serves: 1000 clients @ 1 poll/min

**Cost**: ~$75 total

### Example 2: Intel NUC + Trimble Thunderbolt

**Hardware**:
- Intel NUC with i210 NIC
- Trimble Thunderbolt E (GPS + OCXO)
- RS-232 adapter for GPS
- PPS via serial DCD pin

**Performance**:
- Offset: 1-10µs (typical)
- Jitter: < 1µs
- Serves: 10,000 clients @ 1 poll/min
- Hardware timestamping: 100ns precision

**Cost**: ~$600 total

### Example 3: Data Center Deployment

**Hardware**:
- Dell PowerEdge R340
- Intel X550-T2 NIC (hardware timestamping)
- External GPS antenna on roof
- Rubidium frequency standard (optional)

**Performance**:
- Offset: < 100ns (with hardware timestamps)
- Jitter: < 10ns
- Serves: 100,000+ clients

**Cost**: $3000+ (without Rubidium)

---

## Additional Resources

- [RFC 5905 - Network Time Protocol Version 4](https://www.rfc-editor.org/rfc/rfc5905.html)
- [ntp_usg GitHub](https://github.com/192d-Wing/ntp_usg)
- [Linux PPS Documentation](https://www.kernel.org/doc/html/latest/driver-api/pps.html)
- [NMEA 0183 Specification](https://www.nmea.org/)
- [GPS Time Accuracy Guide](https://gpsd.gitlab.io/gpsd/time-service-intro.html)

---

## Support

For issues and questions:
- GitHub Issues: https://github.com/192d-Wing/ntp_usg/issues
- Documentation: https://docs.rs/ntp_usg-server/

---

**Document Version**: 1.0
**Covers ntp_usg**: v3.3.0+
**License**: Apache 2.0
