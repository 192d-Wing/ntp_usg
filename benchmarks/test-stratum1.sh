#!/bin/bash
# Test Stratum 1 accuracy (GPS+PPS) for NTP implementation
#
# Usage: sudo ./test-stratum1.sh <impl>
#   impl: ntp_usg, chrony, or ntpd
#
# Requires: GPS on /dev/ttyAMA0, PPS on /dev/pps0
# Duration: 24 hours

set -euo pipefail

IMPL="${1:-}"
DURATION=86400  # 24 hours

if [[ -z "$IMPL" ]]; then
  echo "Usage: sudo ./test-stratum1.sh <ntp_usg|chrony|ntpd>"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_FILE="$RESULTS_DIR/stratum1-$IMPL.csv"
GPS_DEVICE="/dev/ttyAMA0"
PPS_DEVICE="/dev/pps0"

mkdir -p "$RESULTS_DIR"

echo "Testing $IMPL Stratum 1 accuracy for 24 hours..."
echo "GPS: $GPS_DEVICE"
echo "PPS: $PPS_DEVICE"
echo "Output: $OUTPUT_FILE"
echo ""

# Check hardware
if [[ ! -e "$GPS_DEVICE" ]]; then
  echo "Error: GPS device not found: $GPS_DEVICE"
  exit 1
fi

if [[ ! -e "$PPS_DEVICE" ]]; then
  echo "Error: PPS device not found: $PPS_DEVICE"
  exit 1
fi

# Stop all NTP daemons
systemctl stop ntp chrony systemd-timesyncd 2>/dev/null || true
sleep 2

# Test PPS signal
echo "Testing PPS signal..."
if ! timeout 5 ppstest "$PPS_DEVICE" | grep -q "assert"; then
  echo "Error: No PPS signal detected"
  exit 1
fi
echo "✓ PPS signal detected"
echo ""

# Test GPS
echo "Testing GPS reception..."
if ! timeout 10 cat "$GPS_DEVICE" | grep -q '$GP'; then
  echo "Error: No GPS data received"
  exit 1
fi
echo "✓ GPS data received"
echo ""

# Configure and start server
echo "Starting $IMPL with GPS+PPS..."

case "$IMPL" in
  ntp_usg)
    # Build if needed
    if [[ ! -f "$SCRIPT_DIR/../target/release/examples/stratum1_server" ]]; then
      echo "Building ntp_usg stratum1_server..."
      cd "$SCRIPT_DIR/.." && cargo build --release -p ntp_usg-server \
        --example stratum1_server --features refclock,gps,pps
    fi

    # Note: This example uses LocalClock, not actual GPS
    # For real GPS+PPS, would need to modify or create new example
    echo "WARNING: ntp_usg stratum1_server example uses LocalClock"
    echo "Actual GPS+PPS integration pending"
    echo "Skipping ntp_usg test (not yet implemented with real GPS)"
    exit 0
    ;;

  chrony)
    cat > /tmp/chrony-stratum1.conf << EOF
refclock PPS $PPS_DEVICE refid PPS precision 1e-7
refclock SHM 0 refid GPS precision 1e-1 offset 0.0 delay 0.2
driftfile /tmp/chrony-stratum1.drift
makestep 1.0 3
logdir /tmp
log measurements statistics tracking
EOF

    # Start gpsd to feed SHM
    gpsd -n -b "$GPS_DEVICE"
    sleep 2

    chronyd -f /tmp/chrony-stratum1.conf &
    SERVER_PID=$!
    ;;

  ntpd)
    cat > /tmp/ntp-stratum1.conf << EOF
# PPS reference clock (prefer this)
server 127.127.28.0 minpoll 4 maxpoll 4 prefer
fudge 127.127.28.0 refid PPS flag3 1

# GPS reference clock
server 127.127.20.0 minpoll 4 maxpoll 4
fudge 127.127.20.0 refid GPS

driftfile /tmp/ntp-stratum1.drift
EOF

    # Start gpsd
    gpsd -n -b "$GPS_DEVICE"
    sleep 2

    ntpd -c /tmp/ntp-stratum1.conf -g &
    SERVER_PID=$!
    ;;

  *)
    echo "Unknown implementation: $IMPL"
    exit 1
    ;;
esac

# Wait for initialization
echo "Waiting for GPS fix and PPS sync (60s)..."
sleep 60

# Prepare output file
echo "timestamp,implementation,pps_offset_us,gps_offset_us,satellites,stratum" > "$OUTPUT_FILE"

echo "Starting 24-hour measurement..."
echo ""

START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))
SAMPLE_COUNT=0

while [[ $(date +%s) -lt $END_TIME ]]; do
  TIMESTAMP=$(date +%s)
  SAMPLE_COUNT=$((SAMPLE_COUNT + 1))

  # Get PPS timestamp
  if PPS_DATA=$(timeout 2 ppstest "$PPS_DEVICE" 2>/dev/null | head -5 | tail -1); then
    # Extract PPS offset (simplified - would need real parsing)
    PPS_OFFSET=$(echo "$PPS_DATA" | grep -oP 'assert \K[0-9.]+' || echo "0")
    PPS_OFFSET_US=$(echo "scale=3; $PPS_OFFSET * 1000000" | bc)
  else
    PPS_OFFSET_US="999999"
  fi

  # Get GPS data and server stats
  case "$IMPL" in
    chrony)
      TRACKING=$(chronyc tracking 2>/dev/null || echo "")
      GPS_OFFSET=$(echo "$TRACKING" | grep "System time" | awk '{print $4}')
      GPS_OFFSET_US=$(echo "scale=3; ${GPS_OFFSET:-0} * 1000000" | bc)
      STRATUM=$(echo "$TRACKING" | grep "Stratum" | awk '{print $3}')

      # Get satellite count from gpsd
      SAT_COUNT=$(timeout 2 cgps -s 2>/dev/null | grep "Satellites" | awk '{print $2}' || echo "0")
      ;;

    ntpd)
      RV=$(ntpq -c rv 2>/dev/null || echo "stratum=16")
      STRATUM=$(echo "$RV" | grep -oP 'stratum=\K[0-9]+' || echo "16")
      OFFSET=$(echo "$RV" | grep -oP 'offset=\K[-0-9.]+' || echo "0")
      GPS_OFFSET_US=$(echo "scale=3; $OFFSET" | bc)  # ntpq reports in ms
      SAT_COUNT=$(timeout 2 cgps -s 2>/dev/null | grep "Satellites" | awk '{print $2}' || echo "0")
      ;;

    *)
      GPS_OFFSET_US="0"
      SAT_COUNT="0"
      STRATUM="16"
      ;;
  esac

  echo "$TIMESTAMP,$IMPL,${PPS_OFFSET_US:-0},${GPS_OFFSET_US:-0},${SAT_COUNT:-0},${STRATUM:-16}" >> "$OUTPUT_FILE"

  # Progress (every 100 samples = ~1.7 minutes)
  if [[ $((SAMPLE_COUNT % 100)) -eq 0 ]]; then
    ELAPSED=$((TIMESTAMP - START_TIME))
    HOURS=$((ELAPSED / 3600))
    MINUTES=$(((ELAPSED % 3600) / 60))
    PERCENT=$((ELAPSED * 100 / DURATION))

    echo "[$(date +%H:%M:%S)] Progress: ${PERCENT}% (${HOURS}h ${MINUTES}m) - Samples: $SAMPLE_COUNT - Stratum: ${STRATUM:-?}"
  fi

  sleep 1
done

echo ""
echo "24-hour test complete!"

# Stop server and gpsd
kill $SERVER_PID 2>/dev/null || true
killall gpsd 2>/dev/null || true

# Summary
echo ""
echo "Results written to: $OUTPUT_FILE"
echo "Total samples: $SAMPLE_COUNT"

# Statistics
if command -v python3 &>/dev/null; then
  python3 << EOF
import csv

pps_offsets = []
gps_offsets = []
strata = []

with open('$OUTPUT_FILE') as f:
    reader = csv.DictReader(f)
    for row in reader:
        try:
            pps = float(row['pps_offset_us'])
            gps = float(row['gps_offset_us'])
            if pps < 100000:  # Valid data
                pps_offsets.append(pps)
            if abs(gps) < 100000:
                gps_offsets.append(gps)
            strata.append(int(row['stratum']))
        except:
            pass

if pps_offsets:
    print("\\nPPS Offset Statistics:")
    print(f"  Mean:   {sum(pps_offsets)/len(pps_offsets):.2f} µs")
    print(f"  Median: {sorted(pps_offsets)[len(pps_offsets)//2]:.2f} µs")
    print(f"  Min:    {min(pps_offsets):.2f} µs")
    print(f"  Max:    {max(pps_offsets):.2f} µs")
    print(f"  Stdev:  {(sum((x-sum(pps_offsets)/len(pps_offsets))**2 for x in pps_offsets)/len(pps_offsets))**0.5:.2f} µs")

if gps_offsets:
    print("\\nGPS Offset Statistics:")
    print(f"  Mean:   {sum(gps_offsets)/len(gps_offsets):.2f} µs")
    print(f"  Median: {sorted(gps_offsets)[len(gps_offsets)//2]:.2f} µs")

if strata:
    final_stratum = strata[-1]
    print(f"\\nFinal Stratum: {final_stratum}")
    if final_stratum == 1:
        print("  ✓ Achieved Stratum 1 status")
    else:
        print(f"  ✗ Did not achieve Stratum 1 (stuck at {final_stratum})")
EOF
fi
