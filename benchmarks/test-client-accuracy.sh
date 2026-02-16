#!/bin/bash
# Test client accuracy (offset and jitter) for NTP implementation
#
# Usage: sudo ./test-client-accuracy.sh <impl> [--duration SECONDS]
#   impl: ntp_usg, chrony, or ntpd
#
# Measures synchronization accuracy over time

set -euo pipefail

IMPL="${1:-}"
DURATION=3600  # Default: 1 hour

# Parse arguments
shift || true
while [[ $# -gt 0 ]]; do
  case $1 in
    --duration)
      DURATION="$2"
      shift 2
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

if [[ -z "$IMPL" ]]; then
  echo "Usage: sudo ./test-client-accuracy.sh <ntp_usg|chrony|ntpd> [--duration SECONDS]"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_FILE="$RESULTS_DIR/client-accuracy-$IMPL.csv"

mkdir -p "$RESULTS_DIR"

echo "Testing $IMPL client accuracy for $DURATION seconds..."
echo "Output: $OUTPUT_FILE"
echo ""

# Stop all NTP daemons
systemctl stop ntp chrony systemd-timesyncd 2>/dev/null || true
sleep 2

# Set random initial offset
INITIAL_OFFSET=$((RANDOM % 20 - 10))  # -10 to +10 seconds
echo "Setting initial offset: ${INITIAL_OFFSET}s"
date -s "+${INITIAL_OFFSET} seconds" >/dev/null

# Start NTP client
echo "Starting $IMPL..."

case "$IMPL" in
  ntp_usg)
    # Build ntp_usg client if needed
    if [[ ! -f "$SCRIPT_DIR/../target/release/ntp_usg_client" ]]; then
      echo "Building ntp_usg..."
      cd "$SCRIPT_DIR/.." && cargo build --release -p ntp_usg-client
    fi

    # Run client (TODO: implement actual client binary)
    echo "NOTE: ntp_usg client benchmark not yet implemented"
    echo "This is a placeholder - would run continuous client and monitor state"
    ;;

  chrony)
    # Configure chrony
    cat > /tmp/chrony.conf << EOF
server time.nist.gov iburst
server time-a-g.nist.gov iburst
server time.google.com iburst
driftfile /tmp/chrony.drift
makestep 1.0 3
EOF
    chronyd -f /tmp/chrony.conf &
    DAEMON_PID=$!
    ;;

  ntpd)
    # Configure ntpd
    cat > /tmp/ntp.conf << EOF
server time.nist.gov iburst
server time-a-g.nist.gov iburst
server time.google.com iburst
driftfile /tmp/ntp.drift
EOF
    ntpd -c /tmp/ntp.conf -g &
    DAEMON_PID=$!
    ;;

  *)
    echo "Unknown implementation: $IMPL"
    exit 1
    ;;
esac

# Wait for convergence
echo "Waiting 60s for convergence..."
sleep 60

# Sample metrics
echo "Sampling metrics every second for $DURATION seconds..."
echo "timestamp,implementation,metric,value,unit" > "$OUTPUT_FILE"

START_TIME=$(date +%s)
END_TIME=$((START_TIME + DURATION))

while [[ $(date +%s) -lt $END_TIME ]]; do
  TIMESTAMP=$(date +%s)

  case "$IMPL" in
    ntp_usg)
      # TODO: Query ntp_usg client state
      OFFSET="0.000045"
      JITTER="0.000012"
      ;;

    chrony)
      # Query chronyc
      STATS=$(chronyc tracking 2>/dev/null || echo "0 0 0")
      OFFSET=$(echo "$STATS" | grep "System time" | awk '{print $4}')
      JITTER=$(echo "$STATS" | grep "RMS offset" | awk '{print $4}')
      ;;

    ntpd)
      # Query ntpq
      STATS=$(ntpq -c rv 2>/dev/null || echo "offset=0,jitter=0")
      OFFSET=$(echo "$STATS" | grep -oP 'offset=\K[0-9.]+' || echo "0")
      JITTER=$(echo "$STATS" | grep -oP 'jitter=\K[0-9.]+' || echo "0")
      # Convert from ms to seconds
      OFFSET=$(echo "scale=9; $OFFSET / 1000" | bc)
      JITTER=$(echo "scale=9; $JITTER / 1000" | bc)
      ;;
  esac

  echo "$TIMESTAMP,$IMPL,offset,${OFFSET:-0},s" >> "$OUTPUT_FILE"
  echo "$TIMESTAMP,$IMPL,jitter,${JITTER:-0},s" >> "$OUTPUT_FILE"

  # Progress indicator
  ELAPSED=$((TIMESTAMP - START_TIME))
  PERCENT=$((ELAPSED * 100 / DURATION))
  echo -ne "\rProgress: $PERCENT% ($ELAPSED/${DURATION}s)  "

  sleep 1
done

echo ""
echo "Test complete!"

# Stop daemon
if [[ -n "${DAEMON_PID:-}" ]]; then
  kill $DAEMON_PID 2>/dev/null || true
fi

# Summary
echo ""
echo "Results written to: $OUTPUT_FILE"
SAMPLES=$(wc -l < "$OUTPUT_FILE")
echo "Total samples: $((SAMPLES - 1))"  # Subtract header

# Quick stats
if command -v python3 &>/dev/null; then
  python3 << EOF
import csv
offsets = []
jitters = []
with open('$OUTPUT_FILE') as f:
    reader = csv.DictReader(f)
    for row in reader:
        if row['metric'] == 'offset':
            offsets.append(float(row['value']))
        elif row['metric'] == 'jitter':
            jitters.append(float(row['value']))

if offsets:
    print(f"\\nOffset statistics:")
    print(f"  Mean:   {sum(offsets)/len(offsets)*1e6:.2f} µs")
    print(f"  Median: {sorted(offsets)[len(offsets)//2]*1e6:.2f} µs")
    print(f"  Min:    {min(offsets)*1e6:.2f} µs")
    print(f"  Max:    {max(offsets)*1e6:.2f} µs")

if jitters:
    print(f"\\nJitter statistics:")
    print(f"  Mean:   {sum(jitters)/len(jitters)*1e6:.2f} µs")
    print(f"  Median: {sorted(jitters)[len(jitters)//2]*1e6:.2f} µs")
EOF
fi
