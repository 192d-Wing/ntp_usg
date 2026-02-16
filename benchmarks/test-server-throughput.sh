#!/bin/bash
# Test server throughput (max QPS) for NTP implementation
#
# Usage: sudo ./test-server-throughput.sh <impl> [--duration SECONDS]
#   impl: ntp_usg, chrony, or ntpd
#
# Measures maximum queries per second the server can handle

set -euo pipefail

IMPL="${1:-}"
DURATION=1800  # Default: 30 minutes

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
  echo "Usage: sudo ./test-server-throughput.sh <ntp_usg|chrony|ntpd> [--duration SECONDS]"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_FILE="$RESULTS_DIR/server-throughput-$IMPL.csv"

mkdir -p "$RESULTS_DIR"

echo "Testing $IMPL server throughput for $DURATION seconds..."
echo "Output: $OUTPUT_FILE"
echo ""

# Stop all NTP daemons
systemctl stop ntp chrony systemd-timesyncd 2>/dev/null || true
sleep 2

# Start NTP server
echo "Starting $IMPL server..."

case "$IMPL" in
  ntp_usg)
    # Build if needed
    if [[ ! -f "$SCRIPT_DIR/../target/release/examples/server" ]]; then
      echo "Building ntp_usg server..."
      cd "$SCRIPT_DIR/.." && cargo build --release -p ntp_usg-server --example server --features tokio
    fi

    # Start server in background
    "$SCRIPT_DIR/../target/release/examples/server" &
    SERVER_PID=$!
    SERVER_PORT=123
    ;;

  chrony)
    # Configure chronyd as server
    cat > /tmp/chrony-server.conf << EOF
server time.google.com iburst
driftfile /tmp/chrony-server.drift
allow all
port 123
EOF
    chronyd -f /tmp/chrony-server.conf &
    SERVER_PID=$!
    SERVER_PORT=123
    ;;

  ntpd)
    # Configure ntpd as server
    cat > /tmp/ntp-server.conf << EOF
server time.google.com iburst
driftfile /tmp/ntp-server.drift
restrict default nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1
EOF
    ntpd -c /tmp/ntp-server.conf -g &
    SERVER_PID=$!
    SERVER_PORT=123
    ;;

  *)
    echo "Unknown implementation: $IMPL"
    exit 1
    ;;
esac

# Wait for server to start
echo "Waiting for server to initialize..."
sleep 5

# Test connectivity
if ! ntpdate -q 127.0.0.1 >/dev/null 2>&1; then
  echo "Error: Server not responding"
  kill $SERVER_PID 2>/dev/null || true
  exit 1
fi

echo "✓ Server responding"
echo ""

# Prepare output file
echo "timestamp,implementation,load_level,qps,response_time_ms,cpu_percent,memory_mb,packet_loss_percent" > "$OUTPUT_FILE"

# Test at different load levels
LOAD_LEVELS=(100 500 1000 5000 10000 20000 50000 100000)

for LOAD in "${LOAD_LEVELS[@]}"; do
  echo "[$(date +%H:%M:%S)] Testing at $LOAD QPS..."

  # Start load generators in background
  PIDS=()
  QUERIES_PER_CLIENT=$((LOAD / 10))  # 10 parallel clients

  for i in {1..10}; do
    (
      COUNT=0
      INTERVAL=$(echo "scale=6; 1.0 / $QUERIES_PER_CLIENT" | bc)
      while [[ $COUNT -lt $((DURATION / 10)) ]]; do
        ntpdate -q 127.0.0.1 >/dev/null 2>&1 || true
        COUNT=$((COUNT + 1))
        sleep "$INTERVAL" 2>/dev/null || sleep 0.01
      done
    ) &
    PIDS+=($!)
  done

  # Monitor for 10 seconds at this load
  for SEC in {1..10}; do
    TIMESTAMP=$(date +%s)

    # Measure response time (average of 10 queries)
    TOTAL_TIME=0
    SUCCESS=0
    for _ in {1..10}; do
      START=$(date +%s%N)
      if ntpdate -q 127.0.0.1 >/dev/null 2>&1; then
        END=$(date +%s%N)
        ELAPSED=$((END - START))
        TOTAL_TIME=$((TOTAL_TIME + ELAPSED))
        SUCCESS=$((SUCCESS + 1))
      fi
    done

    if [[ $SUCCESS -gt 0 ]]; then
      AVG_TIME=$(echo "scale=3; $TOTAL_TIME / $SUCCESS / 1000000" | bc)  # Convert to ms
    else
      AVG_TIME=999.999
    fi

    PACKET_LOSS=$(echo "scale=2; (10 - $SUCCESS) * 10" | bc)

    # Measure CPU and memory
    if [[ -e /proc/$SERVER_PID/stat ]]; then
      CPU=$(ps -p $SERVER_PID -o %cpu | tail -1)
      MEM=$(ps -p $SERVER_PID -o rss | tail -1)
      MEM_MB=$(echo "scale=1; $MEM / 1024" | bc)
    else
      CPU=0
      MEM_MB=0
    fi

    echo "$TIMESTAMP,$IMPL,$LOAD,$LOAD,$AVG_TIME,$CPU,$MEM_MB,$PACKET_LOSS" >> "$OUTPUT_FILE"

    sleep 1
  done

  # Stop load generators
  for PID in "${PIDS[@]}"; do
    kill $PID 2>/dev/null || true
  done
  wait

  # Check if server is overloaded
  if (( $(echo "$PACKET_LOSS > 5.0" | bc -l) )); then
    echo "  Packet loss > 5% at $LOAD QPS. Server limit reached."
    break
  fi

  # Small cooldown
  sleep 2
done

echo ""
echo "Test complete!"

# Stop server
kill $SERVER_PID 2>/dev/null || true

# Summary
echo ""
echo "Results written to: $OUTPUT_FILE"
SAMPLES=$(wc -l < "$OUTPUT_FILE")
echo "Total samples: $((SAMPLES - 1))"

# Quick stats
if command -v python3 &>/dev/null; then
  python3 << EOF
import csv

data = []
with open('$OUTPUT_FILE') as f:
    reader = csv.DictReader(f)
    for row in reader:
        data.append(row)

if data:
    max_qps = 0
    max_qps_row = None

    for row in data:
        qps = int(row['qps'])
        loss = float(row['packet_loss_percent'])
        if loss < 1.0 and qps > max_qps:
            max_qps = qps
            max_qps_row = row

    if max_qps_row:
        print(f"\\nMaximum stable throughput:")
        print(f"  QPS:           {max_qps:,}")
        print(f"  Response time: {float(max_qps_row['response_time_ms']):.2f} ms")
        print(f"  CPU usage:     {float(max_qps_row['cpu_percent']):.1f}%")
        print(f"  Memory:        {float(max_qps_row['memory_mb']):.1f} MB")
        print(f"  Packet loss:   {float(max_qps_row['packet_loss_percent']):.1f}%")
EOF
fi
