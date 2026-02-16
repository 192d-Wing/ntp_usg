#!/bin/bash
# Test resource usage (memory and CPU) for NTP implementation
#
# Usage: sudo ./test-resources.sh <impl> [--duration SECONDS]
#   impl: ntp_usg, chrony, or ntpd
#
# Measures memory and CPU at various load levels

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
  echo "Usage: sudo ./test-resources.sh <ntp_usg|chrony|ntpd> [--duration SECONDS]"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
OUTPUT_FILE="$RESULTS_DIR/resources-$IMPL.csv"

mkdir -p "$RESULTS_DIR"

echo "Testing $IMPL resource usage for $DURATION seconds..."
echo "Output: $OUTPUT_FILE"
echo ""

# Stop all NTP daemons
systemctl stop ntp chrony systemd-timesyncd 2>/dev/null || true
sleep 2

# Start NTP server
echo "Starting $IMPL..."

case "$IMPL" in
  ntp_usg)
    if [[ ! -f "$SCRIPT_DIR/../target/release/examples/server" ]]; then
      cd "$SCRIPT_DIR/.." && cargo build --release -p ntp_usg-server --example server --features tokio
    fi
    "$SCRIPT_DIR/../target/release/examples/server" &
    SERVER_PID=$!
    ;;

  chrony)
    cat > /tmp/chrony-test.conf << EOF
server time.google.com iburst
driftfile /tmp/chrony.drift
allow all
EOF
    chronyd -f /tmp/chrony-test.conf &
    SERVER_PID=$!
    ;;

  ntpd)
    cat > /tmp/ntp-test.conf << EOF
server time.google.com iburst
driftfile /tmp/ntp.drift
EOF
    ntpd -c /tmp/ntp-test.conf -g &
    SERVER_PID=$!
    ;;

  *)
    echo "Unknown implementation: $IMPL"
    exit 1
    ;;
esac

# Wait for startup
sleep 5

if ! ps -p $SERVER_PID > /dev/null; then
  echo "Error: Server failed to start"
  exit 1
fi

echo "✓ Server running (PID: $SERVER_PID)"
echo ""

# Prepare output file
echo "timestamp,implementation,load_qps,cpu_percent,memory_rss_mb,memory_vsz_mb,threads" > "$OUTPUT_FILE"

# Test at different load levels
# Each level runs for DURATION/4 seconds
LOAD_LEVELS=(0 1000 10000 50000)
LEVEL_DURATION=$((DURATION / 4))

for LOAD in "${LOAD_LEVELS[@]}"; do
  if [[ $LOAD -eq 0 ]]; then
    echo "[$(date +%H:%M:%S)] Measuring idle resource usage..."
  else
    echo "[$(date +%H:%M:%S)] Measuring at $LOAD QPS load..."

    # Start load generators
    LOAD_PIDS=()
    QUERIES_PER_CLIENT=$((LOAD / 10))

    for i in {1..10}; do
      (
        INTERVAL=$(echo "scale=6; 1.0 / $QUERIES_PER_CLIENT" | bc)
        while true; do
          ntpdate -q 127.0.0.1 >/dev/null 2>&1 || true
          sleep "$INTERVAL" 2>/dev/null || sleep 0.01
        done
      ) &
      LOAD_PIDS+=($!)
    done
  fi

  # Monitor for duration
  START_TIME=$(date +%s)
  END_TIME=$((START_TIME + LEVEL_DURATION))

  while [[ $(date +%s) -lt $END_TIME ]]; do
    TIMESTAMP=$(date +%s)

    # Get CPU and memory stats
    if [[ -e /proc/$SERVER_PID/stat ]]; then
      # CPU percentage (averaged over 1 second)
      CPU1=$(ps -p $SERVER_PID -o %cpu --no-headers)
      sleep 1
      CPU2=$(ps -p $SERVER_PID -o %cpu --no-headers)
      CPU=$(echo "scale=2; ($CPU1 + $CPU2) / 2" | bc)

      # Memory (RSS and VSZ in MB)
      MEM_STATS=$(ps -p $SERVER_PID -o rss,vsz --no-headers)
      RSS=$(echo "$MEM_STATS" | awk '{print $1}')
      VSZ=$(echo "$MEM_STATS" | awk '{print $2}')
      RSS_MB=$(echo "scale=2; $RSS / 1024" | bc)
      VSZ_MB=$(echo "scale=2; $VSZ / 1024" | bc)

      # Thread count
      THREADS=$(ps -p $SERVER_PID -o nlwp --no-headers)

      echo "$TIMESTAMP,$IMPL,$LOAD,$CPU,$RSS_MB,$VSZ_MB,$THREADS" >> "$OUTPUT_FILE"

      # Progress
      ELAPSED=$((TIMESTAMP - START_TIME))
      echo -ne "\r  Progress: $ELAPSED/${LEVEL_DURATION}s  CPU: ${CPU}%  MEM: ${RSS_MB}MB  "
    else
      echo ""
      echo "Error: Server process died"
      break 2
    fi
  done

  echo ""

  # Stop load generators
  for PID in "${LOAD_PIDS[@]:-}"; do
    kill $PID 2>/dev/null || true
  done
  wait 2>/dev/null || true

  # Cooldown
  if [[ $LOAD -ne 0 ]]; then
    echo "  Cooldown..."
    sleep 5
  fi
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

# Statistics
if command -v python3 &>/dev/null; then
  python3 << EOF
import csv
from collections import defaultdict

data_by_load = defaultdict(list)

with open('$OUTPUT_FILE') as f:
    reader = csv.DictReader(f)
    for row in reader:
        load = int(row['load_qps'])
        data_by_load[load].append(row)

print("\\nResource usage by load level:")
print("┌───────────┬─────────────┬──────────────┬──────────────┐")
print("│   Load    │  CPU (avg)  │ Memory (avg) │   Threads    │")
print("├───────────┼─────────────┼──────────────┼──────────────┤")

for load in sorted(data_by_load.keys()):
    rows = data_by_load[load]
    avg_cpu = sum(float(r['cpu_percent']) for r in rows) / len(rows)
    avg_mem = sum(float(r['memory_rss_mb']) for r in rows) / len(rows)
    threads = rows[-1]['threads']

    load_str = "Idle" if load == 0 else f"{load:,} QPS"
    print(f"│ {load_str:<9} │ {avg_cpu:>9.1f}% │ {avg_mem:>10.1f} MB │ {threads:>12} │")

print("└───────────┴─────────────┴──────────────┴──────────────┘")
EOF
fi
