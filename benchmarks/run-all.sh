#!/bin/bash
# Run all NTP benchmarks comparing ntp_usg, chrony, and ntpd
#
# Usage: sudo ./run-all.sh [--quick] [--no-stratum1]
#
# Options:
#   --quick         Run shortened versions (10 min vs 1 hour)
#   --no-stratum1   Skip 24-hour Stratum 1 tests
#
# Requires: root access, ~27 hours without --no-stratum1, ~3 hours with

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="$SCRIPT_DIR/results"
QUICK_MODE=0
SKIP_STRATUM1=0

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --quick)
      QUICK_MODE=1
      shift
      ;;
    --no-stratum1)
      SKIP_STRATUM1=1
      shift
      ;;
    *)
      echo "Unknown option: $1"
      echo "Usage: sudo ./run-all.sh [--quick] [--no-stratum1]"
      exit 1
      ;;
  esac
done

# Check for root
if [[ $EUID -ne 0 ]]; then
   echo "Error: This script must be run as root (sudo ./run-all.sh)"
   exit 1
fi

# Create results directory
mkdir -p "$RESULTS_DIR"

# Banner
echo "═══════════════════════════════════════════════════════"
echo "  NTP Benchmark Suite - ntp_usg vs chrony vs ntpd"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Configuration:"
echo "  Quick mode: $( [[ $QUICK_MODE -eq 1 ]] && echo "YES (10 min tests)" || echo "NO (1 hour tests)" )"
echo "  Stratum 1:  $( [[ $SKIP_STRATUM1 -eq 1 ]] && echo "SKIP" || echo "RUN (24 hours)" )"
echo "  Results:    $RESULTS_DIR"
echo ""

# Estimated duration
if [[ $QUICK_MODE -eq 1 ]]; then
  DURATION="~1 hour"
elif [[ $SKIP_STRATUM1 -eq 1 ]]; then
  DURATION="~3 hours"
else
  DURATION="~27 hours (24h Stratum 1 + 3h other tests)"
fi

echo "Estimated duration: $DURATION"
echo ""
read -p "Press Enter to continue or Ctrl+C to abort... "
echo ""

# Stop any running NTP daemons
echo "[$(date +%H:%M:%S)] Stopping existing NTP daemons..."
systemctl stop ntp 2>/dev/null || true
systemctl stop chrony 2>/dev/null || true
systemctl stop systemd-timesyncd 2>/dev/null || true
sleep 2

# Test 1: Client Accuracy
echo ""
echo "═══════════════════════════════════════════════════════"
echo "Test 1: Client Accuracy (offset and jitter)"
echo "═══════════════════════════════════════════════════════"
echo ""

for impl in ntp_usg chrony ntpd; do
  echo "[$(date +%H:%M:%S)] Testing $impl..."
  if [[ $QUICK_MODE -eq 1 ]]; then
    timeout 600 "$SCRIPT_DIR/test-client-accuracy.sh" "$impl" --duration 600 || true
  else
    "$SCRIPT_DIR/test-client-accuracy.sh" "$impl" || true
  fi
  echo ""
done

# Test 2: Server Throughput
echo ""
echo "═══════════════════════════════════════════════════════"
echo "Test 2: Server Throughput (max QPS)"
echo "═══════════════════════════════════════════════════════"
echo ""

for impl in ntp_usg chrony ntpd; do
  echo "[$(date +%H:%M:%S)] Testing $impl..."
  if [[ $QUICK_MODE -eq 1 ]]; then
    timeout 600 "$SCRIPT_DIR/test-server-throughput.sh" "$impl" --duration 600 || true
  else
    "$SCRIPT_DIR/test-server-throughput.sh" "$impl" || true
  fi
  echo ""
done

# Test 3: Resource Usage
echo ""
echo "═══════════════════════════════════════════════════════"
echo "Test 3: Resource Usage (memory and CPU)"
echo "═══════════════════════════════════════════════════════"
echo ""

for impl in ntp_usg chrony ntpd; do
  echo "[$(date +%H:%M:%S)] Testing $impl..."
  if [[ $QUICK_MODE -eq 1 ]]; then
    timeout 600 "$SCRIPT_DIR/test-resources.sh" "$impl" --duration 600 || true
  else
    "$SCRIPT_DIR/test-resources.sh" "$impl" || true
  fi
  echo ""
done

# Test 4: Stratum 1 Accuracy (optional, requires GPS hardware)
if [[ $SKIP_STRATUM1 -eq 0 ]]; then
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "Test 4: Stratum 1 Accuracy (GPS+PPS)"
  echo "═══════════════════════════════════════════════════════"
  echo ""
  echo "WARNING: This test requires:"
  echo "  - GPS receiver on /dev/ttyAMA0"
  echo "  - PPS signal on /dev/pps0"
  echo "  - 24 hours of runtime"
  echo ""

  if [[ ! -e /dev/pps0 ]] || [[ ! -e /dev/ttyAMA0 ]]; then
    echo "GPS hardware not detected. Skipping Stratum 1 tests."
  else
    read -p "Run 24-hour Stratum 1 tests? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      for impl in ntp_usg chrony ntpd; do
        echo "[$(date +%H:%M:%S)] Testing $impl (this will take 24 hours)..."
        "$SCRIPT_DIR/test-stratum1.sh" "$impl" || true
        echo ""
      done
    else
      echo "Skipped Stratum 1 tests."
    fi
  fi
fi

# Summary
echo ""
echo "═══════════════════════════════════════════════════════"
echo "  All tests complete!"
echo "═══════════════════════════════════════════════════════"
echo ""
echo "Results saved to: $RESULTS_DIR"
echo ""
echo "Next steps:"
echo "  1. Analyze results:  python3 $SCRIPT_DIR/analyze.py"
echo "  2. Create plots:     python3 $SCRIPT_DIR/plot.py"
echo "  3. Generate report:  $SCRIPT_DIR/generate-report.sh"
echo ""
echo "Example:"
echo "  $SCRIPT_DIR/generate-report.sh > docs/BENCHMARK-RESULTS-$(date +%Y%m%d).md"
echo ""
