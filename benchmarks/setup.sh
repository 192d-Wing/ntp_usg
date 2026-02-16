#!/bin/bash
# Install dependencies for NTP benchmarks
#
# Usage: ./setup.sh

set -euo pipefail

echo "Installing NTP benchmark dependencies..."
echo ""

# Check OS
if [[ ! -f /etc/os-release ]]; then
  echo "Error: /etc/os-release not found. Unsupported OS."
  exit 1
fi

source /etc/os-release

# Install based on distro
case "$ID" in
  ubuntu|debian)
    echo "Detected: $PRETTY_NAME"
    sudo apt-get update
    sudo apt-get install -y \
      chrony \
      ntp \
      ntpdate \
      bc \
      python3 \
      python3-pip \
      gpsd \
      gpsd-clients \
      pps-tools
    ;;

  fedora|rhel|centos|rocky|almalinux)
    echo "Detected: $PRETTY_NAME"
    sudo dnf install -y \
      chrony \
      ntp \
      ntpdate \
      bc \
      python3 \
      python3-pip \
      gpsd \
      pps-tools
    ;;

  arch|manjaro)
    echo "Detected: $PRETTY_NAME"
    sudo pacman -S --noconfirm \
      chrony \
      ntp \
      bc \
      python \
      python-pip \
      gpsd \
      pps-tools
    ;;

  *)
    echo "Warning: Unsupported distribution: $ID"
    echo "Please install manually:"
    echo "  - chrony"
    echo "  - ntp (ntpd)"
    echo "  - ntpdate, ntpq"
    echo "  - bc (calculator)"
    echo "  - python3 with pip"
    exit 1
    ;;
esac

# Install Python packages
echo ""
echo "Installing Python packages..."
pip3 install --user pandas matplotlib numpy scipy 2>/dev/null || \
  python3 -m pip install --user pandas matplotlib numpy scipy

# Verify installations
echo ""
echo "Verifying installations..."

MISSING=0

command -v chronyd >/dev/null 2>&1 || { echo "  ✗ chronyd not found"; MISSING=1; }
command -v ntpd >/dev/null 2>&1 || { echo "  ✗ ntpd not found"; MISSING=1; }
command -v ntpdate >/dev/null 2>&1 || { echo "  ✗ ntpdate not found"; MISSING=1; }
command -v ntpq >/dev/null 2>&1 || { echo "  ✗ ntpq not found"; MISSING=1; }
command -v bc >/dev/null 2>&1 || { echo "  ✗ bc not found"; MISSING=1; }
command -v python3 >/dev/null 2>&1 || { echo "  ✗ python3 not found"; MISSING=1; }

if [[ $MISSING -eq 0 ]]; then
  echo "  ✓ All required tools installed"
else
  echo ""
  echo "Error: Some tools are missing. Please install manually."
  exit 1
fi

# Check Python packages
echo ""
echo "Checking Python packages..."
python3 -c "import pandas, matplotlib, numpy, scipy" 2>/dev/null && \
  echo "  ✓ Python packages installed" || \
  echo "  ✗ Python packages missing (run: pip3 install pandas matplotlib numpy scipy)"

# Build ntp_usg
echo ""
echo "Building ntp_usg..."
cd "$(dirname "${BASH_SOURCE[0]}")/.."
cargo build --release -p ntp_usg-client --all-features
cargo build --release -p ntp_usg-server --all-features

echo ""
echo "✓ Setup complete!"
echo ""
echo "Next steps:"
echo "  1. Run quick test: sudo ./benchmarks/run-all.sh --quick --no-stratum1"
echo "  2. Run full suite: sudo ./benchmarks/run-all.sh --no-stratum1"
echo ""
