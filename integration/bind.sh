#!/usr/bin/env bash
# Build the NetProbe gomobile binding.
#   ./integration/bind.sh android   -> netprobe.aar        (needs Android NDK)
#   ./integration/bind.sh ios       -> NetProbe.xcframework (needs macOS + Xcode)
set -euo pipefail

TARGET="${1:-android}"
cd "$(dirname "$0")/.."   # repo root

command -v gomobile >/dev/null 2>&1 || {
  echo "gomobile not found. Install it:"
  echo "  go install golang.org/x/mobile/cmd/gomobile@latest"
  echo "  go install golang.org/x/mobile/cmd/gobind@latest"
  echo "  gomobile init"
  exit 1
}

case "$TARGET" in
  android)
    gomobile bind -target=android -androidapi=21 -o netprobe.aar ./lib/mobile
    echo "Built netprobe.aar"
    ;;
  ios)
    gomobile bind -target=ios -o NetProbe.xcframework ./lib/mobile
    echo "Built NetProbe.xcframework"
    ;;
  *)
    echo "usage: $0 [android|ios]"; exit 1
    ;;
esac
