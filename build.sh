#!/usr/bin/env sh
# Build the mediamtx binary with a version passed as a parameter.
#
# The version is embedded via //go:embed internal/core/VERSION
# (normally produced by `git describe --tags`). This script pins it
# to the value you pass instead.
#
# Usage:
#   ./build.sh <version> [output-binary] [target-os] [target-arch]
#
# Examples:
#   ./build.sh v1.2.3
#   ./build.sh v1.2.3 mediamtx-arena
#   ./build.sh v1.2.3 mediamtx-linux linux amd64

set -eu

VERSION="${1:?usage: ./build.sh <version> [output-binary] [GOOS] [GOARCH]}"
OUT="${2:-mediamtx}"
TARGET_OS="${3:-}"
TARGET_ARCH="${4:-}"

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# 1. Ensure the hls.js embed exists (required by internal/servers/hls).
#    Only fetch when missing so the script stays offline-friendly.
if [ ! -f internal/servers/hls/hls.min.js ]; then
  echo ">> generating hls.min.js"
  ( cd internal/servers/hls && go run ./hlsjsdownloader )
fi

# 2. Pin the embedded version to the parameter.
echo ">> setting version: $VERSION"
printf '%s' "$VERSION" > internal/core/VERSION

# 3. Build. CGO off for a static, portable binary.
#    Use `env` so optional GOOS/GOARCH (from variable expansion) are applied
#    as real environment assignments, not parsed as a command.
echo ">> building: $OUT"
env CGO_ENABLED=0 \
  ${TARGET_OS:+GOOS=$TARGET_OS} \
  ${TARGET_ARCH:+GOARCH=$TARGET_ARCH} \
  go build -o "$OUT" .

echo ">> done: $OUT"
# Print version when building for the host platform.
if [ -z "$TARGET_OS" ] && [ -z "$TARGET_ARCH" ]; then
  ./"$OUT" --version
fi
