#!/usr/bin/env sh
# Build the Arena mediamtx Docker image.
#
# Dockerfile-mediamtx copies a pre-built linux/amd64 binary
# (`COPY mediamtx-linux-amd64 /mediamtx`). This script cross-compiles that
# binary with the version embedded, drops it next to the Dockerfile, then
# builds the image.
#
# Usage:
#   ./build-docker.sh <version> [image-tag]
#
# Examples:
#   ./build-docker.sh v1.2.3
#   ./build-docker.sh v1.2.3 registry.example.com/arena-mediamtx:v1.2.3

set -eu

VERSION="${1:?usage: ./build-docker.sh <version> [image-tag]}"
IMAGE="${2:-mediamtx-arena:$VERSION}"

DIR="$(cd "$(dirname "$0")" && pwd)"   # customized-dockers/  (docker build context)
ROOT="$(cd "$DIR/.." && pwd)"          # repo root

# 1. Cross-compile linux/amd64 with the version embedded, output into the
#    build context so the Dockerfile's COPY finds it.
echo ">> building linux/amd64 binary (version $VERSION)"
"$ROOT/build.sh" "$VERSION" "$DIR/mediamtx-linux-amd64" linux amd64

# 2. Build the image (context = this directory).
echo ">> building image $IMAGE"
docker build -f "$DIR/Dockerfile-mediamtx" -t "$IMAGE" "$DIR"

echo ">> done: $IMAGE"
