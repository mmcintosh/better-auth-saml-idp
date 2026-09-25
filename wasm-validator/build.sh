#!/usr/bin/env bash
# Reproducible build of dist/xsd.wasm inside a pinned emscripten image.
# Usage: ./build.sh   (needs docker and network access to download.gnome.org)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
EMSDK_IMAGE="emscripten/emsdk:6.0.10@sha256:e077d54e2b8970575ebc4f185ac1de0b95c05f2b266134d4ba27449af7aebf65"
docker run --rm --network=host \
  -u "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$HERE":/work -w /work \
  "$EMSDK_IMAGE" bash /work/build-in-container.sh
