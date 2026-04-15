#!/usr/bin/env bash
# Build wrapper — forces ZIG_LIB_DIR to vendor/zig-std
# Fixes: vendor/zig/zig uses /lib/zig (older system stdlib) instead of vendor/zig-std (newer)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export ZIG_LIB_DIR="$SCRIPT_DIR/vendor/zig-std"
exec "$SCRIPT_DIR/vendor/zig/zig" build "$@"
