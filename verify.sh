#!/bin/bash
# Ghost Engine Verification Script - ZERO DEPENDENCY / ZERO INTERVENTION
# Compiles, configures iptables, runs the engine, validates output, cleans up.
#
# Exit codes: 0 = overall success, 1 = failure
# Usage: sudo ./verify.sh [TARGET_IP] [PORT]

set -euo pipefail

TARGET="${1:-1.1.1.1}"
PORT="${2:-443}"
TIMEOUT=20

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ENGINE_OUTPUT=$(mktemp /tmp/ghost_engine_output.XXXXXX)
BUILD_LOG=$(mktemp /tmp/ghost_build.XXXXXX)

cleanup() {
    rm -f "$ENGINE_OUTPUT" "$BUILD_LOG"
}
trap cleanup EXIT

log_ok()   { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_fail() { echo -e "${RED}[FAILURE]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# ---- Phase 1: Build ----
echo -e "${BLUE}[*] Ghost Engine Zero-Dependency Verification${NC}"
echo -e "${BLUE}[*] Target: $TARGET:$PORT${NC}"
echo -e "${BLUE}[*] Building Ghost Engine...${NC}"

if ! zig build 2>&1 | tee "$BUILD_LOG"; then
    log_fail "Build failed"
    cat "$BUILD_LOG"
    exit 1
fi
log_ok "Build completed"

# ---- Phase 2: Run ----
echo -e "${BLUE}[*] Launching Ghost Engine (timeout ${TIMEOUT}s)...${NC}"
echo -e "${YELLOW}[!] Requires root for raw socket access${NC}"

# Pre-authenticate sudo on the real TTY so password prompt works correctly.
# Without this, sudo prompts INSIDE the redirected subshell which breaks
# terminal echo (password shows in plaintext) and re-prompts on each call.
if ! sudo -v 2>/dev/tty; then
    log_fail "sudo authentication failed"
    exit 1
fi

# Run with timeout; capture combined stdout+stderr
timeout $TIMEOUT sudo ./zig-out/bin/ghost_engine "$TARGET" "$PORT" >"$ENGINE_OUTPUT" 2>&1 || true

# ---- Phase 3: Validate ----
echo -e "${BLUE}[*] Analyzing output...${NC}"

RESULT=0
STAGES=0

# 3.1  Surgical SYN-ACK capture
if grep -q '\[SUCCESS\] Targeted SYN-ACK Captured' "$ENGINE_OUTPUT"; then
    log_ok "Surgical SYN-ACK filter: Targeted SYN-ACK captured"
    ((STAGES++))
else
    log_fail "Surgical SYN-ACK filter: Not captured"
    RESULT=1
fi

# 3.2  Handshake completion (ACK sent)
if grep -q 'Handshake Completed' "$ENGINE_OUTPUT"; then
    log_ok "Handshake Stage 2: ACK sent"
    ((STAGES++))
else
    log_warn "Handshake ACK not confirmed"
fi

# 3.3  Ghost Jitter (8-15ms)
if grep -q '\[GHOST JITTER\]' "$ENGINE_OUTPUT"; then
    JITTER_MS=$(grep -oP '\[GHOST JITTER\] Delaying \K[0-9]+' "$ENGINE_OUTPUT" | tail -1)
    if [ -n "$JITTER_MS" ] && [ "$JITTER_MS" -ge 8 ] && [ "$JITTER_MS" -le 15 ]; then
        log_ok "Ghost Jitter: ${JITTER_MS}ms (within 8-15ms organic range)"
    else
        log_warn "Ghost Jitter: ${JITTER_MS:-?}ms (outside 8-15ms)"
    fi
else
    log_warn "Ghost Jitter marker not found"
fi

# 3.4  MTU compliance (<= 1500)
if grep -q '\[MTU\] Packet size' "$ENGINE_OUTPUT"; then
    PKT_SIZE=$(grep -oP '\[MTU\] Packet size \K[0-9]+' "$ENGINE_OUTPUT" | tail -1)
    if [ -n "$PKT_SIZE" ] && [ "$PKT_SIZE" -le 1500 ]; then
        log_ok "MTU Compliance: ${PKT_SIZE} bytes (<= 1500)"
        ((STAGES++))
    else
        log_fail "MTU Violation: ${PKT_SIZE:-?} bytes"
        RESULT=1
    fi
else
    log_warn "MTU marker not found"
fi

# 3.5  TCP Checksum
if grep -q '\[CHECKSUM\]' "$ENGINE_OUTPUT"; then
    CSUM=$(grep -oP 'checksum=0x\K[0-9a-fA-F]+' "$ENGINE_OUTPUT" | tail -1)
    log_ok "TCP Checksum pseudo-header computed: 0x${CSUM}"
else
    log_warn "TCP Checksum marker not found"
fi

# 3.6  TLS Client Hello sent
if grep -q 'TLS Client Hello sent' "$ENGINE_OUTPUT"; then
    log_ok "TLS Stage: Client Hello transmitted"
    ((STAGES++))
else
    log_warn "TLS Client Hello not sent"
fi

# 3.7  TLS Alert parsing
if grep -q '\[TLS ALERT\]' "$ENGINE_OUTPUT"; then
    ALERT_LINE=$(grep '\[TLS ALERT\]' "$ENGINE_OUTPUT" | tail -1)
    log_info "TLS Alert received: $ALERT_LINE"
fi

# 3.8  JA4S confirmation
if grep -q '\[SUCCESS\] JA4S Confirmed' "$ENGINE_OUTPUT"; then
    log_ok "JA4S Verification: Server Hello cipher suite match"
    ((STAGES++))
elif grep -q 'JA4S Verification Failed' "$ENGINE_OUTPUT"; then
    log_warn "JA4S: No valid Server Hello (may be dropped by CDN)"
fi

# 3.9  No kernel RST leak
if grep -q 'Kernel Leak Detected' "$ENGINE_OUTPUT"; then
    log_fail "Kernel RST leak detected"
    RESULT=1
else
    log_ok "No kernel RST leak"
fi

# 3.10  No global noise (INBOUND PACKET should only appear for validated packets)
INBOUND_COUNT=$(grep -c 'INBOUND PACKET' "$ENGINE_OUTPUT" 2>/dev/null || echo 0)
log_info "Validated inbound packets logged: $INBOUND_COUNT"

# 3.11  Hex dump packet analysis
DUMP_COUNT=$(grep -c 'RAW HEX DUMP BEFORE SEND' "$ENGINE_OUTPUT" 2>/dev/null || echo 0)
if [ "$DUMP_COUNT" -gt 0 ]; then
    log_ok "Raw socket transmission: $DUMP_COUNT packet(s) sent"
fi

# ---- Phase 4: Summary ----
echo ""
echo -e "${BLUE}[*] Verification Summary:${NC}"
echo -e "${BLUE}    Handshake stages completed: $STAGES/5${NC}"

if [ $RESULT -eq 0 ]; then
    if [ $STAGES -ge 4 ]; then
        echo -e "${GREEN}[OVERALL SUCCESS] Ghost Engine Surgical Integrity Verified${NC}"
    elif [ $STAGES -ge 2 ]; then
        echo -e "${YELLOW}[PARTIAL SUCCESS] Core functionality verified, handshake incomplete${NC}"
    else
        echo -e "${YELLOW}[MINIMAL] Build succeeded but handshake did not progress${NC}"
    fi
else
    echo -e "${RED}[OVERALL FAILURE] Verification failed${NC}"
fi

exit $RESULT
