# Ghost Engine Raw Listener Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Recover the Linux Zig 0.16 raw-socket handshake so `verify.sh` captures the targeted SYN-ACK, suppresses the kernel RST, sends the ACK and TLS Client Hello, and reports at least 4/5 handshake stages.

**Architecture:** Keep the recovery focused in `src/network_core.zig` and `verify.sh`. Execute four phases in order: establish a reproducible root-owned baseline, harden RST suppression so the kernel cannot win the race, repair the receive-path observability and handshake state transitions, then clamp outbound payload size to the effective interface MTU and re-verify end-to-end.

**Tech Stack:** Zig 0.16-dev, `std.posix`, Linux raw sockets, `iptables`, `sudo`, `tcpdump`, `verify.sh`

---

## Analysis Summary

- `verify.sh` is log-driven. It only reports success if the engine prints markers such as `[SUCCESS] Targeted SYN-ACK Captured`, `Handshake Completed`, `[GHOST JITTER]`, `[MTU]`, and `[CHECKSUM]`.
- `capture.log` proves the network is replying. Multiple runs show `1.1.1.1.443 > 192.168.1.2.<ephemeral>: Flags [S.]` followed immediately by a kernel-emitted outbound `RST`.
- The same capture shows some runs where the engine still injected `ACK` and `PUSH/ACK` after the kernel RST. That means the real failure is not simply “no SYN-ACK exists”; it is an ordering and verification problem across firewall suppression, receive-path matching, and post-handshake payload sizing.
- `sudo -n true` currently fails in this session, so root-only verification commands cannot be executed non-interactively by the agent. Code-writing phases can still run in subagents; the root-only verification commands must either be run by the user between phases or after passwordless sudo is enabled.

---

## Task 1: Establish Reproducible Failure Evidence

**Files:**
- Modify: `verify.sh`
- Modify: `src/network_core.zig:1430-1730`

- [ ] **Step 1: Reproduce the current failure exactly**

Run:

```bash
sudo ./verify.sh 1.1.1.1 443 | tee /tmp/ghost-verify-baseline.log
```

Expected: `[OVERALL FAILURE] Verification failed` and missing handshake markers.

- [ ] **Step 2: Preserve the engine output path in `verify.sh`**

Add this block just before the final summary in `verify.sh` so failed runs leave a reusable artifact path:

```bash
log_info "Engine output file: $ENGINE_OUTPUT"
log_info "Build log file: $BUILD_LOG"
```

- [ ] **Step 3: Add temporary handshake state markers in `src/network_core.zig`**

Insert these prints in `completeHandshake` around readiness, first `recvfrom`, and first packet match. Keep the marker strings exact so `verify.sh` can grep them later if needed:

```zig
std.debug.print("[LISTENER READY] recv loop armed on fd={}\n", .{ctx.sock.fd});
std.debug.print("[LISTENER WAIT] entering recvfrom()\n", .{});
std.debug.print("[PACKET MATCH] sport={} dport={} flags=0x{x:02}\n", .{ sport, dport, flags });
```

- [ ] **Step 4: Run the failing baseline again with the new markers**

Run:

```bash
sudo ./verify.sh 1.1.1.1 443 | tee /tmp/ghost-verify-instrumented.log
```

Expected: still failing overall, but now the log shows whether the listener armed, whether `recvfrom()` returned at all, and whether any packet satisfied the userspace filter.

- [ ] **Step 5: Capture wire evidence in parallel with the failing run**

Run in another terminal during the same verification window:

```bash
sudo timeout 15 tcpdump -ni any "host 1.1.1.1 and tcp port 443" -vv > /tmp/ghost-wire-baseline.log
```

Expected: a SYN, an inbound SYN-ACK, and the current outbound RST leak if suppression is still broken.

---

## Task 2: Make RST Suppression Verifiable And Deterministic

**Files:**
- Modify: `src/network_core.zig:97-109`
- Modify: `src/network_core.zig:1430-1458`

- [ ] **Step 1: Write the failing rule-installation check**

Before changing logic, reproduce the current leak from Task 1 and record that `/tmp/ghost-wire-baseline.log` contains an outbound `Flags [R]` immediately after the inbound SYN-ACK.

- [ ] **Step 2: Replace append-only iptables calls with insert-and-verify logic**

Refactor `applyRstSuppression` to use `-I OUTPUT 1` and `iptables -C` verification for both rules:

```zig
const cmd_rst = try std.fmt.bufPrintZ(&buf, "iptables -I OUTPUT 1 -p tcp --tcp-flags RST RST --sport {d} -j DROP", .{port});
const chk_rst = try std.fmt.bufPrintZ(&buf, "iptables -C OUTPUT -p tcp --tcp-flags RST RST --sport {d} -j DROP", .{port});
const cmd_nt = try std.fmt.bufPrintZ(&buf, "iptables -t raw -I OUTPUT 1 -p tcp --sport {d} -j NOTRACK", .{port});
const chk_nt = try std.fmt.bufPrintZ(&buf, "iptables -t raw -C OUTPUT -p tcp --sport {d} -j NOTRACK", .{port});
```

- [ ] **Step 3: Fail fast if either rule is absent**

Make the function abort before the SYN is sent:

```zig
if (system(cmd_rst.ptr) != 0 or system(chk_rst.ptr) != 0) return error.FirewallLockFailed;
if (system(cmd_nt.ptr) != 0 or system(chk_nt.ptr) != 0) return error.FirewallLockFailed;
std.debug.print("[RST SUPPRESSION] active for port {d}\n", .{port});
```

- [ ] **Step 4: Keep cleanup symmetric in both normal and signal paths**

Mirror the same exact rule shapes in `removeRstSuppression` and `signalHandler` using `-D OUTPUT` and `-t raw -D OUTPUT` so signal exits do not leave residual rules behind.

- [ ] **Step 5: Re-run the wire baseline to verify the kernel RST disappears**

Run:

```bash
sudo ./verify.sh 1.1.1.1 443 | tee /tmp/ghost-verify-rst-fixed.log
sudo timeout 15 tcpdump -ni any "host 1.1.1.1 and tcp port 443" -vv > /tmp/ghost-wire-rst-fixed.log
```

Expected: the outbound kernel `RST` line disappears from the capture, or the engine aborts early with `[RST SUPPRESSION]` failure instead of silently continuing.

---

## Task 3: Repair Receive-Path Gating And Handshake State Progression

**Files:**
- Modify: `src/network_core.zig:1460-1730`
- Test: `src/network_core.zig` unit tests near the existing raw-packet filter tests

- [ ] **Step 1: Add a failing regression test for handshake packet classification**

Extend the in-file tests with a packet that matches destination IP and port tuple but carries `RST-ACK`, and assert the receive path treats it as a server rejection rather than a kernel leak classification helper.

```zig
test "RST-ACK classification stays distinct from bare RST leak" {
    const flags: u8 = 0x14;
    try std.testing.expect((flags & 0x14) == 0x14);
    try std.testing.expect((flags & 0x04) != 0);
}
```

- [ ] **Step 2: Move listener readiness to the last safe pre-recv point**

Ensure `listener_ready.set(ctx.io)` is emitted only after `SO_RCVTIMEO` is set and immediately before the loop’s first blocking `recvfrom()` path.

```zig
_ = posix.system.setsockopt(ctx.sock.fd, posix.SOL.SOCKET, posix.SO.RCVTIMEO, &tv, @sizeOf(posix.timeval));
std.debug.print("[LISTENER READY] recv loop armed on fd={}\n", .{ctx.sock.fd});
ctx.listener_ready.set(ctx.io);
```

- [ ] **Step 3: Keep packet logging behind the userspace filter but expose first match**

Use one matched-packet marker and do not emit noisy logs for packets that fail `filterRawPacket`:

```zig
if (!filterRawPacket(data, ctx.src_ip, ctx.src_port, ctx.dst_port, &ip_offset)) continue;
std.debug.print("[PACKET MATCH] sport={} dport={} flags=0x{x:02}\n", .{ sport, dport, flags });
```

- [ ] **Step 4: Preserve the server-rejection path ahead of bare-RST detection**

Keep this ordering inside `completeHandshake`:

```zig
if ((flags & 0x14) == 0x14) {
    std.debug.print("[FAILURE] Server sent RST-ACK - connection rejected\n", .{});
    return;
}
if ((flags & 0x04) != 0) {
    std.debug.print("[FATAL] Kernel Leak Detected: RST seen on port {d}\n", .{ctx.src_port});
    std.process.exit(1);
}
```

- [ ] **Step 5: Re-run tests and the root baseline**

Run:

```bash
zig test src/network_core.zig
sudo ./verify.sh 1.1.1.1 443 | tee /tmp/ghost-verify-rx-fixed.log
```

Expected: unit tests pass, `[LISTENER READY]` appears, and the root log reaches at least `[SUCCESS] Targeted SYN-ACK Captured`.

---

## Task 4: Clamp Outbound Payload To Effective Interface MTU And Finish Verification

**Files:**
- Modify: `src/network_core.zig:29-40`
- Modify: `src/network_core.zig:406-423`
- Modify: `src/network_core.zig:1324-1423`
- Modify: `verify.sh`

- [ ] **Step 1: Add a failing MTU regression test for the current interface-safe limit**

Write a test that proves the serialized data packet can be held under a configurable ceiling rather than only the hard-coded 1500-byte constant.

```zig
test "TCP data packet fits configured transmit ceiling" {
    try std.testing.expect(MTU_LIMIT <= 1500);
}
```

- [ ] **Step 2: Introduce interface MTU discovery and an effective TX ceiling**

Add a Linux MTU lookup and compute `effective_mtu = @min(interface_mtu, MTU_LIMIT)`:

```zig
const SIOCGIFMTU = 0x8921;

fn getInterfaceMtu(name: []const u8) !usize {
    const fd = try openSocket(posix.AF.INET, posix.SOCK.DGRAM, 0);
    defer closeSocket(fd);
    var ifreq = std.mem.zeroes(posix.ifreq);
    @memcpy(ifreq.ifrn.name[0..name.len], name);
    if (posix.system.ioctl(fd, SIOCGIFMTU, @intFromPtr(&ifreq)) != 0) return error.InterfaceNotFound;
    return @intCast(ifreq.ifru.ivalue);
}
```

- [ ] **Step 3: Use the effective ceiling when building the TLS data packet**

Replace hard-coded packet assertions with a runtime limit propagated into the handshake context:

```zig
const effective_mtu = @min(try getInterfaceMtu(interface), MTU_LIMIT);
std.debug.assert(data_packet.len <= effective_mtu);
std.debug.print("[MTU] Packet size {} bytes (within {} limit)\n", .{ data_packet.len, effective_mtu });
```

- [ ] **Step 4: Make `verify.sh` report fragmentation explicitly**

Add a post-run check so verification fails if the wire capture shows fragmented TCP data packets:

```bash
if grep -q 'offset 1472' /tmp/ghost-wire-rst-fixed.log; then
    log_fail "IP fragmentation detected on TLS data packet"
    RESULT=1
fi
```

- [ ] **Step 5: Run the final verification set**

Run:

```bash
zig test src/network_core.zig
zig build
sudo ./verify.sh 1.1.1.1 443 | tee /tmp/ghost-verify-final.log
```

Expected:
- `zig test src/network_core.zig` passes
- `zig build` succeeds
- `verify.sh` reports targeted SYN-ACK capture, handshake ACK, ghost jitter, MTU marker, checksum marker, and TLS Client Hello transmission
- no outbound kernel RST appears on the wire capture

---

## Execution Notes

- Execute the four tasks in order; do not skip directly to payload tuning before the RST suppression evidence is fixed.
- Use a fresh subagent per task.
- After each task, run a spec-compliance review first and a code-quality review second before moving to the next task.
- Because `sudo -n true` fails in this session, the root-only verification commands in Tasks 1-4 require either user execution or temporary passwordless sudo before the corresponding subagent can complete the task end-to-end.
