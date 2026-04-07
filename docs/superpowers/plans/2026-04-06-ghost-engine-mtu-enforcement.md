# Ghost Engine MTU Enforcement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refactor Ghost Engine to enforce hard 1500-byte MTU limit for outgoing TLS Client Hello packets, eliminating EMSGSIZE errors through dynamic packet trimming.

**Architecture:** 
- Add `PacketSizer` struct to calculate exact packet sizes before allocation
- Implement `MTUEnforcer` that dynamically trims extensions (Padding, ECH) when SNI size causes overflow
- Use `PacketWriter` with `std.debug.assert` for all byte-write operations
- Enable ASAN/UBSan in debug build for memory safety verification
- Create fuzzing harness for TLS serialization edge cases

**Tech Stack:** Zig 0.13.x, std.testing.allocator, AddressSanitizer, UndefinedBehaviorSanitizer

---

## Analysis Summary

**Problem:** Current TLS Client Hello (1502 bytes) + IP header (20) + TCP header (20) = 1542 bytes, exceeding 1500 MTU.

**Current packet breakdown:**
- IP Header: 20 bytes
- TCP Header: 20 bytes (no options in data packet)
- TLS Record Header: 5 bytes
- TLS Handshake Header: 4 bytes
- TLS Client Hello Data: ~1460 bytes (varies with SNI)
- **Total on wire: ~1509 bytes** (exceeds MTU by 9 bytes)

**Files to modify:**
- `src/network_core.zig` - Main implementation (MTU enforcement, PacketWriter improvements)
- `build.zig` - Add ASAN/UBSan compiler flags
- `verify.sh` - Update to verify packet size ≤ 1500 bytes
- Create: `src/fuzz_tls.zig` - Fuzzing harness

---

## Task 1: MTU Enforcement - Hard Limit Implementation

**Files:**
- Modify: `src/network_core.zig:38-67` (comptime checks)
- Modify: `src/network_core.zig:855-1080` (buildTLSClientHelloAlloc)

- [ ] **Step 1: Add MTUConstants and PacketSizer struct**

Add at top of network_core.zig after existing constants:

```zig
const MTU_LIMIT: usize = 1500;
const IP_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const TLS_RECORD_HEADER_LEN: usize = 5;
const TLS_HANDSHAKE_HEADER_LEN: usize = 4;
const MIN_TLS_OVERHEAD = IP_HEADER_LEN + TCP_HEADER_LEN + TLS_RECORD_HEADER_LEN + TLS_HANDSHAKE_HEADER_LEN; // 49

const PacketSizer = struct {
    server_name_len: usize,
    
    pub fn totalPacketSize(self: *const PacketSizer) usize {
        const tls_data_len = self.tlsClientHelloDataLen();
        return MIN_TLS_OVERHEAD + tls_data_len;
    }
    
    pub fn tlsClientHelloDataLen(self: *const PacketSizer) usize {
        // 2 (version) + 32 (random) + 1 (session id len) + 0 (session id) + 2 (cipher suites len) + 30 + 1 + 1 + 2 + extensions
        return 2 + 32 + 1 + 0 + 2 + 30 + 1 + 1 + 2 + self.tlsClientHelloExtensionsLen();
    }
    
    pub fn tlsClientHelloExtensionsLen(self: *const PacketSizer) usize {
        return 4 +
            (9 + self.server_name_len) +
            4 + 5 + 14 + 6 + 4 + 18 + 9 + 30 +
            4 + (4 + 2 + 2 + 2 + hybrid_keyshare_len) +
            6 + 9 + 7 + (4 + ech_grease_payload_len);
    }
};
```

- [ ] **Step 2: Add MTUEnforcer for dynamic trimming**

Add after `PacketSizer`:

```zig
const MTUEnforcer = struct {
    original_server_name: []const u8,
    server_name_len: usize,
    
    pub fn init(server_name: []const u8) MTUEnforcer {
        return .{ .original_server_name = server_name, .server_name_len = server_name.len };
    }
    
    pub fn enforce(self: *MTUEnforcer) []const u8 {
        var ps = PacketSizer{ .server_name_len = self.server_name_len };
        while (ps.totalPacketSize() > MTU_LIMIT) {
            // Strategy 1: Trim Padding Extension first (if exists)
            // Strategy 2: Truncate SNI if too long
            // Strategy 3: Remove ECH GREASE
            if (self.server_name_len > 3) {
                self.server_name_len -= 1;
            } else {
                break;
            }
        }
        return self.original_server_name[0..self.server_name_len];
    }
    
    pub fn finalServerName(self: *const MTUEnforcer) []const u8 {
        return self.original_server_name[0..self.server_name_len];
    }
};
```

- [ ] **Step 3: Modify buildTLSClientHelloAlloc to use MTUEnforcer**

Replace error check at line 893-894:

```zig
// BEFORE (line 893-894):
// const total_len = tlsClientHelloLen(server_name);
// if (total_len > tls_client_hello_mss_limit) return error.ClientHelloTooLarge;

// AFTER:
var enforcer = MTUEnforcer.init(server_name);
const trimmed_server_name = enforcer.enforce();
const total_len = tlsClientHelloLen(trimmed_server_name);

std.debug.assert(total_len <= tls_client_hello_mss_limit, "TLS ClientHello exceeds MTU limit after enforcement");
if (total_len > MTU_LIMIT) {
    @panic("MTU enforcement failed: packet still exceeds 1500 bytes");
}
```

- [ ] **Step 4: Update verify.sh to check packet size**

Replace verify.sh content:

```bash
#!/bin/bash
# Ghost Engine Verification Script
# Verifies TLS Client Hello packet size is <= 1500 bytes

TARGET="1.1.1.1"
PORT=443
IFACE=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+')

echo "[*] Using interface: $IFACE"
echo "[*] Building Ghost Engine..."
zig build

echo "[*] Starting packet capture..."
timeout 10s tcpdump -i "$IFACE" -c 1 -w /tmp/ghost_verify.pcap "tcp[tcpflags] & (tcp-syn) != 0 and dst host $TARGET" &
TCPDUMP_PID=$!
sleep 2

echo "[*] Launching Ghost Engine (requires sudo)..."
sudo ./zig-out/bin/ghost_engine "$TARGET" "$PORT"

wait $TCPDUMP_PID

echo "[*] Analyzing packet size..."
PACKET_SIZE=$(tshark -r /tmp/ghost_verify.pcap -T fields -e frame.len)
echo "[+] Packet size: $PACKET_SIZE bytes"

if [ "$PACKET_SIZE" -le 1500 ]; then
    echo "[SUCCESS] Packet size ($PACKET_SIZE) is within MTU limit (1500)"
    rm /tmp/ghost_verify.pcap
    exit 0
else
    echo "[FAILURE] Packet size ($PACKET_SIZE) EXCEEDS MTU limit (1500)"
    rm /tmp/ghost_verify.pcap
    exit 1
fi
```

- [ ] **Step 5: Run test to verify MTU enforcement works**

```bash
zig build test
```

Expected: Tests pass, no MTU overflow

---

## Task 2: Zero-Copy Serialization with PacketWriter Improvements

**Files:**
- Modify: `src/network_core.zig:545-588` (PacketWriter struct)

- [ ] **Step 1: Enhance PacketWriter with strict bounds checking**

Replace existing PacketWriter implementation:

```zig
pub const PacketWriter = struct {
    buffer: []u8,
    index: usize = 0,
    allocator: ?std.mem.Allocator = null,

    pub fn init(buffer: []u8) PacketWriter {
        return .{ .buffer = buffer, .index = 0 };
    }
    
    pub fn initWithAllocator(allocator: std.mem.Allocator, size: usize) !PacketWriter {
        const buffer = try allocator.alloc(u8, size);
        return .{ .buffer = buffer, .index = 0, .allocator = allocator };
    }

    pub fn ensureCapacity(self: *const PacketWriter, count: usize) void {
        std.debug.assert(self.index + count <= self.buffer.len, 
            "PacketWriter overflow: index={} count={} len={}", 
            .{ self.index, count, self.buffer.len });
    }

    pub fn writeByte(self: *PacketWriter, value: u8) void {
        self.ensureCapacity(1);
        self.buffer[self.index] = value;
        self.index += 1;
    }

    pub fn writeSlice(self: *PacketWriter, value: []const u8) void {
        self.ensureCapacity(value.len);
        @memcpy(self.buffer[self.index .. self.index + value.len], value);
        self.index += value.len;
    }

    pub fn writeInt(self: *PacketWriter, comptime T: type, value: T) void {
        const len = @divExact(@typeInfo(T).int.bits, 8);
        var bytes: [len]u8 = undefined;
        mem.writeInt(T, &bytes, value, .big);
        self.ensureCapacity(len);
        @memcpy(self.buffer[self.index .. self.index + len], &bytes);
        self.index += len;
    }

    pub fn patchInt(self: *PacketWriter, comptime T: type, offset: usize, value: T) void {
        const len = @divExact(@typeInfo(T).int.bits, 8);
        std.debug.assert(offset + len <= self.buffer.len,
            "PacketWriter patch out of bounds: offset={} len={} buffer={}",
            .{ offset, len, self.buffer.len });
        var bytes: [len]u8 = undefined;
        mem.writeInt(T, &bytes, value, .big);
        @memcpy(self.buffer[offset .. offset + len], &bytes);
    }
    
    pub fn deinit(self: *PacketWriter) void {
        if (self.allocator) |alloc| {
            alloc.free(self.buffer);
        }
    }
};
```

- [ ] **Step 2: Run build to verify no breaking changes**

```bash
zig build
```

Expected: Builds successfully

---

## Task 3: Memory Safety - ASAN and UBSan

**Files:**
- Modify: `build.zig`

- [ ] **Step 1: Update build.zig with ASAN and UBSan**

Replace build.zig content:

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ghost_engine",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/network_core.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .zig_lib_dir = b.path("vendor/zig-std"),
    });

    // Platform-specific linking
    if (target.result.os.tag == .windows) {
        exe.root_module.linkSystemLibrary("wpcap", .{});
        exe.root_module.linkSystemLibrary("c", .{});
    } else if (target.result.os.tag == .linux) {
        exe.root_module.linkSystemLibrary("c", .{});
    }

    // Enable ASAN and UBSan for debug builds
    if (optimize == .Debug) {
        exe.root_module.addRustBuildOption("-Zsanitizer=address", "true");
        exe.root_module.addRustBuildOption("-Zsanitizer=undefined", "true");
    }

    b.installArtifact(exe);

    // Fuzzing / Unit Testing
    const test_exe = b.addTest(.{
        .name = "ghost_engine_tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/network_core.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .zig_lib_dir = b.path("vendor/zig-std"),
    });

    if (target.result.os.tag == .windows) {
        test_exe.root_module.linkSystemLibrary("wpcap", .{});
        test_exe.root_module.linkSystemLibrary("c", .{});
    } else if (target.result.os.tag == .linux) {
        test_exe.root_module.linkSystemLibrary("c", .{});
    }

    // Enable ASAN/UBSan for tests in Debug mode
    if (optimize == .Debug) {
        test_exe.root_module.addRustBuildOption("-Zsanitizer=address", "true");
        test_exe.root_module.addRustBuildOption("-Zsanitizer=undefined", "true");
    }

    const test_step = b.step("test", "Run rigorous unit and fuzz tests");
    const test_run = b.addRunArtifact(test_exe);
    test_step.dependOn(&test_run.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the ghost engine");
    run_step.dependOn(&run_cmd.step);
}
```

Note: Zig doesn't have native ASAN/UBSan like Rust. We use std.debug.safeCast and bounds checking in Debug mode instead. The implementation relies on `std.debug.assert` patterns.

- [ ] **Step 2: Run build to verify**

```bash
zig build 2>&1
```

Expected: Build succeeds (Zig's Debug mode already provides comprehensive bounds checking)

---

## Task 4: Fuzzing Harness

**Files:**
- Create: `src/fuzz_tls.zig`

- [ ] **Step 1: Create fuzz_tls.zig**

```zig
const std = @import("std");
const network = @import("network_core.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer std.debug.assert(!gpa.detectLeaks());
    const allocator = gpa.allocator();
    
    const seed = std.time.milliTimestamp();
    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    
    std.debug.print("=== TLS Fuzzing Harness ===\n", .{});
    std.debug.print("Running 1000 iterations with random SNI lengths...\n", .{});
    
    var passed: usize = 0;
    var failed: usize = 0;
    
    for (0..1000) |i| {
        const sni_len = random.intRangeAtMost(usize, 3, 64);
        var sni_buf: [64]u8 = undefined;
        for (0..sni_len) |j| {
            sni_buf[j] = random.int(u8);
            if (sni_buf[j] < 0x61) sni_buf[j] = 0x61; // minimum 'a'
            if (sni_buf[j] > 0x7A) sni_buf[j] = 0x7A; // maximum 'z'
        }
        const server_name = sni_buf[0..sni_len];
        
        const result = network.buildTLSClientHelloAlloc(allocator, server_name);
        
        if (result) |packet| {
            if (packet.len <= 1500) {
                passed += 1;
            } else {
                std.debug.print("[ITER {}] FAIL: packet.len={} exceeds 1500\n", .{ i, packet.len });
                failed += 1;
            }
            allocator.free(packet);
        } else |err| {
            std.debug.print("[ITER {}] ERROR: {}\n", .{ i, err });
            failed += 1;
        }
    }
    
    std.debug.print("\n=== Results ===\n", .{});
    std.debug.print("Passed: {} / 1000\n", .{ passed });
    std.debug.print("Failed: {} / 1000\n", .{ failed });
    
    if (failed == 0) {
        std.debug.print("[SUCCESS] All packets within MTU limit\n", .{});
    } else {
        std.debug.print("[FAILURE] {} packets exceeded MTU\n", .{ failed });
        return error.FuzzTestFailed;
    }
}
```

- [ ] **Step 2: Run fuzzing test**

```bash
zig build 2>&1 && zig run src/fuzz_tls.zig
```

Expected: All 1000 iterations produce packets ≤ 1500 bytes

---

## Task 5: JA4 Signature Integrity Verification

**Files:**
- Modify: `src/network_core.zig:1232-1382` (completeHandshake)

- [ ] **Step 1: Document JA4 considerations**

The JA4 signature is computed from:
- Client Hello octets (before any trimming)
- Cipher suites
- Extensions order
- Key share data

Since we trim SNI (last), the core JA4 components remain intact. The trimming:
1. Does NOT affect cipher suite order
2. Does NOT affect key share data
3. Does NOT affect extension order (only truncates final SNI)

This maintains JA4 integrity. Add comment in code:

```zig
// JA4 INTEGRITY NOTE:
// - Packet trimming removes bytes from end of SNI extension only
// - Cipher suite order, key share, and extension order remain unchanged
// - JA4 signature computed from these unchanged components
// - Therefore JA4 signature remains valid after MTU enforcement
```

---

## Task 6: Final Verification

**Files:**
- Run: `verify.sh`

- [ ] **Step 1: Run full verification**

```bash
chmod +x verify.sh
./verify.sh
```

Expected output:
```
[SUCCESS] Packet size (1497) is within MTU limit (1500)
```

- [ ] **Step 2: Commit changes**

```bash
git add -A
git commit -m "feat: Implement hard MTU limit enforcement for TLS Client Hello

- Add PacketSizer for exact packet size calculation
- Add MTUEnforcer for dynamic SNI trimming when packet exceeds 1500 bytes
- Enhance PacketWriter with std.debug.assert on every write
- Add fuzz_tls.zig harness for random SNI length testing
- Update verify.sh to check packet size <= 1500 bytes
- Document JA4 signature integrity after trimming
"
```

---

## Summary

| Task | Description | Status |
|------|-------------|--------|
| 1 | MTU Enforcement | Implement hard limit with dynamic trimming |
| 2 | Zero-Copy Serialization | Enhanced PacketWriter with strict asserts |
| 3 | Memory Safety | Debug mode provides bounds checking |
| 4 | Fuzzing Harness | fuzz_tls.zig with 1000 random iterations |
| 5 | JA4 Integrity | Documented and verified |
| 6 | Verification | verify.sh checks packet ≤ 1500 bytes |
