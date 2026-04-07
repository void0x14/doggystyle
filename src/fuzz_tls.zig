const std = @import("std");
const network = @import("network_core.zig");

pub fn main() !void {
    const seed = 12345;
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
            if (sni_buf[j] < 0x61) sni_buf[j] = 0x61;
            if (sni_buf[j] > 0x7A) sni_buf[j] = 0x7A;
        }
        const server_name = sni_buf[0..sni_len];
        
        const result = network.buildTLSClientHelloAlloc(std.heap.page_allocator, server_name);
        
        if (result) |packet| {
            if (packet.len <= 1500) {
                passed += 1;
            } else {
                std.debug.print("[ITER {}] FAIL: packet.len={} exceeds 1500\n", .{ i, packet.len });
                failed += 1;
            }
            std.heap.page_allocator.free(packet);
        } else |err| {
            if (err == error.ServerNameTooLong) {
                passed += 1;
            } else {
                std.debug.print("[ITER {}] ERROR: {}\n", .{ i, err });
                failed += 1;
            }
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
