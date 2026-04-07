const std = @import("std");
const network = @import("network_core.zig");

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const sni = "github.com";
    const packet = try network.buildTLSClientHelloAlloc(allocator, sni);
    defer allocator.free(packet);
    std.debug.print("SNI: {s}\n", .{sni});
    std.debug.print("Packet len: {}\n", .{packet.len});
    std.debug.print("Total on wire (IP+TCP+TLS): {} bytes\n", .{20 + 20 + packet.len});
}
