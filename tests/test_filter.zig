const std = @import("std");

fn filterRawPacket(
    data: []const u8,
    expected_dst_ip: u32,
    expected_dst_port: u16,
    expected_src_port: u16,
    ip_header_len: *usize,
) bool {
    if (data.len < 20) { std.debug.print("Failed length\n", .{}); return false; }

    const ip_header = data[0..20];

    if ((ip_header[0] >> 4) != 4) { std.debug.print("Failed IPv4\n", .{}); return false; }
    if (ip_header[9] != 0x06) { std.debug.print("Failed TCP proto\n", .{}); return false; }

    const pkt_dst_ip = (@as(u32, ip_header[16]) << 24) |
        (@as(u32, ip_header[17]) << 16) |
        (@as(u32, ip_header[18]) << 8) |
        @as(u32, ip_header[19]);
    if (pkt_dst_ip != expected_dst_ip) {
        std.debug.print("Failed dst_ip: pkt 0x{x} vs exp 0x{x}\n", .{pkt_dst_ip, expected_dst_ip});
        return false;
    }

    const ihl_words = (ip_header[0] & 0x0F);
    const ihl_bytes = @as(usize, ihl_words) * 4;

    if (ihl_bytes < 20 or data.len < ihl_bytes + 20) {
        std.debug.print("Failed IHL or length\n", .{});
        return false;
    }

    const tcp_header = data[ihl_bytes .. ihl_bytes + 20];
    const pkt_src_port = (@as(u16, tcp_header[0]) << 8) | @as(u16, tcp_header[1]);
    const pkt_dst_port = (@as(u16, tcp_header[2]) << 8) | @as(u16, tcp_header[3]);

    if (pkt_src_port != expected_src_port) {
        std.debug.print("Failed src_port: pkt {} exp {}\n", .{pkt_src_port, expected_src_port});
        return false; 
    }
    if (pkt_dst_port != expected_dst_port) {
        std.debug.print("Failed dst_port: pkt {} exp {}\n", .{pkt_dst_port, expected_dst_port});
        return false;
    }

    ip_header_len.* = ihl_bytes;
    return true;
}

pub fn main() !void {
    // Manually constructed SYN-ACK from 1.1.1.1:443 to 192.168.1.2:60397
    var pkt: [60]u8 = undefined;
    @memset(&pkt, 0);

    // IP
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[9] = 0x06; // TCP
    // Src IP: 1.1.1.1
    pkt[12] = 1; pkt[13] = 1; pkt[14] = 1; pkt[15] = 1;
    // Dst IP: 192.168.1.2
    pkt[16] = 192; pkt[17] = 168; pkt[18] = 1; pkt[19] = 2;

    // TCP
    const sport: u16 = 443;
    const dport: u16 = 60397;
    pkt[20] = @truncate(sport >> 8); pkt[21] = @truncate(sport & 0xFF);
    pkt[22] = @truncate(dport >> 8); pkt[23] = @truncate(dport & 0xFF);

    var ip_offset: usize = 0;
    
    // ctx.src_ip computation (same as `main` logic in network_core.zig)
    const expected_dst_ip = (@as(u32, 192) << 24) | (@as(u32, 168) << 16) | (@as(u32, 1) << 8) | 2;
    // Note: ctx.src_ip in `network_core.zig` comes from `return @byteSwap(addr.addr);`
    
    const result = filterRawPacket(&pkt, expected_dst_ip, dport, sport, &ip_offset);
    std.debug.print("Mock SYN-ACK test: {}\n", .{result});
}
