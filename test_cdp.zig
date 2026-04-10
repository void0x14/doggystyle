const std = @import("std");
const linux = std.os.linux;

pub fn main() void {
    const addr = std.posix.sockaddr.in{
        .port = std.mem.bigToNative(u16, 9222),
        .addr = @as(u32, 127) << 24 | @as(u32, 1),
    };

    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM, 0);
    if (rc == std.math.maxInt(usize)) {
        std.debug.print("socket failed\n", .{});
        return;
    }
    const fd: i32 = @intCast(rc);
    defer _ = std.c.close(fd);

    const rc2 = linux.connect(fd, @ptrCast(&addr), @sizeOf(std.posix.sockaddr.in));
    if (rc2 == std.math.maxInt(usize)) {
        std.debug.print("connect failed\n", .{});
        return;
    }
    std.debug.print("TCP connected fd={d}\n", .{fd});

    // Send HTTP GET /json
    const req = "GET /json HTTP/1.1\r\nHost: localhost:9222\r\nConnection: close\r\n\r\n";
    const written = std.c.write(fd, req.ptr, req.len);
    std.debug.print("Written: {d} bytes (expected {d})\n", .{ written, req.len });

    // Set SO_RCVTIMEO
    const tv = linux.timeval{ .sec = 3, .usec = 0 };
    const so_rc = linux.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&tv), @sizeOf(linux.timeval));
    std.debug.print("setsockopt result: {d}\n", .{so_rc});

    // Read response
    var buf: [65536]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len - 1) {
        std.debug.print("Reading at offset {d}...\n", .{total});
        const n = std.posix.read(fd, buf[total..]) catch |err| {
            std.debug.print("read error: {}\n", .{err});
            break;
        };
        std.debug.print("Read {d} bytes\n", .{n});
        if (n == 0) break;
        total += n;
    }

    std.debug.print("Total: {d} bytes\n", .{total});
    if (total > 0) {
        const display = @min(total, 500);
        std.debug.print("Response:\n{s}\n", .{buf[0..display]});
    }
}
