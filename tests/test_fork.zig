const std = @import("std");

pub fn main() !void {
    const pid = try std.posix.fork();
    if (pid == 0) {
        std.posix.exit(0);
    }
}
