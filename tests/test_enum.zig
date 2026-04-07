const std = @import("std");
pub fn main() void {
    const info = @typeInfo(std.zig.SanitizeC);
    for (info.Enum.fields) |f| {
        std.debug.print("{s}\n", .{f.name});
    }
}
