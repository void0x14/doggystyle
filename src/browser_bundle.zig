const std = @import("std");
const mem = std.mem;

pub const HeaderPair = struct {
    name: []u8,
    value: []u8,

    pub fn deinit(self: *HeaderPair, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

pub const RequestBundle = struct {
    url: []u8,
    method: []u8,
    post_data: []u8,
    headers: []HeaderPair,

    pub fn deinit(self: *RequestBundle, allocator: std.mem.Allocator) void {
        allocator.free(self.url);
        allocator.free(self.method);
        allocator.free(self.post_data);
        for (self.headers) |*header| header.deinit(allocator);
        allocator.free(self.headers);
    }

    pub fn headerValue(self: *const RequestBundle, name: []const u8) ?[]const u8 {
        for (self.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }

    pub fn hasHeader(self: *const RequestBundle, name: []const u8) bool {
        return self.headerValue(name) != null;
    }
};

pub const SignupBundle = struct {
    request: RequestBundle,

    pub fn deinit(self: *SignupBundle, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
    }
};

pub const VerifyBundle = struct {
    request: RequestBundle,

    pub fn deinit(self: *VerifyBundle, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
    }
};

test "RequestBundle.headerValue: case insensitive lookup" {
    const allocator = std.testing.allocator;
    var headers = try allocator.alloc(HeaderPair, 2);
    headers[0] = .{
        .name = try allocator.dupe(u8, "cookie"),
        .value = try allocator.dupe(u8, "_gh_sess=abc"),
    };
    headers[1] = .{
        .name = try allocator.dupe(u8, "Sec-Fetch-Mode"),
        .value = try allocator.dupe(u8, "navigate"),
    };

    var bundle = RequestBundle{
        .url = try allocator.dupe(u8, "https://github.com/signup?social=false"),
        .method = try allocator.dupe(u8, "POST"),
        .post_data = try allocator.dupe(u8, "authenticity_token=abc"),
        .headers = headers,
    };
    defer bundle.deinit(allocator);

    try std.testing.expectEqualStrings("_gh_sess=abc", bundle.headerValue("Cookie").?);
    try std.testing.expectEqualStrings("navigate", bundle.headerValue("sec-fetch-mode").?);
}
