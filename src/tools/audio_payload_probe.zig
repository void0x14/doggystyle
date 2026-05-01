const std = @import("std");

fn hexToBytes(hex: []const u8, output: []u8) !void {
    if (hex.len % 2 != 0) return error.InvalidFormat;
    if (output.len < hex.len / 2) return error.BufferTooSmall;
    const hex_chars = "0123456789abcdef";
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        const hi = std.mem.indexOfScalar(u8, hex_chars, std.ascii.toLower(hex[i])) orelse return error.InvalidFormat;
        const lo = std.mem.indexOfScalar(u8, hex_chars, std.ascii.toLower(hex[i + 1])) orelse return error.InvalidFormat;
        output[i / 2] = @intCast(hi * 16 + lo);
    }
}

fn aes256CbcDecrypt(key: [32]u8, iv: [16]u8, ciphertext: []const u8, plaintext: []u8) !void {
    if (plaintext.len != ciphertext.len) return error.BufferSizeMismatch;
    if (ciphertext.len % 16 != 0) return error.NotBlockAligned;
    const Aes = std.crypto.core.aes.Aes256;
    var aes_ctx = Aes.initDec(key);
    var i: usize = 0;
    var prev_block = iv;
    while (i < ciphertext.len) : (i += 16) {
        var block: [16]u8 = undefined;
        aes_ctx.decrypt(&block, ciphertext[i .. i + 16][0..16]);
        for (plaintext[i .. i + 16], 0..) |_, j| {
            plaintext[i + j] = block[j] ^ prev_block[j];
        }
        prev_block = ciphertext[i .. i + 16][0..16].*;
    }
}

fn looksLikeMp3(bytes: []const u8) bool {
    if (bytes.len >= 3 and std.mem.eql(u8, bytes[0..3], "ID3")) return true;
    return bytes.len >= 2 and bytes[0] == 0xff and (bytes[1] & 0xe0) == 0xe0;
}

fn tryDecryptVariant(name: []const u8, seed: []const u8, salt: []const u8, iv: [16]u8, encrypted: []const u8) !void {
    var key_material: [512]u8 = undefined;
    if (seed.len + salt.len > key_material.len) return;
    @memcpy(key_material[0..seed.len], seed);
    @memcpy(key_material[seed.len .. seed.len + salt.len], salt);
    const total_len = seed.len + salt.len;

    var md5_chain: [4][16]u8 = undefined;
    std.crypto.hash.Md5.hash(key_material[0..total_len], &md5_chain[0], .{});

    var chain_buf: [528]u8 = undefined;
    chain_buf[0..16].* = md5_chain[0];
    @memcpy(chain_buf[16 .. 16 + total_len], key_material[0..total_len]);
    std.crypto.hash.Md5.hash(chain_buf[0 .. 16 + total_len], &md5_chain[1], .{});
    chain_buf[0..16].* = md5_chain[1];
    @memcpy(chain_buf[16 .. 16 + total_len], key_material[0..total_len]);
    std.crypto.hash.Md5.hash(chain_buf[0 .. 16 + total_len], &md5_chain[2], .{});
    chain_buf[0..16].* = md5_chain[2];
    @memcpy(chain_buf[16 .. 16 + total_len], key_material[0..total_len]);
    std.crypto.hash.Md5.hash(chain_buf[0 .. 16 + total_len], &md5_chain[3], .{});

    var key: [32]u8 = undefined;
    @memcpy(key[0..16], &md5_chain[0]);
    @memcpy(key[16..32], &md5_chain[1]);

    const decrypted = try std.heap.page_allocator.alloc(u8, encrypted.len);
    defer std.heap.page_allocator.free(decrypted);
    aes256CbcDecrypt(key, iv, encrypted, decrypted) catch return;

    if (!looksLikeMp3(decrypted)) return;
    std.debug.print("[PROBE] variant={s} produced MP3-looking plaintext len={d}\n", .{ name, decrypted.len });
    const out = try std.fmt.allocPrint(std.heap.page_allocator, "/tmp/opencode/{s}.mp3", .{name});
    defer std.heap.page_allocator.free(out);
    var io_impl = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();
    var file = try std.Io.Dir.createFileAbsolute(io, out, .{ .truncate = true });
    defer file.close(io);
    try file.writeStreamingAll(io, decrypted);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    var args_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_iter.deinit();
    _ = args_iter.skip();

    const payload_path = args_iter.next() orelse {
        std.debug.print("usage: audio_payload_probe <json-payload-file>\n", .{});
        return;
    };

    var io_impl = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();
    const cwd = std.Io.Dir.cwd();
    const file = try cwd.openFile(io, payload_path, .{});
    defer file.close(io);
    const file_size = try file.length(io);
    const raw = try allocator.alloc(u8, file_size);
    defer allocator.free(raw);
    _ = try std.Io.File.readPositionalAll(file, io, raw, 0);

    const ct_marker = "\"ct\":\"";
    const s_marker = "\"s\":\"";
    const iv_marker = "\"iv\":\"";

    const ct_start = std.mem.indexOf(u8, raw, ct_marker) orelse return error.InvalidFormat;
    const ct_value_start = ct_start + ct_marker.len;
    const ct_value_end = std.mem.indexOf(u8, raw[ct_value_start..], "\"") orelse return error.InvalidFormat;
    const ct_b64 = raw[ct_value_start .. ct_value_start + ct_value_end];

    const s_start = std.mem.indexOf(u8, raw, s_marker) orelse return error.InvalidFormat;
    const s_value_start = s_start + s_marker.len;
    const s_value_end = std.mem.indexOf(u8, raw[s_value_start..], "\"") orelse return error.InvalidFormat;
    const s_hex = raw[s_value_start .. s_value_start + s_value_end];

    const iv_start = std.mem.indexOf(u8, raw, iv_marker) orelse return error.InvalidFormat;
    const iv_value_start = iv_start + iv_marker.len;
    const iv_value_end = std.mem.indexOf(u8, raw[iv_value_start..], "\"") orelse return error.InvalidFormat;
    const iv_hex = raw[iv_value_start .. iv_value_start + iv_value_end];

    const decoded_len = try std.base64.standard.Decoder.calcSizeForSlice(ct_b64);
    const encrypted = try allocator.alloc(u8, decoded_len);
    defer allocator.free(encrypted);
    _ = try std.base64.standard.Decoder.decode(encrypted, ct_b64);

    var salt: [8]u8 = undefined;
    try hexToBytes(s_hex, &salt);
    var iv: [16]u8 = undefined;
    try hexToBytes(iv_hex, &iv);

    const seeds = [_]struct { name: []const u8, value: []const u8 }{
        .{ .name = "ua", .value = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36" },
        .{ .name = "arkose-audio", .value = "audio" },
        .{ .name = "session-literal", .value = "session_token" },
        .{ .name = "challenge-literal", .value = "challengeID" },
        .{ .name = "live-session", .value = "38618ab8603198835.0433941705" },
        .{ .name = "live-challenge", .value = "56318ab860b5ded25.8716862305" },
        .{ .name = "live-session+challenge", .value = "38618ab8603198835.043394170556318ab860b5ded25.8716862305" },
        .{ .name = "live-challenge+session", .value = "56318ab860b5ded25.871686230538618ab8603198835.0433941705" },
        .{ .name = "ua+live-session", .value = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.3638618ab8603198835.0433941705" },
        .{ .name = "ua+live-challenge", .value = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.3656318ab860b5ded25.8716862305" },
    };
    for (seeds) |seed| {
        tryDecryptVariant(seed.name, seed.value, &salt, iv, encrypted) catch {};
    }
}
