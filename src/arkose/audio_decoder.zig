const std = @import("std");
const process = std.process;
const mem = std.mem;
const Io = std.Io;

// SOURCE: Digital audio sample format — IEEE 32-bit float (f32le)
// SOURCE: man ffprobe — multimedia stream metadata extraction
// SOURCE: man ffmpeg — PCM f32le encoding/decoding
// SOURCE: POSIX file I/O — open/read/write/close

pub const AudioMetadata = struct {
    sample_rate: u32,
    bit_depth: u8,
    channels: u8,
    duration_seconds: f64,
    format: []const u8,
};

pub const DecodedClip = struct {
    samples: []const f32,
    sample_rate: u32,
    total_samples: usize,
    max_amplitude: f32,
};

comptime {
    std.debug.assert(@sizeOf(AudioMetadata) > 0);
    std.debug.assert(@sizeOf(DecodedClip) > 0);
}

fn detectFormat(file_path: []const u8) []const u8 {
    if (mem.endsWith(u8, file_path, ".wav")) return "wav";
    if (mem.endsWith(u8, file_path, ".mp3")) return "mp3";
    if (mem.endsWith(u8, file_path, ".raw")) return "raw";
    if (mem.endsWith(u8, file_path, ".flac")) return "flac";
    if (mem.endsWith(u8, file_path, ".ogg")) return "ogg";
    if (mem.endsWith(u8, file_path, ".f32")) return "f32";
    if (mem.endsWith(u8, file_path, ".aac")) return "aac";
    if (mem.endsWith(u8, file_path, ".wma")) return "wma";
    return "unknown";
}

fn readMonotonicNs() u64 {
    var ts: std.posix.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    std.debug.assert(rc == 0);
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s +
        @as(u64, @intCast(ts.nsec));
}

fn parseAudioMetadataOutput(output: []const u8, file_path: []const u8) !AudioMetadata {
    var sample_rate: ?u32 = null;
    var bit_depth: ?u8 = null;
    var channels: ?u8 = null;
    var duration_seconds: ?f64 = null;

    var lines = mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " \n\r");
        if (trimmed.len == 0) continue;

        const eq_index = mem.indexOfScalar(u8, trimmed, '=') orelse return error.InvalidMetadata;
        const key = mem.trim(u8, trimmed[0..eq_index], " \n\r");
        const value = mem.trim(u8, trimmed[eq_index + 1 ..], " \n\r");

        if (mem.eql(u8, key, "sample_rate")) {
            sample_rate = try std.fmt.parseInt(u32, value, 10);
        } else if (mem.eql(u8, key, "bits_per_sample")) {
            bit_depth = try std.fmt.parseInt(u8, value, 10);
        } else if (mem.eql(u8, key, "channels")) {
            channels = try std.fmt.parseInt(u8, value, 10);
        } else if (mem.eql(u8, key, "duration")) {
            duration_seconds = try std.fmt.parseFloat(f64, value);
        }
    }

    const parsed_sample_rate = sample_rate orelse return error.InvalidMetadata;
    const parsed_bit_depth = bit_depth orelse return error.InvalidMetadata;
    const parsed_channels = channels orelse return error.InvalidMetadata;
    const parsed_duration_seconds = duration_seconds orelse return error.InvalidMetadata;

    std.debug.assert(parsed_sample_rate == 44100 or parsed_sample_rate == 22050 or parsed_sample_rate == 16000);

    return AudioMetadata{
        .sample_rate = parsed_sample_rate,
        .bit_depth = parsed_bit_depth,
        .channels = parsed_channels,
        .duration_seconds = parsed_duration_seconds,
        .format = detectFormat(file_path),
    };
}

// SOURCE: man ffprobe — -show_entries stream for sample_rate, bits_per_sample, channels, duration
// SOURCE: man ffprobe — default output format key=value parser
pub fn probeAudioMetadata(allocator: std.mem.Allocator, io: Io, file_path: []const u8) !AudioMetadata {
    const result = try process.run(allocator, io, .{
        .argv = &.{
            "ffprobe",
            "-v",
            "error",
            "-show_entries",
            "stream=sample_rate,bits_per_sample,channels,duration",
            "-of",
            "default=noprint_wrappers=1",
            file_path,
        },
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    switch (result.term) {
        .exited => |code| {
            if (code != 0) return error.FfprobeFailed;
        },
        else => return error.FfprobeFailed,
    }

    return parseAudioMetadataOutput(result.stdout, file_path);
}

// SOURCE: man ffmpeg — pcm_f32le encoder writes 32-bit float PCM in little-endian
pub fn convertToPcmF32(allocator: std.mem.Allocator, io: Io, input_path: []const u8, sample_rate: u32) !DecodedClip {
    std.debug.assert(sample_rate == 44100 or sample_rate == 22050 or sample_rate == 16000);

    const ts = readMonotonicNs();
    const output_path = try std.fmt.allocPrint(allocator, "/tmp/audio_convert_{d}.f32", .{ts});
    defer allocator.free(output_path);
    defer Io.Dir.deleteFileAbsolute(io, output_path) catch {};

    var sample_rate_buf: [16]u8 = undefined;
    const sample_rate_str = try std.fmt.bufPrint(&sample_rate_buf, "{d}", .{sample_rate});

    const result = try process.run(allocator, io, .{
        .argv = &.{
            "ffmpeg",
            "-y",
            "-i",
            input_path,
            "-f",
            "f32le",
            "-acodec",
            "pcm_f32le",
            "-ac",
            "1",
            "-ar",
            sample_rate_str,
            output_path,
        },
    });
    defer {
        allocator.free(result.stdout);
        allocator.free(result.stderr);
    }

    switch (result.term) {
        .exited => |code| {
            if (code != 0) return error.FfmpegFailed;
        },
        else => return error.FfmpegFailed,
    }

    const samples = try loadF32File(allocator, io, output_path);

    var max_amp: f32 = 0.0;
    for (samples) |s| {
        const abs_s = if (s < 0) -s else s;
        if (abs_s > max_amp) max_amp = abs_s;
    }

    return DecodedClip{
        .samples = samples,
        .sample_rate = sample_rate,
        .total_samples = samples.len,
        .max_amplitude = max_amp,
    };
}

// SOURCE: Digital audio peak normalization standard — max amplitude = 1.0 (0dBFS)
pub fn peakNormalize(allocator: std.mem.Allocator, samples: []const f32) !struct { normalized: []f32, scale: f32 } {
    std.debug.assert(samples.len > 0);

    var max_amp: f32 = 0.0;
    for (samples) |s| {
        const abs_s = if (s < 0) -s else s;
        if (abs_s > max_amp) max_amp = abs_s;
    }

    if (max_amp == 0.0) return error.SilentClip;

    const scale = 1.0 / max_amp;
    const normalized = try allocator.alloc(f32, samples.len);
    errdefer allocator.free(normalized);

    for (samples, 0..) |s, i| {
        normalized[i] = s * scale;
    }

    return .{ .normalized = normalized, .scale = scale };
}

// SOURCE: POSIX file I/O — open/read/close for binary .f32 format
pub fn loadF32File(allocator: std.mem.Allocator, io: Io, file_path: []const u8) ![]const f32 {
    var file = try Io.Dir.openFileAbsolute(io, file_path, .{});
    defer file.close(io);

    const stat = try file.stat(io);
    std.debug.assert(stat.size > 0);
    std.debug.assert(stat.size % @sizeOf(f32) == 0);

    const f32_count = @as(usize, @intCast(stat.size / @sizeOf(f32)));
    const samples = try allocator.alloc(f32, f32_count);
    errdefer allocator.free(samples);

    const byte_buf = mem.sliceAsBytes(samples);
    const bytes_read = try file.readPositionalAll(io, byte_buf, 0);
    if (bytes_read != stat.size) return error.FileReadError;

    return samples;
}

// SOURCE: POSIX file I/O — open/write/close for binary .f32 format
pub fn saveF32ToFile(allocator: std.mem.Allocator, io: Io, samples: []const f32, file_path: []const u8) !void {
    _ = allocator;
    var file = try Io.Dir.createFileAbsolute(io, file_path, .{ .truncate = true });
    defer file.close(io);

    const byte_buf = mem.sliceAsBytes(samples);
    try file.writeStreamingAll(io, byte_buf);
}

test "audio_decoder: peak normalization" {
    const allocator = std.testing.allocator;
    const samples = [_]f32{ 0.5, -0.3, 0.8, -0.2 };

    const result = try peakNormalize(allocator, &samples);
    defer allocator.free(result.normalized);

    try std.testing.expectEqual(@as(f32, 1.25), result.scale);
    try std.testing.expectEqual(@as(f32, 0.625), result.normalized[0]);
    try std.testing.expectEqual(@as(f32, -0.375), result.normalized[1]);
    try std.testing.expectEqual(@as(f32, 1.0), result.normalized[2]);
    try std.testing.expectEqual(@as(f32, -0.25), result.normalized[3]);
}

test "audio_decoder: peak normalization rejects silent clip" {
    const allocator = std.testing.allocator;
    const silent = [_]f32{ 0.0, 0.0, 0.0 };

    try std.testing.expectError(error.SilentClip, peakNormalize(allocator, &silent));
}

test "audio_decoder: AudioMetadata struct size" {
    try std.testing.expect(@sizeOf(AudioMetadata) > 0);
}

test "audio_decoder: DecodedClip struct size" {
    try std.testing.expect(@sizeOf(DecodedClip) > 0);
}

test "audio_decoder: detectFormat from file extension" {
    try std.testing.expectEqualStrings("wav", detectFormat("/path/to/file.wav"));
    try std.testing.expectEqualStrings("mp3", detectFormat("/path/to/file.mp3"));
    try std.testing.expectEqualStrings("raw", detectFormat("/path/to/file.raw"));
    try std.testing.expectEqualStrings("f32", detectFormat("/path/to/file.f32"));
    try std.testing.expectEqualStrings("unknown", detectFormat("/path/to/file.xyz"));
}

test "audio_decoder: probeAudioMetadata returns error for invalid file" {
    const allocator = std.testing.allocator;
    var io_impl: Io.Threaded = undefined;
    io_impl = Io.Threaded.init(std.heap.smp_allocator, .{});
    const io = io_impl.io();

    if (probeAudioMetadata(allocator, io, "/tmp/nonexistent_test_audio_file_xyz.wav")) |_| {
        try std.testing.expect(false);
    } else |_| {
        // Expected — either ffprobe not found or file doesn't exist
    }
}

test "audio_decoder: ffprobe key=value output parses by key not line position" {
    const sample_output =
        "sample_rate=44100\n" ++
        "channels=1\n" ++
        "bits_per_sample=0\n" ++
        "duration=14.497937\n";

    const metadata = try parseAudioMetadataOutput(sample_output, "/tmp/test.mp3");

    try std.testing.expectEqual(@as(u32, 44100), metadata.sample_rate);
    try std.testing.expectEqual(@as(u8, 1), metadata.channels);
    try std.testing.expectEqual(@as(u8, 0), metadata.bit_depth);
    try std.testing.expectApproxEqAbs(@as(f64, 14.497937), metadata.duration_seconds, 0.000001);
    try std.testing.expectEqualStrings("mp3", metadata.format);
}

test "audio_decoder: save and load f32 round-trip" {
    const allocator = std.testing.allocator;
    var io_impl: Io.Threaded = undefined;
    io_impl = Io.Threaded.init(std.heap.smp_allocator, .{});
    const io = io_impl.io();

    const original = [_]f32{ 0.5, -0.3, 0.8, -0.2, 1.0, -1.0, 0.0 };

    const ts = readMonotonicNs();
    const tmp_path = try std.fmt.allocPrint(allocator, "/tmp/audio_roundtrip_{d}.f32", .{ts});
    defer allocator.free(tmp_path);
    defer Io.Dir.deleteFileAbsolute(io, tmp_path) catch {};

    try saveF32ToFile(allocator, io, &original, tmp_path);

    const loaded = try loadF32File(allocator, io, tmp_path);
    defer allocator.free(loaded);

    try std.testing.expectEqual(original.len, loaded.len);
    for (&original, loaded) |orig, ld| {
        try std.testing.expectEqual(orig, ld);
    }
}
