const std = @import("std");
const fft = @import("audio/fft_analyzer.zig");

// SOURCE: libFuzzer-inspired — FFT + spectral flux random input test
// Tests that FFT and spectral flux handle garbage input without UB

test "fuzz_fft: random input does not crash" {
    var prng = std.Random.DefaultPrng.init(0xDEAD);
    const rand = prng.random();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var buf: [44100]u8 = undefined;
    for (0..100) |_| {
        rand.bytes(&buf);
        const f32_count = buf.len / @sizeOf(f32);
        const samples = @as([]const f32, @ptrCast(@alignCast(buf[0..f32_count * @sizeOf(f32)])));

        const clip_len = samples.len / 3;
        if (clip_len < 64) continue;

        const clips = [_][]const f32{
            samples[0..clip_len],
            samples[clip_len .. 2 * clip_len],
            samples[2 * clip_len ..],
        };

        const result = fft.analyze(allocator, &clips, 44100) catch continue;
        _ = result;
    }
}
