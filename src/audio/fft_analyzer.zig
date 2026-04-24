const std = @import("std");

pub const Complex = struct {
    re: f64,
    im: f64,
};

pub const SpectralFluxResult = struct {
    guess: u8,
    execution_time_ms: u64,
    deltas: [3]f64,
};

comptime {
    std.debug.assert(@sizeOf(Complex) == 16);
    std.debug.assert(@sizeOf(SpectralFluxResult) > 0);
}

// SOURCE: Cooley & Tukey, "An algorithm for the machine calculation of complex
// Fourier series", 1965, Math. Comp. 19: 297-301
pub fn fft(buffer: []Complex) void {
    const N = buffer.len;
    std.debug.assert(std.math.isPowerOfTwo(N));

    var log2N: usize = 0;
    var tmp = N;
    while (tmp > 1) : (tmp >>= 1) {
        log2N += 1;
    }

    // Bit-reversal permutation
    for (0..N) |i| {
        const j = bitReverse(i, log2N);
        if (j > i) {
            const t = buffer[i];
            buffer[i] = buffer[j];
            buffer[j] = t;
        }
    }

    // Cooley-Tukey DIT butterfly iterations
    var stage_len: usize = 2;
    while (stage_len <= N) : (stage_len *= 2) {
        const half = stage_len / 2;
        var k: usize = 0;
        while (k < N) : (k += stage_len) {
            var j: usize = 0;
            while (j < half) : (j += 1) {
                const angle = -2.0 * std.math.pi *
                    @as(f64, @floatFromInt(j)) /
                    @as(f64, @floatFromInt(stage_len));
                const w_re = std.math.cos(angle);
                const w_im = std.math.sin(angle);

                const odd_re = buffer[k + j + half].re * w_re -
                    buffer[k + j + half].im * w_im;
                const odd_im = buffer[k + j + half].re * w_im +
                    buffer[k + j + half].im * w_re;

                const even = buffer[k + j];
                buffer[k + j] = Complex{
                    .re = even.re + odd_re,
                    .im = even.im + odd_im,
                };
                buffer[k + j + half] = Complex{
                    .re = even.re - odd_re,
                    .im = even.im - odd_im,
                };
            }
        }
    }
}

fn bitReverse(x: usize, numBits: usize) usize {
    var result: usize = 0;
    var t = x;
    for (0..numBits) |_| {
        result = (result << 1) | (t & 1);
        t >>= 1;
    }
    return result;
}

// SOURCE: Cauchy-Schwarz theorem — Euclidean norm
pub fn magnitude(comp: Complex) f64 {
    return @sqrt(comp.re * comp.re + comp.im * comp.im);
}

// SOURCE: Blackman & Tukey, "The measurement of power spectra", 1958
fn hanningWindow(allocator: std.mem.Allocator, length: usize) ![]f64 {
    const window = try allocator.alloc(f64, length);
    const inv = 1.0 / @as(f64, @floatFromInt(length - 1));
    for (0..length) |n| {
        const x = @as(f64, @floatFromInt(n));
        window[n] = 0.5 * (1.0 - std.math.cos(2.0 * std.math.pi * x * inv));
    }
    return window;
}

// SOURCE: Scheirer & Slaney, "Construction and evaluation of a robust
// multifeature speech/music discriminator", 1997, IEEE ICASSP
fn computeSpectralFlux(allocator: std.mem.Allocator, clip: []const f32, sample_rate: u32) !f64 {
    const total_samples = clip.len;
    const mid_point = @min(sample_rate * 6, total_samples / 2);
    std.debug.assert(mid_point > 0);
    const second_half_len = total_samples - mid_point;
    const fft_window_len = @min(mid_point, second_half_len);

    const fft_len = try std.math.ceilPowerOfTwo(u64, fft_window_len);
    std.debug.assert(std.math.isPowerOfTwo(fft_len));
    const half_bins = fft_len / 2;

    // Footstep frequency band: 1-3 kHz
    // SOURCE: Ekimov & Sabatier, "Human walking sound spectrum analysis", 2006
    // SOURCE: NASA SP-7010 — walking footstep dominant frequencies 1-3 kHz
    const freq_start_hz: f64 = 1000.0;
    const freq_end_hz: f64 = 3000.0;
    const nyquist_hz = @as(f64, @floatFromInt(sample_rate)) / 2.0;
    const use_footstep_band = nyquist_hz >= freq_end_hz;
    const band_bin_start = if (use_footstep_band)
        @min(@as(usize, @intFromFloat(@as(f64, @floatFromInt(fft_len)) * freq_start_hz / @as(f64, @floatFromInt(sample_rate)))), half_bins - 1)
    else
        0;
    const band_bin_end = if (use_footstep_band)
        @min(@as(usize, @intFromFloat(@as(f64, @floatFromInt(fft_len)) * freq_end_hz / @as(f64, @floatFromInt(sample_rate)))), half_bins)
    else
        half_bins;
    const bin_count = band_bin_end - band_bin_start;
    std.debug.assert(bin_count > 0);

    const window = try hanningWindow(allocator, fft_window_len);
    defer allocator.free(window);

    const fft_buf = try allocator.alloc(Complex, fft_len);
    defer allocator.free(fft_buf);

    const mag = try allocator.alloc(f64, bin_count);
    defer allocator.free(mag);

    // First half: [0, fft_window_len)
    @memset(fft_buf, Complex{ .re = 0.0, .im = 0.0 });
    for (0..fft_window_len) |i| {
        const val: f64 = @floatCast(clip[i]);
        fft_buf[i] = Complex{ .re = val * window[i], .im = 0.0 };
    }
    fft(fft_buf);
    for (0..bin_count) |i| {
        mag[i] = magnitude(fft_buf[band_bin_start + i]);
    }

    // Second half: [mid_point, mid_point + fft_window_len)
    @memset(fft_buf, Complex{ .re = 0.0, .im = 0.0 });
    for (0..fft_window_len) |i| {
        const val: f64 = @floatCast(clip[mid_point + i]);
        fft_buf[i] = Complex{ .re = val * window[i], .im = 0.0 };
    }
    fft(fft_buf);

    var delta: f64 = 0.0;
    for (0..bin_count) |i| {
        const m2 = magnitude(fft_buf[band_bin_start + i]);
        const diff = m2 - mag[i];
        delta += diff * diff;
    }

    return delta;
}

// SOURCE: clock_gettime — man 2 clock_gettime, CLOCK_MONOTONIC
pub fn analyze(allocator: std.mem.Allocator, clips: []const []const f32, sample_rate: u32) !SpectralFluxResult {
    std.debug.assert(clips.len == 3);

    var start_ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &start_ts);

    var deltas: [3]f64 = undefined;
    for (clips, 0..) |clip, i| {
        deltas[i] = try computeSpectralFlux(allocator, clip, sample_rate);
    }

    var end_ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &end_ts);

    const start_ns = @as(u128, @intCast(start_ts.sec)) * 1_000_000_000 +
        @as(u128, @intCast(start_ts.nsec));
    const end_ns = @as(u128, @intCast(end_ts.sec)) * 1_000_000_000 +
        @as(u128, @intCast(end_ts.nsec));
    const elapsed_ns = end_ns - start_ns;
    const elapsed_ms = @as(u64, @intCast(elapsed_ns / 1_000_000));

    std.debug.assert(elapsed_ms > 0);

    var max_index: u8 = 0;
    var max_delta = deltas[0];
    for (deltas, 0..) |d, i| {
        if (d > max_delta) {
            max_delta = d;
            max_index = @as(u8, @intCast(i));
        }
    }
    std.debug.assert(max_index <= 2);

    return SpectralFluxResult{
        .guess = max_index,
        .execution_time_ms = elapsed_ms,
        .deltas = deltas,
    };
}

// ---- Tests ----

test "fft_analyzer: Complex struct size" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(Complex));
}

test "fft_analyzer: FFT correctness (DC signal)" {
    const N = 8;
    var buffer: [N]Complex = undefined;
    for (&buffer) |*b| b.* = .{ .re = 1.0, .im = 0.0 };
    fft(&buffer);
    try std.testing.expectApproxEqAbs(@as(f64, 8.0), buffer[0].re, 1e-9);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), buffer[0].im, 1e-9);
    for (1..N) |i| {
        try std.testing.expectApproxEqAbs(@as(f64, 0.0), buffer[i].re, 1e-9);
        try std.testing.expectApproxEqAbs(@as(f64, 0.0), buffer[i].im, 1e-9);
    }
}

test "fft_analyzer: spectral flux with synthetic data" {
    const sample_rate: u32 = 100;
    var clip = try std.testing.allocator.alloc(f32, sample_rate * 12);
    defer std.testing.allocator.free(clip);

    for (0..sample_rate * 6) |i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        clip[i] = @as(f32, @floatCast(std.math.sin(2.0 * std.math.pi * 440.0 * t)));
    }
    for (sample_rate * 6..sample_rate * 12) |i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        clip[i] = @as(f32, @floatCast(std.math.sin(2.0 * std.math.pi * 880.0 * t)));
    }

    const flux = try computeSpectralFlux(std.testing.allocator, clip, sample_rate);
    try std.testing.expect(flux > 0.0);
}

test "fft_analyzer: spectral flux with identical halves" {
    const sample_rate: u32 = 100;
    var clip = try std.testing.allocator.alloc(f32, sample_rate * 12);
    defer std.testing.allocator.free(clip);

    for (0..sample_rate * 12) |i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        clip[i] = @as(f32, @floatCast(std.math.sin(2.0 * std.math.pi * 440.0 * t)));
    }

    const flux = try computeSpectralFlux(std.testing.allocator, clip, sample_rate);
    try std.testing.expect(flux < 0.01);
}

test "fft_analyzer: analyze returns valid guess" {
    const allocator = std.testing.allocator;

    // Create 3 clips with different spectral characteristics
    // Clip 0: pure sine 440Hz in first half, 880Hz in second half — high flux
    // Clip 1: pure sine 440Hz throughout — low flux
    // Clip 2: pure sine 880Hz throughout — low flux
    const sample_rate: u32 = 44100;
    const clip_duration_sec: f64 = 12.0;
    const total_samples = @as(usize, @intFromFloat(sample_rate * clip_duration_sec));
    const mid = @as(usize, @intFromFloat(@as(f64, @floatFromInt(sample_rate)) * 6.0));

    // Generate clips
    var clip0 = try allocator.alloc(f32, total_samples);
    defer allocator.free(clip0);
    var clip1 = try allocator.alloc(f32, total_samples);
    defer allocator.free(clip1);
    var clip2 = try allocator.alloc(f32, total_samples);
    defer allocator.free(clip2);

    for (0..total_samples) |i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, sample_rate);
        clip0[i] = if (i < mid)
            @as(f32, @floatCast(@sin(2.0 * std.math.pi * 440.0 * t)))
        else
            @as(f32, @floatCast(@sin(2.0 * std.math.pi * 880.0 * t)));
        clip1[i] = @as(f32, @floatCast(@sin(2.0 * std.math.pi * 440.0 * t)));
        clip2[i] = @as(f32, @floatCast(@sin(2.0 * std.math.pi * 880.0 * t)));
    }

    const clips = [_][]const f32{ clip0, clip1, clip2 };
    const result = try analyze(allocator, &clips, sample_rate);

    // Clip 0 should have the highest spectral flux (frequency changes at midpoint)
    try std.testing.expectEqual(@as(u8, 0), result.guess);
    try std.testing.expect(result.deltas[0] > result.deltas[1]);
    try std.testing.expect(result.deltas[0] > result.deltas[2]);
    try std.testing.expect(result.execution_time_ms > 0);
}

test "fft_analyzer: gerçek Arkose audio verisi ile analiz" {
    const allocator = std.testing.allocator;
    var io_impl = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();
    const cwd = std.Io.Dir.cwd();

    const file = try cwd.openFile(io, "tmp/audio_live.f32", .{});
    defer file.close(io);
    const file_size = try file.length(io);
    const raw_bytes = try allocator.alloc(u8, file_size);
    defer allocator.free(raw_bytes);
    _ = try std.Io.File.readPositionalAll(file, io, raw_bytes, 0);

    const all_samples = @as([]const f32, @alignCast(std.mem.bytesAsSlice(f32, raw_bytes)));
    const sample_rate: u32 = 44100;

    // Split into 3 equal parts (~7s each)
    const clip_len = all_samples.len / 3;
    const clips = [_][]const f32{
        all_samples[0..clip_len],
        all_samples[clip_len .. 2 * clip_len],
        all_samples[2 * clip_len ..],
    };

    const result = try analyze(allocator, &clips, sample_rate);

    std.debug.print("\n=== ARKOSE AUDIO ANALYSIS RESULT ===\n", .{});
    std.debug.print("Clip split: 21.133s → 3 × {d:.3}s\n", .{@as(f64, @floatFromInt(clip_len)) / @as(f64, sample_rate)});
    std.debug.print("Spectral flux deltas: [{d:.6}, {d:.6}, {d:.6}]\n", .{ result.deltas[0], result.deltas[1], result.deltas[2] });
    std.debug.print("Guess (highest delta clip): {d}\n", .{result.guess});
    std.debug.print("Execution time: {d} ms\n", .{result.execution_time_ms});

    // Also try the plan approach: first 12s split at 6s midpoint
    const plan_samples_12s: usize = sample_rate * 12;
    if (all_samples.len >= plan_samples_12s) {
        const plan_clip = all_samples[0..plan_samples_12s];
        const plan_result = try computeSpectralFlux(allocator, plan_clip, sample_rate);
        std.debug.print("\n--- Plan approach (12s, split at 6s) ---\n", .{});
        std.debug.print("Spectral flux (first vs second half): {d:.6}\n", .{plan_result});
    }

    // Validate: execution_time must be > 0
    try std.testing.expect(result.execution_time_ms > 0);
    try std.testing.expect(result.guess <= 2);
}
