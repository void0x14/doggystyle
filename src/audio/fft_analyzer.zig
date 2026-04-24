const std = @import("std");

const CLIP_COUNT: usize = 3;
const MAX_THREAD_SCRATCH_BYTES: usize = std.Thread.SpawnConfig.default_stack_size / 4;
const MAX_FFT_N: usize = MAX_THREAD_SCRATCH_BYTES / (@sizeOf(f32) * 2);

pub const Complex = struct {
    re: f32,
    im: f32,
};

pub const SpectralFluxResult = struct {
    guess: u8,
    execution_time_us: u64,
    deltas: [CLIP_COUNT]f64,
};

const ClipAnalysisContext = struct {
    clip: []const f32,
    sample_rate: u32,
    output: *[]f32,
    delta: *f64,
    failed: *std.atomic.Value(bool),
};

const AnalysisError = error{
    InvalidClip,
    FftTooLarge,
    OutputBufferTooSmall,
    ClipAnalysisFailed,
};

comptime {
    std.debug.assert(@sizeOf(Complex) == @sizeOf(f32) * 2);
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
                    @as(f32, @floatFromInt(j)) /
                    @as(f32, @floatFromInt(stage_len));
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
    const re: f64 = @floatCast(comp.re);
    const im: f64 = @floatCast(comp.im);
    return @sqrt(re * re + im * im);
}

// SOURCE: Blackman & Tukey, "The measurement of power spectra", 1958
fn hanningWindowValue(index: usize, length: usize) f32 {
    const inv = 1.0 / @as(f32, @floatFromInt(length - 1));
    const x = @as(f32, @floatFromInt(index));
    return 0.5 * (1.0 - std.math.cos(2.0 * std.math.pi * x * inv));
}

fn fftLenForClip(clip: []const f32, sample_rate: u32) AnalysisError!usize {
    const total_samples = clip.len;
    const mid_point = @min(@as(usize, sample_rate) * 6, total_samples / 2);
    if (mid_point == 0) return error.InvalidClip;

    const second_half_len = total_samples - mid_point;
    const fft_window_len = @min(mid_point, second_half_len);
    if (fft_window_len < 2) return error.InvalidClip;

    const fft_len_u64 = std.math.ceilPowerOfTwo(u64, fft_window_len) catch return error.FftTooLarge;
    const fft_len: usize = @intCast(fft_len_u64);
    if (fft_len > MAX_FFT_N) return error.FftTooLarge;
    return fft_len;
}

fn outputAsComplex(output: []f32, fft_len: usize) AnalysisError![]Complex {
    const needed = fft_len * 2;
    if (output.len < needed) return error.OutputBufferTooSmall;
    const bytes = std.mem.sliceAsBytes(output[0..needed]);
    return std.mem.bytesAsSlice(Complex, bytes);
}

// SOURCE: Scheirer & Slaney, "Construction and evaluation of a robust
// multifeature speech/music discriminator", 1997, IEEE ICASSP
fn computeSpectralFlux(scratch_allocator: std.mem.Allocator, clip: []const f32, sample_rate: u32, output: []f32) AnalysisError!f64 {
    const total_samples = clip.len;
    const mid_point = @min(@as(usize, sample_rate) * 6, total_samples / 2);
    if (mid_point == 0) return error.InvalidClip;

    const second_half_len = total_samples - mid_point;
    const fft_window_len = @min(mid_point, second_half_len);
    if (fft_window_len < 2) return error.InvalidClip;

    const fft_len = try fftLenForClip(clip, sample_rate);
    std.debug.assert(std.math.isPowerOfTwo(fft_len));
    const half_bins = fft_len / 2;

    const bands = [_]struct { start_hz: f64, end_hz: f64, weight: f64 }{
        .{ .start_hz = 0.0, .end_hz = 500.0, .weight = 0.15 },
        .{ .start_hz = 500.0, .end_hz = 2000.0, .weight = 0.35 },
        .{ .start_hz = 2000.0, .end_hz = 8000.0, .weight = 0.35 },
        .{ .start_hz = 8000.0, .end_hz = 22000.0, .weight = 0.15 },
    };
    const sample_rate_f = @as(f64, @floatFromInt(sample_rate));

    const window = scratch_allocator.alloc(f32, fft_window_len) catch return error.FftTooLarge;
    for (0..fft_window_len) |i| {
        window[i] = hanningWindowValue(i, fft_window_len);
    }

    const fft_buf = try outputAsComplex(output, fft_len);
    var first_half_energy = [_]f64{0.0} ** bands.len;

    @memset(fft_buf, Complex{ .re = 0.0, .im = 0.0 });
    for (0..fft_window_len) |i| {
        fft_buf[i] = Complex{ .re = clip[i] * window[i], .im = 0.0 };
    }
    fft(fft_buf);
    for (bands, 0..) |band, band_index| {
        const band_bin_start = @min(@as(usize, @intFromFloat(@as(f64, @floatFromInt(fft_len)) * band.start_hz / sample_rate_f)), half_bins - 1);
        const band_bin_end = @min(@as(usize, @intFromFloat(@as(f64, @floatFromInt(fft_len)) * band.end_hz / sample_rate_f)), half_bins);
        if (band_bin_end <= band_bin_start) return error.InvalidClip;

        for (band_bin_start..band_bin_end) |bin| {
            first_half_energy[band_index] += magnitude(fft_buf[bin]);
        }
    }

    @memset(fft_buf, Complex{ .re = 0.0, .im = 0.0 });
    for (0..fft_window_len) |i| {
        fft_buf[i] = Complex{ .re = clip[mid_point + i] * window[i], .im = 0.0 };
    }
    fft(fft_buf);

    var total_score: f64 = 0.0;
    for (bands, 0..) |band, band_index| {
        const band_bin_start = @min(@as(usize, @intFromFloat(@as(f64, @floatFromInt(fft_len)) * band.start_hz / sample_rate_f)), half_bins - 1);
        const band_bin_end = @min(@as(usize, @intFromFloat(@as(f64, @floatFromInt(fft_len)) * band.end_hz / sample_rate_f)), half_bins);
        if (band_bin_end <= band_bin_start) return error.InvalidClip;

        var second_half_energy: f64 = 0.0;
        for (band_bin_start..band_bin_end) |bin| {
            second_half_energy += magnitude(fft_buf[bin]);
        }

        const delta = @abs(second_half_energy - first_half_energy[band_index]) / (first_half_energy[band_index] + 1e-10);
        total_score += delta * band.weight;
    }

    return total_score;
}

fn analyzeClip(ctx: *ClipAnalysisContext) void {
    const fft_len = fftLenForClip(ctx.clip, ctx.sample_rate) catch {
        ctx.failed.store(true, .release);
        return;
    };
    const scratch_len = fft_len * @sizeOf(f32) * 2;
    if (scratch_len > MAX_THREAD_SCRATCH_BYTES) {
        ctx.failed.store(true, .release);
        return;
    }

    var scratch_storage: [MAX_THREAD_SCRATCH_BYTES]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(scratch_storage[0..scratch_len]);
    const delta = computeSpectralFlux(fixed.allocator(), ctx.clip, ctx.sample_rate, ctx.output.*) catch {
        ctx.failed.store(true, .release);
        return;
    };
    ctx.delta.* = delta;
}

fn monotonicNowNs() u128 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u128, @intCast(ts.sec)) * 1_000_000_000 + @as(u128, @intCast(ts.nsec));
}

// SOURCE: clock_gettime — man 2 clock_gettime, CLOCK_MONOTONIC
pub fn analyze(allocator: std.mem.Allocator, clips: []const []const f32, sample_rate: u32) !SpectralFluxResult {
    std.debug.assert(clips.len == CLIP_COUNT);

    const start_ns = monotonicNowNs();

    var output_buffers: [CLIP_COUNT][]f32 = undefined;
    var allocated_outputs: usize = 0;
    errdefer {
        for (output_buffers[0..allocated_outputs]) |buf| allocator.free(buf);
    }
    defer {
        for (output_buffers[0..allocated_outputs]) |buf| allocator.free(buf);
    }

    for (clips, 0..) |clip, i| {
        const fft_len = try fftLenForClip(clip, sample_rate);
        output_buffers[i] = try allocator.alloc(f32, fft_len * 2);
        allocated_outputs += 1;
    }

    var deltas: [CLIP_COUNT]f64 = [_]f64{0.0} ** CLIP_COUNT;
    var failed = std.atomic.Value(bool).init(false);
    var contexts: [CLIP_COUNT]ClipAnalysisContext = undefined;
    var threads: [CLIP_COUNT]std.Thread = undefined;
    var spawned_count: usize = 0;

    for (clips, 0..) |clip, i| {
        contexts[i] = .{
            .clip = clip,
            .sample_rate = sample_rate,
            .output = &output_buffers[i],
            .delta = &deltas[i],
            .failed = &failed,
        };
        threads[i] = std.Thread.spawn(.{}, analyzeClip, .{&contexts[i]}) catch |err| {
            for (threads[0..spawned_count]) |thread| thread.join();
            return err;
        };
        spawned_count += 1;
    }

    for (threads[0..spawned_count]) |thread| {
        thread.join();
    }

    const elapsed_ns = monotonicNowNs() - start_ns;
    const elapsed_us = @as(u64, @intCast(elapsed_ns / 1_000));

    if (failed.load(.acquire)) return error.ClipAnalysisFailed;

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
        .execution_time_us = elapsed_us,
        .deltas = deltas,
    };
}

// ---- Tests ----

test "fft_analyzer: Complex struct size" {
    try std.testing.expectEqual(@as(usize, @sizeOf(f32) * 2), @sizeOf(Complex));
}

test "fft_analyzer: FFT correctness (DC signal)" {
    const N = 8;
    var buffer: [N]Complex = undefined;
    for (&buffer) |*b| b.* = .{ .re = 1.0, .im = 0.0 };
    fft(&buffer);
    try std.testing.expectApproxEqAbs(@as(f32, 8.0), buffer[0].re, 1e-5);
    try std.testing.expectApproxEqAbs(@as(f32, 0.0), buffer[0].im, 1e-5);
    for (1..N) |i| {
        try std.testing.expectApproxEqAbs(@as(f32, 0.0), buffer[i].re, 1e-5);
        try std.testing.expectApproxEqAbs(@as(f32, 0.0), buffer[i].im, 1e-5);
    }
}

test "fft_analyzer: spectral flux with synthetic data" {
    const sample_rate: u32 = 100;
    var clip = try std.testing.allocator.alloc(f32, sample_rate * 12);
    defer std.testing.allocator.free(clip);
    const fft_len = try fftLenForClip(clip, sample_rate);
    const output = try std.testing.allocator.alloc(f32, fft_len * 2);
    defer std.testing.allocator.free(output);
    var scratch_storage: [MAX_THREAD_SCRATCH_BYTES]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&scratch_storage);

    for (0..sample_rate * 6) |i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        clip[i] = @as(f32, @floatCast(std.math.sin(2.0 * std.math.pi * 440.0 * t)));
    }
    for (sample_rate * 6..sample_rate * 12) |i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        clip[i] = @as(f32, @floatCast(std.math.sin(2.0 * std.math.pi * 880.0 * t)));
    }

    const flux = try computeSpectralFlux(fixed.allocator(), clip, sample_rate, output);
    try std.testing.expect(flux > 0.0);
}

test "fft_analyzer: spectral flux with identical halves" {
    const sample_rate: u32 = 100;
    var clip = try std.testing.allocator.alloc(f32, sample_rate * 12);
    defer std.testing.allocator.free(clip);
    const fft_len = try fftLenForClip(clip, sample_rate);
    const output = try std.testing.allocator.alloc(f32, fft_len * 2);
    defer std.testing.allocator.free(output);
    var scratch_storage: [MAX_THREAD_SCRATCH_BYTES]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&scratch_storage);

    for (0..sample_rate * 12) |i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        clip[i] = @as(f32, @floatCast(std.math.sin(2.0 * std.math.pi * 440.0 * t)));
    }

    const flux = try computeSpectralFlux(fixed.allocator(), clip, sample_rate, output);
    try std.testing.expect(flux < 0.01);
}

test "fft_analyzer: spectral flux includes low frequency band" {
    const sample_rate: u32 = 44100;
    const total_samples = sample_rate * 12;
    const mid = sample_rate * 6;
    var clip = try std.testing.allocator.alloc(f32, total_samples);
    defer std.testing.allocator.free(clip);
    const fft_len = try fftLenForClip(clip, sample_rate);
    const output = try std.testing.allocator.alloc(f32, fft_len * 2);
    defer std.testing.allocator.free(output);
    var scratch_storage: [MAX_THREAD_SCRATCH_BYTES]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&scratch_storage);

    for (0..total_samples) |i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        clip[i] = if (i < mid)
            @as(f32, @floatCast(@sin(2.0 * std.math.pi * 100.0 * t)))
        else
            @as(f32, @floatCast(2.0 * @sin(2.0 * std.math.pi * 100.0 * t)));
    }

    const flux = try computeSpectralFlux(fixed.allocator(), clip, sample_rate, output);
    try std.testing.expect(flux > 0.1);
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
    try std.testing.expect(result.execution_time_us > 0);
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
    std.debug.print("Clip split: 21.133s -> 3 x {d:.3}s\n", .{@as(f64, @floatFromInt(clip_len)) / @as(f64, sample_rate)});
    std.debug.print("Spectral flux deltas: [{d:.6}, {d:.6}, {d:.6}]\n", .{ result.deltas[0], result.deltas[1], result.deltas[2] });
    std.debug.print("Guess (highest delta clip): {d}\n", .{result.guess});
    std.debug.print("Execution time: {d} us\n", .{result.execution_time_us});

    // Also try the plan approach: first 12s split at 6s midpoint
    const plan_samples_12s: usize = sample_rate * 12;
    if (all_samples.len >= plan_samples_12s) {
        const plan_clip = all_samples[0..plan_samples_12s];
        const fft_len = try fftLenForClip(plan_clip, sample_rate);
        const output = try allocator.alloc(f32, fft_len * 2);
        defer allocator.free(output);
        var scratch_storage: [MAX_THREAD_SCRATCH_BYTES]u8 = undefined;
        var fixed = std.heap.FixedBufferAllocator.init(&scratch_storage);
        const plan_result = try computeSpectralFlux(fixed.allocator(), plan_clip, sample_rate, output);
        std.debug.print("\n--- Plan approach (12s, split at 6s) ---\n", .{});
        std.debug.print("Spectral flux (first vs second half): {d:.6}\n", .{plan_result});
    }

    // Validate: execution_time must be > 0
    try std.testing.expect(result.execution_time_us > 0);
    try std.testing.expect(result.guess <= 2);
}
