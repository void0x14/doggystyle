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

pub const ClipInput = struct { samples: []const f32, sample_rate: u32 };
pub const SemanticLabel = enum { water, bee, steps, speech, unknown, different };
pub const VADConfig = struct { announcement_skip_ms: u32 = 0, frame_ms: u32 = 10, min_active_frames: u32 = 3, snr_min: f64 = 3.0 };
pub const OutlierConfig = struct { vad: VADConfig = .{}, min_confidence: f64 = 0.15, ambiguous_score_threshold: f64 = 0.05, hardware_primary_margin: f64 = 0.20, quantization_tolerance: f64 = 0.1, low_freq_cutoff_hz: f64 = 500.0, optional_bit_depth: ?u8 = null };

// SOURCE: Measured from 45 Arkose "odd animal out" audio challenge files (2026-05-01)
// Audio structure: [silence][TTS announcer ~970ms][gap][clip1][gap][clip2][gap][clip3][trailing]
// Equal-thirds split PROVEN BROKEN: Split2 hits inside a segment in 91.1% of files.
// These defaults correctly isolated all 3 animal clips across all 45 test files.
pub const MultiSegmentConfig = struct {
    // Energy frame size — 30ms provides 33Hz temporal resolution for clips >=100ms
    // SOURCE: Digital audio processing convention; validated on 44100Hz Arkose files
    frame_ms: u32 = 30,
    // Energy fraction threshold: threshold = max_frame_energy * energy_fraction.
    // SOURCE: ANALIZ_RAPORU.md section 8.2 (2026-05-01) — quiet real clip measured near
    // ~2.5% of max_frame_energy, so 0.005 keeps the late quiet animal candidate alive.
    energy_fraction: f64 = 0.005,
    // Minimum segment duration — filters transient noise bursts.
    // SOURCE: ANALIZ_RAPORU.md section 8.2 (2026-05-01) — <200ms segments treated as noise.
    min_segment_ms: u32 = 200,
    // Maximum gap to merge into one segment — only bridge micro-silences/sample artifacts.
    // SOURCE: ANALIZ_RAPORU.md section 8.2 (2026-05-01).
    merge_gap_ms: u32 = 50,
    // Spectral centroid cutoff for speech/animal discrimination.
    // SOURCE: ANALIZ_RAPORU.md section 8.2 (2026-05-01) — TTS speech < 2100Hz.
    speech_centroid_cutoff_hz: f64 = 2100.0,
};
pub const DecisionMode = enum { hardware_primary, weighted_fallback, ambiguous };
pub const QuantizationGridSource = enum { caller_bit_depth, runtime_common_grid };

pub const ActiveRegion = struct { start: usize, end: usize, noise_frame_count: u32, active_frame_count: u32, active_rms: f64, noise_floor_rms: f64, snr_estimate: f64 };
pub const HardwareSignature = struct { dc_offset: f64, dc_window_std_dev: f64, dc_bias_confidence: f64, noise_floor_rms: f64, noise_floor_confidence: f64, quantization_uniformity: f64, crest_factor: f64, rms: f64 };
pub const AcousticSignature = struct { spectral_flux: f64, spectral_rolloff: f64, zero_crossing_rate: f64, harmonic_peak_ratio: f64, spectral_centroid: f64, narrowband_stability: f64, low_frequency_transient_energy: f64 };
pub const ClipFeatures = struct { active: ActiveRegion, hardware: HardwareSignature, acoustic: AcousticSignature };
pub const OutlierScore = struct { dc_offset_score: f64, noise_floor_score: f64, quantization_uniformity_score: f64, crest_factor_score: f64, rms_energy_score: f64, spectral_flux_score: f64, spectral_rolloff_score: f64, zero_crossing_rate_score: f64, harmonic_peak_score: f64, spectral_centroid_score: f64, narrowband_stability_score: f64, low_frequency_transient_score: f64 };
pub const OutlierDiagnostics = struct { dc_delta_ratios: [CLIP_COUNT]f64, selected_quantization_grid_scale: f64, quantization_grid_source: QuantizationGridSource, score_range: f64 };
pub const OutlierAnalysisResult = struct { guess: u8, execution_time_us: u64, features: [CLIP_COUNT]ClipFeatures, outlier_scores: [CLIP_COUNT]OutlierScore, hardware_scores: [CLIP_COUNT]f64, acoustic_scores: [CLIP_COUNT]f64, final_scores: [CLIP_COUNT]f64, confidence: f64, decision_mode: DecisionMode, diagnostics: OutlierDiagnostics };

const ClipAnalysisContext = struct {
    clip: []const f32,
    sample_rate: u32,
    output: *[]f32,
    delta: *f64,
    failed: *std.atomic.Value(bool),
};

const AnalysisError = error{
    InvalidClip,
    InvalidSampleRate,
    FftTooLarge,
    OutputBufferTooSmall,
    ClipAnalysisFailed,
    AmbiguousSignal,
    NoActiveSignal,
    // Returned by extractThreeLargestSegments when the audio contains fewer than
    // CLIP_COUNT usable energy segments after merging and filtering.
    // SOURCE: 45-file forensic analysis 2026-05-01 — all valid challenge files yield >= 3 segments
    InsufficientSegments,
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

fn msToSamples(ms: u32, sample_rate: u32) usize {
    return @as(usize, @intCast((@as(u64, ms) * @as(u64, sample_rate)) / 1000));
}

fn computeRangeRms(samples: []const f32, start: usize, end: usize) f64 {
    const bounded_start = @min(start, samples.len);
    const bounded_end = @min(@max(end, bounded_start), samples.len);
    if (bounded_end == bounded_start) return 0.0;

    var sum_sq: f64 = 0.0;
    for (samples[bounded_start..bounded_end]) |sample| {
        const value: f64 = @floatCast(sample);
        sum_sq += value * value;
    }
    return @sqrt(sum_sq / @as(f64, @floatFromInt(bounded_end - bounded_start)));
}

fn findActiveRegion(clip: []const f32, sample_rate: u32, config: VADConfig) AnalysisError!ActiveRegion {
    if (clip.len == 0) return error.InvalidClip;
    if (sample_rate == 0) return error.InvalidSampleRate;

    const frame_len = msToSamples(config.frame_ms, sample_rate);
    if (frame_len == 0) return error.InvalidSampleRate;
    const skip = @min(msToSamples(config.announcement_skip_ms, sample_rate), clip.len);
    const available = clip.len - skip;
    const frame_count = available / frame_len;
    if (frame_count == 0) return error.InvalidClip;

    var min_energy = std.math.inf(f64);
    var max_energy: f64 = 0.0;
    for (0..frame_count) |frame_index| {
        const start = skip + frame_index * frame_len;
        const end = start + frame_len;
        const frame_rms = computeRangeRms(clip, start, end);
        const frame_energy = frame_rms * frame_rms;
        min_energy = @min(min_energy, frame_energy);
        max_energy = @max(max_energy, frame_energy);
    }

    const snr_energy_multiplier = config.snr_min * config.snr_min;
    const threshold_energy = @max(min_energy * snr_energy_multiplier, min_energy + (max_energy - min_energy) * 0.25);
    var best_start_frame: usize = 0;
    var best_frame_count: u32 = 0;
    var run_start_frame: usize = 0;
    var run_frame_count: u32 = 0;
    var noise_frame_count: u32 = 0;
    var noise_sum_energy: f64 = 0.0;
    var noise_sample_count: usize = 0;

    for (0..frame_count) |frame_index| {
        const start = skip + frame_index * frame_len;
        const end = start + frame_len;
        const frame_rms = computeRangeRms(clip, start, end);
        const frame_energy = frame_rms * frame_rms;
        if (frame_energy >= threshold_energy) {
            if (run_frame_count == 0) run_start_frame = frame_index;
            run_frame_count += 1;
        } else {
            noise_frame_count += 1;
            noise_sum_energy += frame_energy * @as(f64, @floatFromInt(frame_len));
            noise_sample_count += frame_len;
            if (run_frame_count > best_frame_count) {
                best_start_frame = run_start_frame;
                best_frame_count = run_frame_count;
            }
            run_frame_count = 0;
        }
    }
    if (run_frame_count > best_frame_count) {
        best_start_frame = run_start_frame;
        best_frame_count = run_frame_count;
    }
    if (best_frame_count < config.min_active_frames) return error.NoActiveSignal;

    const active_start = skip + best_start_frame * frame_len;
    const active_end = active_start + @as(usize, best_frame_count) * frame_len;
    const active_rms = computeRangeRms(clip, active_start, active_end);
    const noise_floor_energy = if (noise_sample_count == 0) min_energy else noise_sum_energy / @as(f64, @floatFromInt(noise_sample_count));
    const noise_floor_rms = @sqrt(noise_floor_energy);
    if (noise_floor_rms <= 0.0 and active_rms <= 0.0) return error.NoActiveSignal;
    const snr_estimate = if (noise_floor_rms <= 0.0) std.math.inf(f64) else active_rms / noise_floor_rms;
    if (snr_estimate < config.snr_min) return error.NoActiveSignal;

    return ActiveRegion{
        .start = active_start,
        .end = active_end,
        .noise_frame_count = noise_frame_count,
        .active_frame_count = best_frame_count,
        .active_rms = active_rms,
        .noise_floor_rms = noise_floor_rms,
        .snr_estimate = snr_estimate,
    };
}

fn wholeClipActiveRegion(clip: []const f32, sample_rate: u32, config: VADConfig) AnalysisError!ActiveRegion {
    if (clip.len == 0) return error.InvalidClip;
    if (sample_rate == 0) return error.InvalidSampleRate;

    const frame_len = msToSamples(config.frame_ms, sample_rate);
    if (frame_len == 0) return error.InvalidSampleRate;
    const skip = @min(msToSamples(config.announcement_skip_ms, sample_rate), clip.len);
    if (skip >= clip.len) return error.NoActiveSignal;

    const active_rms = computeRangeRms(clip, skip, clip.len);
    if (active_rms <= 0.0) return error.NoActiveSignal;
    const frame_count = @max(@as(usize, 1), (clip.len - skip) / frame_len);

    return .{
        .start = skip,
        .end = clip.len,
        .noise_frame_count = 0,
        .active_frame_count = @intCast(@min(frame_count, std.math.maxInt(u32))),
        .active_rms = active_rms,
        .noise_floor_rms = active_rms,
        .snr_estimate = 1.0,
    };
}

fn computeHardwareWithoutQuantization(clip: []const f32, active: ActiveRegion) AnalysisError!HardwareSignature {
    if (active.end <= active.start or active.end > clip.len) return error.InvalidClip;
    const active_len = active.end - active.start;
    if (active_len < 5) return error.NoActiveSignal;

    const rms = computeRangeRms(clip, active.start, active.end);
    var sum: f64 = 0.0;
    var max_abs: f64 = 0.0;
    for (clip[active.start..active.end]) |sample| {
        const value: f64 = @floatCast(sample);
        sum += value;
        max_abs = @max(max_abs, @abs(value));
    }
    const dc_offset = sum / @as(f64, @floatFromInt(active_len));
    const crest_factor = if (rms == 0.0) 0.0 else max_abs / rms;

    const target_window_count = @min(@as(usize, 64), @max(@as(usize, 5), active_len / 1024));
    const window_count = @min(target_window_count, active_len);
    var window_means: [64]f64 = undefined;
    var positive_count: u32 = 0;
    var negative_count: u32 = 0;
    for (0..window_count) |window_index| {
        const start = active.start + (active_len * window_index) / window_count;
        const end = active.start + (active_len * (window_index + 1)) / window_count;
        var window_sum: f64 = 0.0;
        for (clip[start..end]) |sample| window_sum += @as(f64, @floatCast(sample));
        const mean = if (end == start) 0.0 else window_sum / @as(f64, @floatFromInt(end - start));
        window_means[window_index] = mean;
        if (mean >= 0.0) positive_count += 1 else negative_count += 1;
    }

    var variance_sum: f64 = 0.0;
    for (window_means[0..window_count]) |mean| {
        const delta = mean - dc_offset;
        variance_sum += delta * delta;
    }
    const dc_window_std_dev = @sqrt(variance_sum / @as(f64, @floatFromInt(window_count)));
    const dominant_sign_count = @max(positive_count, negative_count);
    const sign_consistency = @as(f64, @floatFromInt(dominant_sign_count)) / @as(f64, @floatFromInt(window_count));
    const window_count_factor = @min(@as(f64, 1.0), @as(f64, @floatFromInt(window_count)) / 5.0);
    const variance_factor = 1.0 / (1.0 + dc_window_std_dev / (@abs(dc_offset) + 1e-12));
    const dc_bias_confidence = @min(@as(f64, 1.0), window_count_factor * variance_factor * sign_consistency);
    const noise_floor_confidence = @min(@as(f64, 1.0), @as(f64, @floatFromInt(active.noise_frame_count)) / 5.0);

    return HardwareSignature{
        .dc_offset = dc_offset,
        .dc_window_std_dev = dc_window_std_dev,
        .dc_bias_confidence = dc_bias_confidence,
        .noise_floor_rms = active.noise_floor_rms,
        .noise_floor_confidence = noise_floor_confidence,
        .quantization_uniformity = 0.0,
        .crest_factor = crest_factor,
        .rms = rms,
    };
}

fn quantizationFractionWithin(clip: []const f32, active: ActiveRegion, grid_scale: f64, tolerance: f64) f64 {
    if (grid_scale <= 0.0 or tolerance < 0.0) return 0.0;
    if (active.end <= active.start or active.end > clip.len) return 0.0;

    var within_count: usize = 0;
    var inspected_count: usize = 0;
    for (clip[active.start..active.end]) |sample| {
        const scaled = @as(f64, @floatCast(sample)) * grid_scale;
        const residual = @abs(scaled - @round(scaled));
        if (residual <= tolerance) within_count += 1;
        inspected_count += 1;
    }
    if (inspected_count == 0) return 0.0;
    return @as(f64, @floatFromInt(within_count)) / @as(f64, @floatFromInt(inspected_count));
}

fn bitDepthGridScale(bit_depth: u8) AnalysisError!f64 {
    if (bit_depth == 0 or bit_depth > 30) return error.InvalidClip;
    const levels = (@as(u64, 1) << @intCast(bit_depth)) - 1;
    return @floatFromInt(levels);
}

fn applyQuantizationGrid(clips: []const ClipInput, features: *[CLIP_COUNT]ClipFeatures, grid_scale: f64, tolerance: f64) void {
    for (0..CLIP_COUNT) |i| {
        features[i].hardware.quantization_uniformity = quantizationFractionWithin(clips[i].samples, features[i].active, grid_scale, tolerance);
    }
}

fn chooseCommonQuantizationGrid(clips: []const ClipInput, features: *[CLIP_COUNT]ClipFeatures, config: OutlierConfig) AnalysisError!struct { scale: f64, source: QuantizationGridSource } {
    if (clips.len != CLIP_COUNT) return error.InvalidClip;
    if (config.optional_bit_depth) |bit_depth| {
        const scale = try bitDepthGridScale(bit_depth);
        applyQuantizationGrid(clips, features, scale, config.quantization_tolerance);
        return .{ .scale = scale, .source = .caller_bit_depth };
    }

    var best_scale: f64 = 2.0;
    var best_sum: f64 = -1.0;
    var scale_int: usize = 2;
    while (scale_int <= 256) : (scale_int += 1) {
        const scale: f64 = @floatFromInt(scale_int);
        var sum: f64 = 0.0;
        for (0..CLIP_COUNT) |i| {
            sum += quantizationFractionWithin(clips[i].samples, features[i].active, scale, config.quantization_tolerance);
        }
        if (sum > best_sum) {
            best_sum = sum;
            best_scale = scale;
        }
    }
    const common_scales = [_]f64{ 511.0, 1023.0, 2047.0, 4095.0, 8191.0, 16383.0, 32767.0, 65535.0 };
    for (common_scales) |scale| {
        var sum: f64 = 0.0;
        for (0..CLIP_COUNT) |i| {
            sum += quantizationFractionWithin(clips[i].samples, features[i].active, scale, config.quantization_tolerance);
        }
        if (sum > best_sum) {
            best_sum = sum;
            best_scale = scale;
        }
    }

    applyQuantizationGrid(clips, features, best_scale, config.quantization_tolerance);
    return .{ .scale = best_scale, .source = .runtime_common_grid };
}

fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    for (0..haystack.len - needle.len + 1) |start| {
        var matched = true;
        for (needle, 0..) |needle_char, offset| {
            if (std.ascii.toLower(haystack[start + offset]) != std.ascii.toLower(needle_char)) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }
    return false;
}

pub fn semanticLabelFromText(text: []const u8) SemanticLabel {
    if (containsAsciiIgnoreCase(text, "water")) return .water;
    if (containsAsciiIgnoreCase(text, "bee") or containsAsciiIgnoreCase(text, "buzz")) return .bee;
    if (containsAsciiIgnoreCase(text, "step") or containsAsciiIgnoreCase(text, "footstep")) return .steps;
    if (containsAsciiIgnoreCase(text, "talk") or
        containsAsciiIgnoreCase(text, "speaking") or
        containsAsciiIgnoreCase(text, "person talking") or
        containsAsciiIgnoreCase(text, "voice") or
        containsAsciiIgnoreCase(text, "drum") or
        containsAsciiIgnoreCase(text, "music")) return .speech;
    if (containsAsciiIgnoreCase(text, "different") or containsAsciiIgnoreCase(text, "odd")) return .different;
    return .unknown;
}

fn acousticFftLen(active_len: usize) AnalysisError!usize {
    if (active_len < 16) return error.InvalidClip;
    if (active_len >= 8192) return 2048;
    if (active_len >= 2048) return 1024;
    var len: usize = 8;
    while (len * 2 <= active_len / 2 and len < 1024) len *= 2;
    return len;
}

fn computeZeroCrossingRate(clip: []const f32, active: ActiveRegion) f64 {
    if (active.end <= active.start + 1) return 0.0;
    var crossings: usize = 0;
    var prev = clip[active.start];
    for (clip[active.start + 1 .. active.end]) |sample| {
        if ((prev < 0.0 and sample >= 0.0) or (prev >= 0.0 and sample < 0.0)) crossings += 1;
        prev = sample;
    }
    return @as(f64, @floatFromInt(crossings)) / @as(f64, @floatFromInt(active.end - active.start - 1));
}

fn computeAcousticSignature(clip: []const f32, active: ActiveRegion, sample_rate: u32, config: OutlierConfig) AnalysisError!AcousticSignature {
    if (sample_rate == 0) return error.InvalidSampleRate;
    if (active.end <= active.start or active.end > clip.len) return error.InvalidClip;
    const active_len = active.end - active.start;
    const fft_len = try acousticFftLen(active_len);
    if (fft_len > 2048) return error.FftTooLarge;
    const half_bins = fft_len / 2;
    if (half_bins == 0) return error.InvalidClip;

    const frame_count: usize = @min(@as(usize, 4), active_len / fft_len);
    if (frame_count < 2) return error.InvalidClip;

    var fft_buf: [2048]Complex = undefined;
    var prev_spectrum: [1024]f64 = [_]f64{0.0} ** 1024;
    var curr_spectrum: [1024]f64 = [_]f64{0.0} ** 1024;
    var flux_sum: f64 = 0.0;
    var flux_count: usize = 0;
    var centroid_sum: f64 = 0.0;
    var rolloff_sum: f64 = 0.0;
    var harmonic_peak_sum: f64 = 0.0;
    var low_frequency_ratios: [4]f64 = [_]f64{0.0} ** 4;
    var peak_bins: [4]usize = [_]usize{0} ** 4;
    const sample_rate_f: f64 = @floatFromInt(sample_rate);

    for (0..frame_count) |frame_index| {
        @memset(fft_buf[0..fft_len], Complex{ .re = 0.0, .im = 0.0 });
        const frame_start = if (frame_count == 1) active.start else active.start + ((active_len - fft_len) * frame_index) / (frame_count - 1);
        for (0..fft_len) |i| {
            fft_buf[i] = .{ .re = clip[frame_start + i] * hanningWindowValue(i, fft_len), .im = 0.0 };
        }
        fft(fft_buf[0..fft_len]);

        var total_energy: f64 = 0.0;
        var weighted_frequency_sum: f64 = 0.0;
        var max_magnitude: f64 = 0.0;
        var peak_bin: usize = 0;
        var low_frequency_energy: f64 = 0.0;
        for (0..half_bins) |bin| {
            const mag = magnitude(fft_buf[bin]);
            curr_spectrum[bin] = mag;
            total_energy += mag;
            const frequency = sample_rate_f * @as(f64, @floatFromInt(bin)) / @as(f64, @floatFromInt(fft_len));
            weighted_frequency_sum += mag * frequency;
            if (frequency <= config.low_freq_cutoff_hz) low_frequency_energy += mag;
            if (mag > max_magnitude) {
                max_magnitude = mag;
                peak_bin = bin;
            }
        }
        peak_bins[frame_index] = peak_bin;
        if (total_energy > 0.0) {
            centroid_sum += weighted_frequency_sum / total_energy;
            harmonic_peak_sum += max_magnitude / total_energy;
            low_frequency_ratios[frame_index] = low_frequency_energy / total_energy;
            const rolloff_target = total_energy * 0.85;
            var cumulative: f64 = 0.0;
            var rolloff_bin: usize = half_bins - 1;
            for (0..half_bins) |bin| {
                cumulative += curr_spectrum[bin];
                if (cumulative >= rolloff_target) {
                    rolloff_bin = bin;
                    break;
                }
            }
            rolloff_sum += sample_rate_f * @as(f64, @floatFromInt(rolloff_bin)) / @as(f64, @floatFromInt(fft_len));
            if (frame_index > 0) {
                var frame_flux: f64 = 0.0;
                for (0..half_bins) |bin| {
                    const prev_norm = prev_spectrum[bin];
                    const curr_norm = curr_spectrum[bin] / total_energy;
                    frame_flux += @abs(curr_norm - prev_norm);
                    prev_spectrum[bin] = curr_norm;
                }
                flux_sum += frame_flux;
                flux_count += 1;
            } else {
                for (0..half_bins) |bin| prev_spectrum[bin] = curr_spectrum[bin] / total_energy;
            }
        }
    }

    var dominant_count: usize = 0;
    for (peak_bins[0..frame_count]) |candidate| {
        var count: usize = 0;
        for (peak_bins[0..frame_count]) |bin| {
            if (bin == candidate) count += 1;
        }
        dominant_count = @max(dominant_count, count);
    }
    const peak_consistency = @as(f64, @floatFromInt(dominant_count)) / @as(f64, @floatFromInt(frame_count));
    const harmonic_peak_ratio = harmonic_peak_sum / @as(f64, @floatFromInt(frame_count));
    var low_frequency_transient_energy: f64 = 0.0;
    for (1..frame_count) |i| {
        low_frequency_transient_energy += @abs(low_frequency_ratios[i] - low_frequency_ratios[i - 1]);
    }
    low_frequency_transient_energy /= @as(f64, @floatFromInt(frame_count - 1));

    return AcousticSignature{
        .spectral_flux = if (flux_count == 0) 0.0 else flux_sum / @as(f64, @floatFromInt(flux_count)),
        .spectral_rolloff = rolloff_sum / @as(f64, @floatFromInt(frame_count)),
        .zero_crossing_rate = computeZeroCrossingRate(clip, active),
        .harmonic_peak_ratio = harmonic_peak_ratio,
        .spectral_centroid = centroid_sum / @as(f64, @floatFromInt(frame_count)),
        .narrowband_stability = @min(@as(f64, 1.0), peak_consistency * harmonic_peak_ratio * 4.0),
        .low_frequency_transient_energy = low_frequency_transient_energy,
    };
}

const DIFFERENT_PROFILE_BANDS = [_]struct { start_hz: f64, end_hz: f64 }{
    .{ .start_hz = 0.0, .end_hz = 500.0 },
    .{ .start_hz = 500.0, .end_hz = 1200.0 },
    .{ .start_hz = 1200.0, .end_hz = 2000.0 },
    .{ .start_hz = 2000.0, .end_hz = 3200.0 },
    .{ .start_hz = 3200.0, .end_hz = 4500.0 },
    .{ .start_hz = 4500.0, .end_hz = 6500.0 },
    .{ .start_hz = 6500.0, .end_hz = 9000.0 },
    .{ .start_hz = 9000.0, .end_hz = 12000.0 },
};

fn computeDifferentProfile(clip: []const f32, active: ActiveRegion, sample_rate: u32) AnalysisError![DIFFERENT_PROFILE_BANDS.len]f64 {
    if (sample_rate == 0) return error.InvalidSampleRate;
    if (active.end <= active.start or active.end > clip.len) return error.InvalidClip;

    const active_len = active.end - active.start;
    const fft_len = try acousticFftLen(active_len);
    if (fft_len > 2048) return error.FftTooLarge;
    const half_bins = fft_len / 2;
    if (half_bins == 0) return error.InvalidClip;

    const frame_count: usize = @min(@as(usize, 4), active_len / fft_len);
    if (frame_count == 0) return error.InvalidClip;

    var fft_buf: [2048]Complex = undefined;
    var profile = [_]f64{0.0} ** DIFFERENT_PROFILE_BANDS.len;
    const sample_rate_f: f64 = @floatFromInt(sample_rate);

    for (0..frame_count) |frame_index| {
        @memset(fft_buf[0..fft_len], Complex{ .re = 0.0, .im = 0.0 });
        const frame_start = if (frame_count == 1) active.start else active.start + ((active_len - fft_len) * frame_index) / @max(frame_count - 1, 1);
        for (0..fft_len) |i| {
            fft_buf[i] = .{ .re = clip[frame_start + i] * hanningWindowValue(i, fft_len), .im = 0.0 };
        }
        fft(fft_buf[0..fft_len]);

        var total_energy: f64 = 0.0;
        var band_energy = [_]f64{0.0} ** DIFFERENT_PROFILE_BANDS.len;
        for (0..half_bins) |bin| {
            const mag = magnitude(fft_buf[bin]);
            const freq = sample_rate_f * @as(f64, @floatFromInt(bin)) / @as(f64, @floatFromInt(fft_len));
            total_energy += mag;
            for (DIFFERENT_PROFILE_BANDS, 0..) |band, band_index| {
                if (freq >= band.start_hz and freq < band.end_hz) {
                    band_energy[band_index] += mag;
                    break;
                }
            }
        }

        if (total_energy > 0.0) {
            for (0..DIFFERENT_PROFILE_BANDS.len) |i| {
                profile[i] += band_energy[i] / total_energy;
            }
        }
    }

    for (0..DIFFERENT_PROFILE_BANDS.len) |i| {
        profile[i] /= @as(f64, @floatFromInt(frame_count));
    }
    return profile;
}

fn cosineDistanceProfile(a: [DIFFERENT_PROFILE_BANDS.len]f64, b: [DIFFERENT_PROFILE_BANDS.len]f64) f64 {
    var dot: f64 = 0.0;
    var norm_a: f64 = 0.0;
    var norm_b: f64 = 0.0;
    for (0..DIFFERENT_PROFILE_BANDS.len) |i| {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    if (norm_a <= 0.0 or norm_b <= 0.0) return 1.0;
    const cosine = dot / (@sqrt(norm_a) * @sqrt(norm_b));
    return 1.0 - cosine;
}

fn computeDifferentPairScores(clips: []const ClipInput, features: [CLIP_COUNT]ClipFeatures) AnalysisError![CLIP_COUNT]f64 {
    var profiles: [CLIP_COUNT][DIFFERENT_PROFILE_BANDS.len]f64 = undefined;
    for (clips, 0..) |clip, i| {
        profiles[i] = try computeDifferentProfile(clip.samples, features[i].active, clip.sample_rate);
    }

    const d01 = cosineDistanceProfile(profiles[0], profiles[1]);
    const d02 = cosineDistanceProfile(profiles[0], profiles[2]);
    const d12 = cosineDistanceProfile(profiles[1], profiles[2]);

    var scores = [_]f64{0.0} ** CLIP_COUNT;
    if (d01 <= d02 and d01 <= d12) {
        scores[2] = @max(d02, d12) - d01;
    } else if (d02 <= d01 and d02 <= d12) {
        scores[1] = @max(d01, d12) - d02;
    } else {
        scores[0] = @max(d01, d02) - d12;
    }
    return scores;
}

fn median3(values: [CLIP_COUNT]f64) f64 {
    var sorted = values;
    if (sorted[0] > sorted[1]) std.mem.swap(f64, &sorted[0], &sorted[1]);
    if (sorted[1] > sorted[2]) std.mem.swap(f64, &sorted[1], &sorted[2]);
    if (sorted[0] > sorted[1]) std.mem.swap(f64, &sorted[0], &sorted[1]);
    return sorted[1];
}

fn maxAdScores(values: [CLIP_COUNT]f64) [CLIP_COUNT]f64 {
    const center = median3(values);
    var deviations: [CLIP_COUNT]f64 = undefined;
    var max_deviation: f64 = 0.0;
    for (values, 0..) |value, i| {
        deviations[i] = @abs(value - center);
        max_deviation = @max(max_deviation, deviations[i]);
    }
    if (max_deviation == 0.0) return [_]f64{0.0} ** CLIP_COUNT;
    var scores: [CLIP_COUNT]f64 = undefined;
    for (deviations, 0..) |deviation, i| scores[i] = deviation / max_deviation;
    return scores;
}

fn computeDcDeltaRatios(features: [CLIP_COUNT]ClipFeatures) [CLIP_COUNT]f64 {
    var ratios: [CLIP_COUNT]f64 = undefined;
    for (0..CLIP_COUNT) |i| {
        var peer_sum: f64 = 0.0;
        for (0..CLIP_COUNT) |j| {
            if (i != j) peer_sum += features[j].hardware.dc_offset;
        }
        const peer_mean = peer_sum / @as(f64, @floatFromInt(CLIP_COUNT - 1));
        ratios[i] = @abs(features[i].hardware.dc_offset - peer_mean) / (@abs(peer_mean) + 1e-12);
    }
    return ratios;
}

fn computeOutlierScores(features: [CLIP_COUNT]ClipFeatures) [CLIP_COUNT]OutlierScore {
    var dc_offset_values: [CLIP_COUNT]f64 = undefined;
    var noise_floor_values: [CLIP_COUNT]f64 = undefined;
    var quantization_values: [CLIP_COUNT]f64 = undefined;
    var crest_values: [CLIP_COUNT]f64 = undefined;
    var rms_values: [CLIP_COUNT]f64 = undefined;
    var flux_values: [CLIP_COUNT]f64 = undefined;
    var rolloff_values: [CLIP_COUNT]f64 = undefined;
    var zcr_values: [CLIP_COUNT]f64 = undefined;
    var harmonic_values: [CLIP_COUNT]f64 = undefined;
    var centroid_values: [CLIP_COUNT]f64 = undefined;
    var narrowband_values: [CLIP_COUNT]f64 = undefined;
    var low_frequency_values: [CLIP_COUNT]f64 = undefined;
    for (features, 0..) |feature, i| {
        dc_offset_values[i] = feature.hardware.dc_offset;
        noise_floor_values[i] = feature.hardware.noise_floor_rms;
        quantization_values[i] = feature.hardware.quantization_uniformity;
        crest_values[i] = feature.hardware.crest_factor;
        rms_values[i] = feature.hardware.rms;
        flux_values[i] = feature.acoustic.spectral_flux;
        rolloff_values[i] = feature.acoustic.spectral_rolloff;
        zcr_values[i] = feature.acoustic.zero_crossing_rate;
        harmonic_values[i] = feature.acoustic.harmonic_peak_ratio;
        centroid_values[i] = feature.acoustic.spectral_centroid;
        narrowband_values[i] = feature.acoustic.narrowband_stability;
        low_frequency_values[i] = feature.acoustic.low_frequency_transient_energy;
    }

    const dc_scores = maxAdScores(dc_offset_values);
    const noise_scores = maxAdScores(noise_floor_values);
    const quantization_scores = maxAdScores(quantization_values);
    const crest_scores = maxAdScores(crest_values);
    const rms_scores = maxAdScores(rms_values);
    const flux_scores = maxAdScores(flux_values);
    const rolloff_scores = maxAdScores(rolloff_values);
    const zcr_scores = maxAdScores(zcr_values);
    const harmonic_scores = maxAdScores(harmonic_values);
    const centroid_scores = maxAdScores(centroid_values);
    const narrowband_scores = maxAdScores(narrowband_values);
    const low_frequency_scores = maxAdScores(low_frequency_values);

    var scores: [CLIP_COUNT]OutlierScore = undefined;
    for (0..CLIP_COUNT) |i| {
        scores[i] = .{
            .dc_offset_score = dc_scores[i],
            .noise_floor_score = noise_scores[i],
            .quantization_uniformity_score = quantization_scores[i],
            .crest_factor_score = crest_scores[i],
            .rms_energy_score = rms_scores[i],
            .spectral_flux_score = flux_scores[i],
            .spectral_rolloff_score = rolloff_scores[i],
            .zero_crossing_rate_score = zcr_scores[i],
            .harmonic_peak_score = harmonic_scores[i],
            .spectral_centroid_score = centroid_scores[i],
            .narrowband_stability_score = narrowband_scores[i],
            .low_frequency_transient_score = low_frequency_scores[i],
        };
    }
    return scores;
}

fn computeDispatcherScores(clips: []const ClipInput, features: [CLIP_COUNT]ClipFeatures, label: SemanticLabel) AnalysisError![CLIP_COUNT]f64 {
    var values: [CLIP_COUNT]f64 = undefined;
    switch (label) {
        .water => {
            for (features, 0..) |f, i| values[i] = f.acoustic.spectral_centroid;
            return maxAdScores(values);
        },
        .bee => {
            for (features, 0..) |f, i| values[i] = f.acoustic.harmonic_peak_ratio + f.acoustic.narrowband_stability;
            return maxAdScores(values);
        },
        .steps => {
            for (features, 0..) |f, i| values[i] = f.acoustic.low_frequency_transient_energy;
            return maxAdScores(values);
        },
        .speech => {
            for (features, 0..) |f, i| values[i] = f.acoustic.spectral_flux + f.acoustic.zero_crossing_rate + f.acoustic.low_frequency_transient_energy;
            return maxAdScores(values);
        },
        .different => {
            return try computeDifferentPairScores(clips, features);
        },
        .unknown => {
            const flux = [_]f64{ features[0].acoustic.spectral_flux, features[1].acoustic.spectral_flux, features[2].acoustic.spectral_flux };
            const centroid = [_]f64{ features[0].acoustic.spectral_centroid, features[1].acoustic.spectral_centroid, features[2].acoustic.spectral_centroid };
            const zcr = [_]f64{ features[0].acoustic.zero_crossing_rate, features[1].acoustic.zero_crossing_rate, features[2].acoustic.zero_crossing_rate };
            const harmonic = [_]f64{ features[0].acoustic.harmonic_peak_ratio, features[1].acoustic.harmonic_peak_ratio, features[2].acoustic.harmonic_peak_ratio };
            const rolloff = [_]f64{ features[0].acoustic.spectral_rolloff, features[1].acoustic.spectral_rolloff, features[2].acoustic.spectral_rolloff };
            const narrowband = [_]f64{ features[0].acoustic.narrowband_stability, features[1].acoustic.narrowband_stability, features[2].acoustic.narrowband_stability };
            const lowfreq = [_]f64{ features[0].acoustic.low_frequency_transient_energy, features[1].acoustic.low_frequency_transient_energy, features[2].acoustic.low_frequency_transient_energy };

            const flux_scores = maxAdScores(flux);
            const centroid_scores = maxAdScores(centroid);
            const zcr_scores = maxAdScores(zcr);
            const harmonic_scores = maxAdScores(harmonic);
            const rolloff_scores = maxAdScores(rolloff);
            const narrowband_scores = maxAdScores(narrowband);
            const lowfreq_scores = maxAdScores(lowfreq);

            for (0..CLIP_COUNT) |i| {
                values[i] = flux_scores[i] + centroid_scores[i] + zcr_scores[i] + harmonic_scores[i] + rolloff_scores[i] + narrowband_scores[i] + lowfreq_scores[i];
            }
            return values;
        },
    }
}

fn bestIndexAndMargin(values: [CLIP_COUNT]f64) struct { index: u8, margin: f64, range: f64 } {
    var best_index: usize = 0;
    var best_value = values[0];
    var second_value = -std.math.inf(f64);
    var min_value = values[0];
    for (values, 0..) |value, i| {
        min_value = @min(min_value, value);
        if (value > best_value) {
            second_value = best_value;
            best_value = value;
            best_index = i;
        } else if (i != best_index and value > second_value) {
            second_value = value;
        }
    }
    return .{ .index = @intCast(best_index), .margin = best_value - second_value, .range = best_value - min_value };
}

pub fn analyzeOutlier(clips: []const ClipInput, label: SemanticLabel, config: OutlierConfig) !OutlierAnalysisResult {
    if (clips.len != CLIP_COUNT) return error.InvalidClip;
    const start_ns = monotonicNowNs();

    var features: [CLIP_COUNT]ClipFeatures = undefined;
    for (clips, 0..) |clip, i| {
        if (clip.samples.len == 0) return error.InvalidClip;
        if (clip.sample_rate == 0) return error.InvalidSampleRate;
        const active = findActiveRegion(clip.samples, clip.sample_rate, config.vad) catch |err| switch (err) {
            error.NoActiveSignal => try wholeClipActiveRegion(clip.samples, clip.sample_rate, config.vad),
            else => return err,
        };
        const hardware = try computeHardwareWithoutQuantization(clip.samples, active);
        const acoustic = try computeAcousticSignature(clip.samples, active, clip.sample_rate, config);
        features[i] = .{ .active = active, .hardware = hardware, .acoustic = acoustic };
    }

    const grid = try chooseCommonQuantizationGrid(clips, &features, config);
    const outlier_scores = computeOutlierScores(features);
    const dispatcher_scores = try computeDispatcherScores(clips, features, label);
    const best = bestIndexAndMargin(dispatcher_scores);
    const decision_mode: DecisionMode = .weighted_fallback;
    const guess = best.index + 1;
    const confidence = best.margin;
    const score_range = best.range;
    const effective_min_confidence = if (label == .different) 0.05 else config.min_confidence;
    const effective_ambiguous_threshold = if (label == .different) 0.01 else config.ambiguous_score_threshold;
    if (score_range <= effective_ambiguous_threshold or confidence < effective_min_confidence) return error.AmbiguousSignal;

    return .{
        .guess = guess,
        .execution_time_us = @intCast((monotonicNowNs() - start_ns) / 1_000),
        .features = features,
        .outlier_scores = outlier_scores,
        .hardware_scores = .{0.0} ** CLIP_COUNT,
        .acoustic_scores = dispatcher_scores,
        .final_scores = dispatcher_scores,
        .confidence = confidence,
        .decision_mode = decision_mode,
        .diagnostics = .{
            .dc_delta_ratios = computeDcDeltaRatios(features),
            .selected_quantization_grid_scale = grid.scale,
            .quantization_grid_source = grid.source,
            .score_range = score_range,
        },
    };
}

// Internal maximum for segment tracking scratch buffer.
// SOURCE: 45-file forensic analysis 2026-05-01 — max observed raw segments per file = 6.
// 32 provides ample headroom for pathological audio without heap allocation.
const MAX_SEGMENTS: usize = 32;

// SegmentBound holds start/end sample indices into the caller's sample buffer.
// Lifetime: slice is valid only as long as the source samples slice is alive.
const SegmentBound = struct { start: usize, end: usize };

const SegmentCandidate = struct {
    bound: SegmentBound,
    duration_samples: usize,
    centroid_hz: f64,
    speech_penalty: f64,
};

// SOURCE: Measured from Arkose audio challenge files (2026-05-01) — multiple sessions
//
// PROVEN PROBLEMS:
//
// P1 (equal-thirds split): Split2 hit inside a segment in 91.1% of files.
//
// P2 (segment-level centroid): Merging ALL active frames first, then computing centroid
//   per merged segment fails when:
//   a) TTS speech labels are < merge_gap apart from animal clips (e.g. 360ms gap — same size as
//      internal clip silences), so speech and clip merge into one blob.
//   b) energy_fraction=0.05 misses quieter animal clips (Option 2 in session 1 was at -25dB
//      while loudest clip at -15dB — ratio ~10% but threshold was 5% of max_frame_energy,
//      causing the quiet clip to fall below threshold and be completely missed).
//
// P3 (top-3 by duration): Failed when announcer segments (~960ms) were longer than some
//   animal clips (~780-903ms in Arkose audio format v2).
//
// SOLUTION: CANDIDATE SEGMENTS + COMBINATION SELECTION
//
// Earlier frame-level hard speech filtering was too aggressive: low-centroid animal clips
// could be split or discarded before selection. Instead:
//   1. Collect ALL above-threshold active runs first.
//   2. Merge only short quiet gaps.
//   3. Compute segment-level centroid per candidate.
//   4. If >3 candidates, evaluate every 3-combination and choose the best trio.
//   5. Speech-like segments are softly penalized, not hard-dropped.
// This keeps quiet / low-centroid late clips available for selection while still
// preferring full animal clips over announcer / TTS fragments.
//
// Threshold parameters measured on real Arkose audio.
// SOURCE: ANALIZ_RAPORU.md section 8.2 (2026-05-01).
//
// Algorithm:
//   1. threshold = max_frame_energy * 0.005
//   2. find active segments, merge only micro-silences with 50ms gap
//   3. drop segments shorter than 200ms
//   4. compute segment centroid with 4096-sample FFT
//   5. drop centroid < 2100Hz speech candidates; if <3 remain, retry with 1500Hz cutoff
//   6. if >3 remain, evaluate all C(n,3) combinations using centroid-margin scoring
//   7. sort selected trio by playback order
pub fn extractThreeLargestSegments(
    samples: []const f32,
    sample_rate: u32,
    config: MultiSegmentConfig,
) ![CLIP_COUNT]ClipInput {
    return extractThreeLargestSegmentsForLabel(samples, sample_rate, config, .unknown);
}

pub fn extractThreeLargestSegmentsForLabel(
    samples: []const f32,
    sample_rate: u32,
    config: MultiSegmentConfig,
    label: SemanticLabel,
) ![CLIP_COUNT]ClipInput {
    if (samples.len == 0) return error.InvalidClip;
    if (sample_rate == 0) return error.InvalidSampleRate;
    _ = label;

    const frame_len = msToSamples(config.frame_ms, sample_rate);
    if (frame_len == 0) return error.InvalidSampleRate;
    const frame_count = samples.len / frame_len;
    if (frame_count == 0) return error.InvalidClip;

    // --- Pass 1: max frame energy for adaptive threshold ---
    // SOURCE: energy_fraction=0.01 validated on session 1 audio (2026-05-01):
    //   quiet clip at ~2.5% of max_frame_energy, previously missed at fraction=0.05
    var max_frame_energy: f64 = 0.0;
    for (0..frame_count) |fi| {
        const rms = computeRangeRms(samples, fi * frame_len, fi * frame_len + frame_len);
        const e = rms * rms;
        if (e > max_frame_energy) max_frame_energy = e;
    }
    if (max_frame_energy == 0.0) return error.InsufficientSegments;
    const threshold = max_frame_energy * config.energy_fraction;

    // --- Pass 2: collect all active runs above energy threshold ---
    var raw: [MAX_SEGMENTS]SegmentBound = undefined;
    var raw_count: usize = 0;
    var in_active_run = false;
    var run_start: usize = 0;

    for (0..frame_count) |fi| {
        const fs = fi * frame_len;
        const fe = fs + frame_len;
        const rms = computeRangeRms(samples, fs, fe);
        const energy = rms * rms;

        if (energy >= threshold) {
            if (!in_active_run) {
                run_start = fs;
                in_active_run = true;
            }
        } else {
            if (in_active_run) {
                if (raw_count < MAX_SEGMENTS) {
                    raw[raw_count] = .{ .start = run_start, .end = fs };
                    raw_count += 1;
                }
                in_active_run = false;
            }
        }
    }
    if (in_active_run and raw_count < MAX_SEGMENTS) {
        raw[raw_count] = .{ .start = run_start, .end = frame_count * frame_len };
        raw_count += 1;
    }

    // --- Pass 3-4: merge and filter with progressive gap increase ---
    // SOURCE: Transient-heavy audio (footsteps, percussion) produces short energy
    // bursts with quiet gaps between them. A single config.merge_gap_ms may be too
    // small to merge footfall gaps within a ~5s segment, causing every transient to
    // become a separate sub-200ms fragment that gets filtered out.
    // Progressive retry widens the merge gap until we find >= CLIP_COUNT segments.
    // Multipliers chosen so that widest gap (10x = 500ms default, 1500ms for .steps/.different)
    // stays below typical cross-segment gaps in Arkose format (~1s+).
    const gap_multipliers = [_]u32{ 1, 4, 10 };
    const min_samples_len = msToSamples(config.min_segment_ms, sample_rate);
    var best_filtered: [MAX_SEGMENTS]SegmentBound = undefined;
    var best_filtered_count: usize = 0;
    var used_multiplier: u32 = 1;

    for (gap_multipliers) |mult| {
        const effective_gap = config.merge_gap_ms * mult;
        const effective_merge_samples = msToSamples(effective_gap, sample_rate);

        var merged: [MAX_SEGMENTS]SegmentBound = undefined;
        var merged_count: usize = 0;
        for (0..raw_count) |i| {
            const seg = raw[i];
            if (merged_count > 0 and seg.start >= merged[merged_count - 1].end and
                seg.start - merged[merged_count - 1].end < effective_merge_samples)
            {
                merged[merged_count - 1].end = seg.end;
            } else {
                merged[merged_count] = seg;
                merged_count += 1;
            }
        }

        var filtered: [MAX_SEGMENTS]SegmentBound = undefined;
        var filtered_count: usize = 0;
        for (0..merged_count) |i| {
            const seg = merged[i];
            if (seg.end > seg.start and seg.end - seg.start >= min_samples_len) {
                filtered[filtered_count] = seg;
                filtered_count += 1;
            }
        }

        if (filtered_count > best_filtered_count) {
            best_filtered = filtered;
            best_filtered_count = filtered_count;
            used_multiplier = mult;
        }

        if (filtered_count >= CLIP_COUNT) break;

        // If widening the gap reduces segment count, stop — further widening
        // will only merge different audio segments together.
        if (filtered_count > 0 and filtered_count < best_filtered_count and mult > 1) break;
    }

    if (best_filtered_count < CLIP_COUNT) {
        std.debug.print(
            "[SEGMENT] Only {d} active segments found (need {d}) after {d}x merge gap — error.InsufficientSegments\n",
            .{ best_filtered_count, CLIP_COUNT, used_multiplier },
        );
        return error.InsufficientSegments;
    }

    std.debug.print(
        "[SEGMENT] Found {d} segments with {d}x merge gap ({d}ms → {d}ms effective)\n",
        .{ best_filtered_count, used_multiplier, config.merge_gap_ms, config.merge_gap_ms * used_multiplier },
    );

    const filtered = best_filtered;
    const filtered_count = best_filtered_count;

    // --- Pass 5: build candidates with segment-level centroid ---
    var candidates: [MAX_SEGMENTS]SegmentCandidate = undefined;
    var candidate_count: usize = 0;
    for (0..filtered_count) |i| {
        const seg = filtered[i];
        const seg_samples = samples[seg.start..seg.end];
        const centroid_hz = computeSegmentCentroid(seg_samples, sample_rate);
        const speech_penalty = if (config.speech_centroid_cutoff_hz > 0.0 and centroid_hz < config.speech_centroid_cutoff_hz)
            std.math.pow(f64, 1.0 - (centroid_hz / config.speech_centroid_cutoff_hz), 2.0)
        else
            0.0;

        candidates[candidate_count] = .{
            .bound = seg,
            .duration_samples = seg.end - seg.start,
            .centroid_hz = centroid_hz,
            .speech_penalty = speech_penalty,
        };
        candidate_count += 1;
    }

    var selected: [CLIP_COUNT]SegmentBound = undefined;

    // SOURCE: Live test 2026-05-03 — audio structure for ALL labels is:
    //   [OPTION 1 speech] [sound effect 1] [OPTION 2 speech] [sound effect 2] [OPTION 3 speech] [sound effect 3]
    // Speech-marker extraction works universally by finding "OPTION N" speech segments
    // and taking the audio BETWEEN them as sound effects. This avoids the broken
    // energy-based equal-splitting approach that fails for transient-heavy sounds.
    selected = selectAlternatingAnimalSegments(&candidates, candidate_count, config.speech_centroid_cutoff_hz) catch blk: {
        const primary_cutoff = config.speech_centroid_cutoff_hz;
        const fallback_cutoff: f64 = 1500.0;
        const zero_cutoff: f64 = 0.0;
        break :blk selectBestCandidateTrio(&candidates, candidate_count, primary_cutoff) catch
            selectBestCandidateTrio(&candidates, candidate_count, fallback_cutoff) catch
            selectBestCandidateTrio(&candidates, candidate_count, zero_cutoff) catch
            return error.InsufficientSegments;
    };

    // --- Pass 7: sort selected by start position ascending (playback order) ---
    for (1..CLIP_COUNT) |i| {
        const key = selected[i];
        var j: usize = i;
        while (j > 0 and selected[j - 1].start > key.start) : (j -= 1) {
            selected[j] = selected[j - 1];
        }
        selected[j] = key;
    }

    std.debug.print(
        "[SEGMENT] Selected clips from {d} candidates. clip1={d}ms clip2={d}ms clip3={d}ms\n",
        .{
            candidate_count,
            (selected[0].end - selected[0].start) * 1000 / sample_rate, (selected[1].end - selected[1].start) * 1000 / sample_rate,
            (selected[2].end - selected[2].start) * 1000 / sample_rate,
        },
    );

    // Runtime sanity: all segments non-empty and within bounds
    for (selected) |seg| {
        std.debug.assert(seg.start < seg.end);
        std.debug.assert(seg.end <= samples.len);
    }

    return [CLIP_COUNT]ClipInput{
        .{ .samples = samples[selected[0].start..selected[0].end], .sample_rate = sample_rate },
        .{ .samples = samples[selected[1].start..selected[1].end], .sample_rate = sample_rate },
        .{ .samples = samples[selected[2].start..selected[2].end], .sample_rate = sample_rate },
    };
}

fn selectAlternatingAnimalSegments(
    candidates: *const [MAX_SEGMENTS]SegmentCandidate,
    candidate_count: usize,
    cutoff_hz: f64,
) AnalysisError![CLIP_COUNT]SegmentBound {
    // SOURCE: Live test 2026-05-03 — audio structure is [OPTION N speech][sound][OPTION N+1 speech][sound]...
    // Strategy: Find "OPTION N" speech markers (low centroid + substantial duration),
    // then extract the audio BETWEEN markers as sound effect segments.
    // This replaces the broken "skip first prompt, take next 3" approach which fails
    // when prompts are interleaved between sound effects.

    _ = cutoff_hz;

    // Pass 1: identify speech markers — segments with low centroid + long duration
    const min_speech_samples = 600 * 44100 / 1000; // 600ms @ 44.1kHz
    var marker_indices: [MAX_SEGMENTS]usize = undefined;
    var marker_count: usize = 0;

    for (0..candidate_count) |i| {
        const cand = candidates[i];
        // Speech marker: centroid in speech range AND enough duration to be "OPTION N"
        if (cand.centroid_hz < 2100.0 and cand.duration_samples >= min_speech_samples) {
            marker_indices[marker_count] = i;
            marker_count += 1;
        }
    }

    // Pass 2: sort markers by start position (playback order)
    // NOTE: marker_count==0 causes integer overflow in `for (1..0)`, guard first
    if (marker_count <= 1) return error.InsufficientSegments;

    for (1..marker_count) |i| {
        const key_idx = marker_indices[i];
        const key_start = candidates[key_idx].bound.start;
        var j: usize = i;
        while (j > 0 and candidates[marker_indices[j - 1]].bound.start > key_start) : (j -= 1) {
            marker_indices[j] = marker_indices[j - 1];
        }
        marker_indices[j] = key_idx;
    }

    // Need at least 3 markers to extract 3 sound segments between them
    if (marker_count < 3) return error.InsufficientSegments;

    // Use first 3 markers (in case there are more due to repeats)
    // Structure: [marker_0=OPTION1] [sound1] [marker_1=OPTION2] [sound2] [marker_2=OPTION3] [sound3]
    // Sound segments are BETWEEN markers:
    var bounds: [CLIP_COUNT]SegmentBound = undefined;
    bounds[0] = .{ .start = candidates[marker_indices[0]].bound.end, .end = candidates[marker_indices[1]].bound.start };
    bounds[1] = .{ .start = candidates[marker_indices[1]].bound.end, .end = candidates[marker_indices[2]].bound.start };

    // For the 3rd sound, search after marker_2 for a non-speech segment
    // OR use [marker_2.end .. next_marker.start] if there's a 4th marker
    // OR use [marker_2.end .. last_candidate.end] as fallback
    if (marker_count >= 4) {
        bounds[2] = .{ .start = candidates[marker_indices[2]].bound.end, .end = candidates[marker_indices[3]].bound.start };
    } else {
        // No 4th marker — the 3rd sound is after the 3rd marker.
        // Find the first non-speech, substantial candidate after marker_2
        var found_after: ?SegmentBound = null;
        for (0..candidate_count) |i| {
            const cand = candidates[i];
            if (cand.bound.start >= candidates[marker_indices[2]].bound.end and
                !(cand.centroid_hz < 2100.0 and cand.duration_samples >= min_speech_samples) and
                cand.duration_samples >= 200 * 44100 / 1000)
            {
                found_after = cand.bound;
                break;
            }
        }
        if (found_after) |fb| {
            bounds[2] = fb;
        } else {
            // Last resort: use the tail — everything after the last marker
            // bounded by the last candidate's end or end of sample space
            bounds[2] = .{ .start = candidates[marker_indices[2]].bound.end, .end = candidates[candidate_count - 1].bound.end };
        }
    }

    // Validate: all segments must have positive duration and meet minimum
    const min_sound_samples = 200 * 44100 / 1000;
    for (bounds, 0..) |b, idx| {
        if (b.end <= b.start or b.end - b.start < min_sound_samples) {
            std.debug.print("[SPEECH-MARKER] Sound segment {d} too short: {d} samples\n", .{ idx, b.end - b.start });
            return error.InsufficientSegments;
        }
    }

    std.debug.print(
        "[SPEECH-MARKER] Found {d} speech markers, extracted 3 sound segments ({d}ms/{d}ms/{d}ms)\n",
        .{
            marker_count,
            (bounds[0].end - bounds[0].start) * 1000 / 44100,
            (bounds[1].end - bounds[1].start) * 1000 / 44100,
            (bounds[2].end - bounds[2].start) * 1000 / 44100,
        },
    );

    return bounds;
}

fn computeSegmentCentroid(samples: []const f32, sample_rate: u32) f64 {
    if (samples.len < 2 or sample_rate == 0) return 0.0;

    var fft_scratch: [4096]Complex = undefined;
    const max_n = @min(samples.len, fft_scratch.len);
    var n: usize = 1;
    while (n * 2 <= max_n) : (n *= 2) {}
    if (n < 2) return 0.0;

    @memset(fft_scratch[0..n], Complex{ .re = 0.0, .im = 0.0 });
    for (0..n) |k| {
        const hann: f32 = @floatCast(0.5 - 0.5 * @cos(
            2.0 * std.math.pi * @as(f64, @floatFromInt(k)) / @as(f64, @floatFromInt(n)),
        ));
        fft_scratch[k] = .{ .re = samples[k] * hann, .im = 0.0 };
    }
    fft(fft_scratch[0..n]);

    const sr_f64: f64 = @floatFromInt(sample_rate);
    const half = n / 2;
    var total_mag: f64 = 0.0;
    var weighted_mag: f64 = 0.0;
    for (0..half) |k| {
        const mag = magnitude(fft_scratch[k]);
        const freq = sr_f64 * @as(f64, @floatFromInt(k)) / @as(f64, @floatFromInt(n));
        total_mag += mag;
        weighted_mag += mag * freq;
    }
    return if (total_mag > 0.0) weighted_mag / total_mag else 0.0;
}

fn selectBestCandidateTrio(
    candidates: *const [MAX_SEGMENTS]SegmentCandidate,
    candidate_count: usize,
    cutoff_hz: f64,
) AnalysisError![CLIP_COUNT]SegmentBound {
    var kept: [MAX_SEGMENTS]usize = undefined;
    var kept_count: usize = 0;
    for (0..candidate_count) |i| {
        if (candidates[i].centroid_hz >= cutoff_hz) {
            kept[kept_count] = i;
            kept_count += 1;
        }
    }
    if (kept_count < CLIP_COUNT) return error.InsufficientSegments;

    const min_reasonable_samples: usize = 600 * 44100 / 1000;
    var preferred: [MAX_SEGMENTS]usize = undefined;
    var preferred_count: usize = 0;
    for (0..kept_count) |idx| {
        const candidate_index = kept[idx];
        if (candidates[candidate_index].duration_samples >= min_reasonable_samples) {
            preferred[preferred_count] = candidate_index;
            preferred_count += 1;
        }
    }

    const active_indices = if (preferred_count >= CLIP_COUNT) preferred[0..preferred_count] else kept[0..kept_count];
    const active_count = if (preferred_count >= CLIP_COUNT) preferred_count else kept_count;

    if (active_count == CLIP_COUNT) {
        return .{
            candidates[active_indices[0]].bound,
            candidates[active_indices[1]].bound,
            candidates[active_indices[2]].bound,
        };
    }

    var found = false;
    var best_score = -std.math.inf(f64);
    var best_selection: [CLIP_COUNT]SegmentBound = undefined;
    for (0..active_count) |ai| {
        const i = active_indices[ai];
        for (ai + 1..active_count) |aj| {
            const j = active_indices[aj];
            for (aj + 1..active_count) |ak| {
                const k = active_indices[ak];
                const score = combinationScore(.{ candidates[i], candidates[j], candidates[k] });
                if (!found or score > best_score) {
                    found = true;
                    best_score = score;
                    best_selection = .{ candidates[i].bound, candidates[j].bound, candidates[k].bound };
                }
            }
        }
    }
    if (!found) return error.InsufficientSegments;
    return best_selection;
}

fn combinationScore(candidates: [CLIP_COUNT]SegmentCandidate) f64 {
    const centroids = [_]f64{
        candidates[0].centroid_hz,
        candidates[1].centroid_hz,
        candidates[2].centroid_hz,
    };
    const center = median3(centroids);
    var deviations = [_]f64{
        @abs(centroids[0] - center),
        @abs(centroids[1] - center),
        @abs(centroids[2] - center),
    };
    if (deviations[0] < deviations[1]) std.mem.swap(f64, &deviations[0], &deviations[1]);
    if (deviations[1] < deviations[2]) std.mem.swap(f64, &deviations[1], &deviations[2]);
    if (deviations[0] < deviations[1]) std.mem.swap(f64, &deviations[0], &deviations[1]);

    const margin = deviations[0] - deviations[1];
    const speech_penalty = @max(candidates[0].speech_penalty, @max(candidates[1].speech_penalty, candidates[2].speech_penalty));
    return margin * (1.0 - speech_penalty);
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

    const bands = [_]struct { start_hz: f64, end_hz: f64 }{
        .{ .start_hz = 0.0, .end_hz = 500.0 },
        .{ .start_hz = 500.0, .end_hz = 2000.0 },
        .{ .start_hz = 2000.0, .end_hz = 8000.0 },
        .{ .start_hz = 8000.0, .end_hz = 22000.0 },
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
        total_score += delta;
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

fn testFeaturesWithActive(active: ActiveRegion) [CLIP_COUNT]ClipFeatures {
    const hardware = HardwareSignature{ .dc_offset = 0.0, .dc_window_std_dev = 0.0, .dc_bias_confidence = 1.0, .noise_floor_rms = active.noise_floor_rms, .noise_floor_confidence = 1.0, .quantization_uniformity = 0.0, .crest_factor = 1.0, .rms = active.active_rms };
    const acoustic = AcousticSignature{ .spectral_flux = 0.0, .spectral_rolloff = 0.0, .zero_crossing_rate = 0.0, .harmonic_peak_ratio = 0.0, .spectral_centroid = 0.0, .narrowband_stability = 0.0, .low_frequency_transient_energy = 0.0 };
    return [_]ClipFeatures{
        .{ .active = active, .hardware = hardware, .acoustic = acoustic },
        .{ .active = active, .hardware = hardware, .acoustic = acoustic },
        .{ .active = active, .hardware = hardware, .acoustic = acoustic },
    };
}

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

test "fft_analyzer: VAD detects active region without announcement skip" {
    const sample_rate: u32 = 1000;
    var clip = [_]f32{0.01} ** 100;
    for (30..60) |i| clip[i] = 0.2;

    const active = try findActiveRegion(&clip, sample_rate, .{ .announcement_skip_ms = 0, .frame_ms = 10, .min_active_frames = 3, .snr_min = 3.0 });

    try std.testing.expectEqual(@as(usize, 30), active.start);
    try std.testing.expectEqual(@as(usize, 60), active.end);
    try std.testing.expectEqual(@as(u32, 3), active.active_frame_count);
    try std.testing.expectApproxEqAbs(@as(f64, 20.0), active.snr_estimate, 0.001);
}

test "fft_analyzer: VAD honors announcement skip milliseconds" {
    const sample_rate: u32 = 1000;
    var clip = [_]f32{0.01} ** 1100;
    for (100..200) |i| clip[i] = 0.8;
    for (1030..1060) |i| clip[i] = 0.3;

    const active = try findActiveRegion(&clip, sample_rate, .{ .announcement_skip_ms = 1000, .frame_ms = 10, .min_active_frames = 3, .snr_min = 3.0 });

    try std.testing.expectEqual(@as(usize, 1030), active.start);
    try std.testing.expectEqual(@as(usize, 1060), active.end);
    try std.testing.expect(active.snr_estimate > 20.0);
}

test "fft_analyzer: VAD SNR estimate is linear ratio" {
    const sample_rate: u32 = 1000;
    var clip = [_]f32{0.02} ** 100;
    for (40..80) |i| clip[i] = 0.2;

    const active = try findActiveRegion(&clip, sample_rate, .{ .frame_ms = 10, .min_active_frames = 4, .snr_min = 3.0 });

    try std.testing.expectApproxEqAbs(@as(f64, 10.0), active.snr_estimate, 0.001);
}

test "fft_analyzer: VAD dynamic threshold uses frame energy" {
    const sample_rate: u32 = 1000;
    var clip = [_]f32{1.0} ** 100;
    for (30..60) |i| clip[i] = 3.05;
    for (60..90) |i| clip[i] = 6.0;

    const active = try findActiveRegion(&clip, sample_rate, .{ .frame_ms = 10, .min_active_frames = 3, .snr_min = 2.0 });

    try std.testing.expectEqual(@as(usize, 60), active.start);
    try std.testing.expectEqual(@as(usize, 90), active.end);
    try std.testing.expectEqual(@as(u32, 3), active.active_frame_count);
}

test "fft_analyzer: HardwareSignature has no dc_delta_ratio field" {
    try std.testing.expect(!@hasField(HardwareSignature, "dc_delta_ratio"));
}

test "fft_analyzer: VAD accepts silent noise floor with active signal" {
    const sample_rate: u32 = 1000;
    var clip = [_]f32{0.0} ** 100;
    for (50..100) |i| clip[i] = 0.2;

    const active = try findActiveRegion(&clip, sample_rate, .{ .frame_ms = 10, .min_active_frames = 5, .snr_min = 3.0 });

    try std.testing.expectEqual(@as(usize, 50), active.start);
    try std.testing.expectEqual(@as(usize, 100), active.end);
    try std.testing.expect(active.snr_estimate == std.math.inf(f64));
}

test "fft_analyzer: hardware DC confidence uses stable signed windows" {
    var stable_clip = [_]f32{0.11} ** 100;
    var mixed_clip: [100]f32 = undefined;
    for (&mixed_clip, 0..) |*sample, i| sample.* = if (i < 60) 0.11 else -0.09;
    const active = ActiveRegion{ .start = 0, .end = stable_clip.len, .noise_frame_count = 5, .active_frame_count = 10, .active_rms = 0.11, .noise_floor_rms = 0.01, .snr_estimate = 11.0 };

    const stable = try computeHardwareWithoutQuantization(&stable_clip, active);
    const mixed = try computeHardwareWithoutQuantization(&mixed_clip, active);

    try std.testing.expectApproxEqAbs(@as(f64, 0.11), stable.dc_offset, 0.001);
    try std.testing.expect(stable.dc_bias_confidence > 0.9);
    try std.testing.expect(stable.dc_window_std_dev < 0.001);
    try std.testing.expect(mixed.dc_bias_confidence < stable.dc_bias_confidence);
}

test "fft_analyzer: quantization fraction uses residual tolerance" {
    const clip = [_]f32{ -1.0, -0.5, 0.0, 0.5, 1.0, 0.251 };
    const active = ActiveRegion{ .start = 0, .end = clip.len, .noise_frame_count = 1, .active_frame_count = 1, .active_rms = 0.6, .noise_floor_rms = 0.1, .snr_estimate = 6.0 };

    const fraction = quantizationFractionWithin(&clip, active, 4.0, 0.01);

    try std.testing.expectApproxEqAbs(@as(f64, 1.0), fraction, 0.0001);
}

test "fft_analyzer: caller bit depth applies one quantization grid to all clips" {
    var clip0 = [_]f32{ 0.0, 0.25, 0.5, 0.75 };
    var clip1 = [_]f32{ 0.0, 0.125, 0.25, 0.375 };
    var clip2 = [_]f32{ 0.0, -0.25, -0.5, -0.75 };
    var features = testFeaturesWithActive(.{ .start = 0, .end = 4, .noise_frame_count = 2, .active_frame_count = 4, .active_rms = 0.5, .noise_floor_rms = 0.05, .snr_estimate = 10.0 });
    const clips = [_]ClipInput{
        .{ .samples = &clip0, .sample_rate = 1000 },
        .{ .samples = &clip1, .sample_rate = 1000 },
        .{ .samples = &clip2, .sample_rate = 1000 },
    };

    const grid = try chooseCommonQuantizationGrid(&clips, &features, .{ .optional_bit_depth = 3, .quantization_tolerance = 0.01 });

    try std.testing.expectEqual(QuantizationGridSource.caller_bit_depth, grid.source);
    try std.testing.expectApproxEqAbs(@as(f64, 7.0), grid.scale, 0.0001);
    try std.testing.expectApproxEqAbs(quantizationFractionWithin(clips[0].samples, features[0].active, grid.scale, 0.01), features[0].hardware.quantization_uniformity, 0.0001);
    try std.testing.expectApproxEqAbs(quantizationFractionWithin(clips[1].samples, features[1].active, grid.scale, 0.01), features[1].hardware.quantization_uniformity, 0.0001);
    try std.testing.expectApproxEqAbs(quantizationFractionWithin(clips[2].samples, features[2].active, grid.scale, 0.01), features[2].hardware.quantization_uniformity, 0.0001);
}

test "fft_analyzer: runtime quantization grid maximizes common sum across clips" {
    var clip0 = [_]f32{ 0.0, 0.25, 0.5, 0.75 };
    var clip1 = [_]f32{ 0.0, 0.25, 0.5, 0.75 };
    var clip2 = [_]f32{ 0.4225595, 0.3767157, 0.4888164, 0.4043268 };
    var features = testFeaturesWithActive(.{ .start = 0, .end = 4, .noise_frame_count = 2, .active_frame_count = 4, .active_rms = 0.5, .noise_floor_rms = 0.05, .snr_estimate = 10.0 });
    const clips = [_]ClipInput{
        .{ .samples = &clip0, .sample_rate = 1000 },
        .{ .samples = &clip1, .sample_rate = 1000 },
        .{ .samples = &clip2, .sample_rate = 1000 },
    };

    const grid = try chooseCommonQuantizationGrid(&clips, &features, .{ .quantization_tolerance = 0.01 });

    try std.testing.expectEqual(QuantizationGridSource.runtime_common_grid, grid.source);
    try std.testing.expectApproxEqAbs(@as(f64, 4.0), grid.scale, 0.0001);
    try std.testing.expect(features[0].hardware.quantization_uniformity > features[2].hardware.quantization_uniformity);
    try std.testing.expectApproxEqAbs(features[0].hardware.quantization_uniformity, features[1].hardware.quantization_uniformity, 0.0001);
}

test "fft_analyzer: semantic labels parse text" {
    try std.testing.expectEqual(SemanticLabel.water, semanticLabelFromText("Water dripping"));
    try std.testing.expectEqual(SemanticLabel.bee, semanticLabelFromText("buzzing bees"));
    try std.testing.expectEqual(SemanticLabel.steps, semanticLabelFromText("FOOTSTEPS"));
    try std.testing.expectEqual(SemanticLabel.speech, semanticLabelFromText("Which option is only one person talking?"));
    try std.testing.expectEqual(SemanticLabel.speech, semanticLabelFromText("Which option is the sound of drums?"));
    try std.testing.expectEqual(SemanticLabel.different, semanticLabelFromText("which one is different"));
    try std.testing.expectEqual(SemanticLabel.unknown, semanticLabelFromText("traffic"));
}

test "fft_analyzer: bee tone has narrowband stability" {
    const sample_rate: u32 = 8192;
    var clip: [4096]f32 = undefined;
    for (&clip, 0..) |*sample, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        sample.* = @floatCast(@sin(2.0 * std.math.pi * 440.0 * t));
    }
    const active = ActiveRegion{ .start = 0, .end = clip.len, .noise_frame_count = 5, .active_frame_count = 40, .active_rms = 0.7, .noise_floor_rms = 0.01, .snr_estimate = 70.0 };

    const acoustic = try computeAcousticSignature(&clip, active, sample_rate, .{});

    try std.testing.expect(acoustic.narrowband_stability > 0.5);
    try std.testing.expect(acoustic.harmonic_peak_ratio > 0.1);
}

test "fft_analyzer: short active region still produces spectral flux from multiple frames" {
    const sample_rate: u32 = 8192;
    var clip: [2048]f32 = undefined;
    for (&clip, 0..) |*sample, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        const freq: f64 = if (i < 1024) 440.0 else 880.0;
        sample.* = @floatCast(@sin(2.0 * std.math.pi * freq * t));
    }
    const active = ActiveRegion{ .start = 0, .end = clip.len, .noise_frame_count = 5, .active_frame_count = 20, .active_rms = 0.7, .noise_floor_rms = 0.01, .snr_estimate = 70.0 };

    const acoustic = try computeAcousticSignature(&clip, active, sample_rate, .{});

    try std.testing.expect(acoustic.spectral_flux > 0.1);
}

test "fft_analyzer: steady low frequency tone is not transient energy" {
    const sample_rate: u32 = 8192;
    var clip: [4096]f32 = undefined;
    for (&clip, 0..) |*sample, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sample_rate));
        sample.* = @floatCast(@sin(2.0 * std.math.pi * 100.0 * t));
    }
    const active = ActiveRegion{ .start = 0, .end = clip.len, .noise_frame_count = 5, .active_frame_count = 40, .active_rms = 0.7, .noise_floor_rms = 0.01, .snr_estimate = 70.0 };

    const acoustic = try computeAcousticSignature(&clip, active, sample_rate, .{ .low_freq_cutoff_hz = 500.0 });

    try std.testing.expect(acoustic.low_frequency_transient_energy < 0.1);
}

test "fft_analyzer: steps pulse exposes low frequency transient energy" {
    const sample_rate: u32 = 8192;
    var clip = [_]f32{0.0} ** 4096;
    for (0..4) |pulse| {
        const base = pulse * 900 + 128;
        for (0..80) |i| clip[base + i] = @floatCast(0.9 - @as(f64, @floatFromInt(i)) / 100.0);
    }
    const active = ActiveRegion{ .start = 0, .end = clip.len, .noise_frame_count = 5, .active_frame_count = 40, .active_rms = 0.2, .noise_floor_rms = 0.01, .snr_estimate = 20.0 };

    const acoustic = try computeAcousticSignature(&clip, active, sample_rate, .{ .low_freq_cutoff_hz = 500.0 });

    try std.testing.expect(acoustic.low_frequency_transient_energy > 0.0);
    try std.testing.expect(acoustic.zero_crossing_rate >= 0.0);
}

test "fft_analyzer: maxAdScores isolates single outlier" {
    const scores = maxAdScores(.{ 0.1, 0.1, 0.4 });

    try std.testing.expect(scores[2] > scores[0]);
    try std.testing.expect(scores[2] > scores[1]);
    try std.testing.expectApproxEqAbs(@as(f64, 0.0), scores[0], 0.0001);
}

test "fft_analyzer: harmonic peak raw feature maps to harmonic peak score" {
    var features = testFeaturesWithActive(.{ .start = 0, .end = 8, .noise_frame_count = 2, .active_frame_count = 4, .active_rms = 0.5, .noise_floor_rms = 0.05, .snr_estimate = 10.0 });
    features[0].acoustic.harmonic_peak_ratio = 0.2;
    features[1].acoustic.harmonic_peak_ratio = 0.2;
    features[2].acoustic.harmonic_peak_ratio = 0.8;

    const scores = computeOutlierScores(features);

    try std.testing.expect(scores[2].harmonic_peak_score > scores[0].harmonic_peak_score);
    try std.testing.expect(scores[2].harmonic_peak_score > scores[1].harmonic_peak_score);
}

test "fft_analyzer: analyzeOutlier returns ambiguous for identical clips" {
    var clip = [_]f32{0.01} ** 4096;
    for (512..4096) |i| {
        const t = @as(f64, @floatFromInt(i)) / 8192.0;
        clip[i] = @floatCast(0.01 + 0.2 * @sin(2.0 * std.math.pi * 440.0 * t));
    }
    const clips = [_]ClipInput{
        .{ .samples = &clip, .sample_rate = 8192 },
        .{ .samples = &clip, .sample_rate = 8192 },
        .{ .samples = &clip, .sample_rate = 8192 },
    };

    try std.testing.expectError(error.AmbiguousSignal, analyzeOutlier(&clips, .unknown, .{ .vad = .{ .snr_min = 1.1 } }));
}

test "fft_analyzer: analyzeOutlier uses whole clip when VAD rejects low SNR active audio" {
    var clip0: [4096]f32 = undefined;
    var clip1: [4096]f32 = undefined;
    var clip2: [4096]f32 = undefined;
    for (0..4096) |i| {
        const t = @as(f64, @floatFromInt(i)) / 8192.0;
        const bed = 0.08 * @sin(2.0 * std.math.pi * 220.0 * t);
        const motion = if ((i / 256) % 2 == 0) 0.04 * @sin(2.0 * std.math.pi * 440.0 * t) else 0.0;
        clip0[i] = @floatCast(bed + motion);
        clip1[i] = @floatCast(bed + motion * 0.95);
        clip2[i] = @floatCast(0.18 + bed + motion);
    }
    const clips = [_]ClipInput{
        .{ .samples = &clip0, .sample_rate = 8192 },
        .{ .samples = &clip1, .sample_rate = 8192 },
        .{ .samples = &clip2, .sample_rate = 8192 },
    };

    const result = try analyzeOutlier(&clips, .unknown, .{ .hardware_primary_margin = 0.05 });

    try std.testing.expectEqual(@as(u8, 3), result.guess);
    try std.testing.expectEqual(@as(usize, 0), result.features[2].active.start);
    try std.testing.expectEqual(@as(usize, clip2.len), result.features[2].active.end);
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

// SOURCE: 45-file forensic analysis 2026-05-01
// Tests that extractThreeLargestSegments correctly isolates 3 animal clips
// from a synthetic audio that mimics the Arkose challenge structure:
//   [silence][announcer=970ms][gap][clip1=1500ms][gap][clip2=3000ms][gap][clip3=1100ms][silence]
test "fft_analyzer: extractThreeLargestSegments isolates 3 animal clips skipping announcer" {
    const sr: u32 = 44100;
    // Durations in samples, matching measured Arkose structure
    const silence_s: usize = sr / 2; // 500ms silence
    const announcer_s: usize = sr * 97 / 100; // 970ms announcer (shorter than all clips)
    const gap_s: usize = sr * 4 / 10; // 400ms gap (>= measured minimum 376ms)
    const clip1_s: usize = sr * 3 / 2; // 1500ms (> announcer 970ms)
    const clip2_s: usize = sr * 3; // 3000ms (longest, the "bee" or long bird call)
    const clip3_s: usize = sr * 11 / 10; // 1100ms (> announcer 970ms)

    const total = silence_s + announcer_s + gap_s + clip1_s + gap_s + clip2_s + gap_s + clip3_s + silence_s;
    const buf = try std.testing.allocator.alloc(f32, total);
    defer std.testing.allocator.free(buf);
    @memset(buf, 0.0);

    // Fill announcer region with speech-like low centroid content.
    const ann_start = silence_s;
    for (buf[ann_start .. ann_start + announcer_s], 0..) |*s, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sr));
        s.* = @floatCast(0.3 * @sin(2.0 * std.math.pi * 300.0 * t));
    }

    // Fill animal clips with high-centroid content so the speech cutoff can separate them.
    var pos: usize = silence_s + announcer_s + gap_s;
    for (buf[pos .. pos + clip1_s], 0..) |*s, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sr));
        s.* = @floatCast(0.8 * @sin(2.0 * std.math.pi * 3200.0 * t));
    }
    pos += clip1_s + gap_s;
    for (buf[pos .. pos + clip2_s], 0..) |*s, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sr));
        s.* = @floatCast(0.8 * @sin(2.0 * std.math.pi * 4200.0 * t));
    }
    pos += clip2_s + gap_s;
    for (buf[pos .. pos + clip3_s], 0..) |*s, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sr));
        s.* = @floatCast(0.8 * @sin(2.0 * std.math.pi * 5200.0 * t));
    }

    const clips = try extractThreeLargestSegments(buf, sr, .{});

    // All 3 returned clips must be non-empty
    try std.testing.expect(clips[0].samples.len > 0);
    try std.testing.expect(clips[1].samples.len > 0);
    try std.testing.expect(clips[2].samples.len > 0);

    // Clips must be in ascending start-position order (playback order preserved)
    const p0 = @intFromPtr(clips[0].samples.ptr);
    const p1 = @intFromPtr(clips[1].samples.ptr);
    const p2 = @intFromPtr(clips[2].samples.ptr);
    try std.testing.expect(p0 < p1);
    try std.testing.expect(p1 < p2);

    // The longest clip (clip2 = 3000ms) must be represented
    // Clip2 is the middle one by position; it is also the longest.
    // After positional sort: [clip1, clip2, clip3]. clip2 is index 1.
    // Allow +-frame_len (30ms * sr/1000 = 1323 samples) tolerance.
    const frame_tol: usize = 30 * sr / 1000 + 1;
    try std.testing.expect(clips[1].samples.len >= clip2_s - frame_tol);
    try std.testing.expect(clips[1].samples.len <= clip2_s + frame_tol);

    // Sample rates must be propagated unchanged
    try std.testing.expectEqual(sr, clips[0].sample_rate);
    try std.testing.expectEqual(sr, clips[1].sample_rate);
    try std.testing.expectEqual(sr, clips[2].sample_rate);

    // The announcer (970ms) must NOT be among the selected clips.
    // Verification method: total duration of 3 selected clips must be close to
    // clip1 + clip2 + clip3 = 1500 + 3000 + 1100 = 5600ms.
    // If the announcer (970ms) were substituted for any clip, total would deviate by ~530ms.
    // Allow 10% tolerance for frame-boundary quantization (frame_ms=30 => <=30ms per edge).
    // SOURCE: frame quantization = frame_ms * sr / 1000 = 30 * 44100 / 1000 = 1323 samples
    const total_returned = clips[0].samples.len + clips[1].samples.len + clips[2].samples.len;
    const expected_total = clip1_s + clip2_s + clip3_s;
    const tol = expected_total / 10; // 10% tolerance
    try std.testing.expect(total_returned >= expected_total - tol);
    try std.testing.expect(total_returned <= expected_total + tol);
}

test "fft_analyzer: extractThreeLargestSegments returns error on all-silence audio" {
    const sr: u32 = 44100;
    const buf = try std.testing.allocator.alloc(f32, sr * 5); // 5s silence
    defer std.testing.allocator.free(buf);
    @memset(buf, 0.0);
    const result = extractThreeLargestSegments(buf, sr, .{});
    try std.testing.expectError(error.InsufficientSegments, result);
}

fn fillTransientRegion(samples: []f32, sr: u32, transient_samples: usize, gap_samples: usize, freq_hz: f64, decay_factor: f64) void {
    var pos: usize = 0;
    while (pos + transient_samples <= samples.len) : (pos += transient_samples + gap_samples) {
        for (0..transient_samples) |k| {
            const env = @exp(-@as(f64, @floatFromInt(k)) / (@as(f64, @floatFromInt(transient_samples)) * decay_factor));
            const t = @as(f64, @floatFromInt(k)) / @as(f64, @floatFromInt(sr));
            samples[pos + k] = @floatCast(0.9 * env * @sin(2.0 * std.math.pi * freq_hz * t));
        }
    }
}

test "fft_analyzer: progressive merge gap finds 3 segments in transient-heavy footstep audio" {
    const sr: u32 = 44100;
    const gap_between_ms: usize = 1000;
    const segment_dur_ms: usize = 2000; // shorter segments for faster test

    const gap_between_s = msToSamples(@intCast(gap_between_ms), sr);
    const segment_s = msToSamples(@intCast(segment_dur_ms), sr);

    const total = gap_between_s + segment_s + gap_between_s + segment_s + gap_between_s + segment_s;
    const buf = try std.testing.allocator.alloc(f32, total);
    defer std.testing.allocator.free(buf);
    @memset(buf, 0.0);

    // Write 3 continuous tone segments with 1000ms gaps between them.
    // With merge_gap_ms=50 (config default), intra-segment has no gaps
    // (continuous tone), so 1x produces 3 segments directly.
    // This validates that the progressive merge loop doesn't break things.
    var cursor: usize = gap_between_s;
    for (buf[cursor .. cursor + segment_s], 0..) |*s, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sr));
        s.* = @floatCast(0.8 * @sin(2.0 * std.math.pi * 440.0 * t));
    }
    cursor = gap_between_s + segment_s + gap_between_s;
    for (buf[cursor .. cursor + segment_s], 0..) |*s, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sr));
        s.* = @floatCast(0.8 * @sin(2.0 * std.math.pi * 880.0 * t));
    }
    cursor = gap_between_s + segment_s + gap_between_s + segment_s + gap_between_s;
    for (buf[cursor .. cursor + segment_s], 0..) |*s, i| {
        const t = @as(f64, @floatFromInt(i)) / @as(f64, @floatFromInt(sr));
        s.* = @floatCast(0.8 * @sin(2.0 * std.math.pi * 1320.0 * t));
    }

    const clips = try extractThreeLargestSegments(buf, sr, .{});

    try std.testing.expect(clips[0].samples.len > 0);
    try std.testing.expect(clips[1].samples.len > 0);
    try std.testing.expect(clips[2].samples.len > 0);

    const p0 = @intFromPtr(clips[0].samples.ptr);
    const p1 = @intFromPtr(clips[1].samples.ptr);
    const p2 = @intFromPtr(clips[2].samples.ptr);
    try std.testing.expect(p0 < p1);
    try std.testing.expect(p1 < p2);
}

test "fft_analyzer: progressive merge gap bridges transient gaps for footstep-like audio" {
    const sr: u32 = 44100;
    // Simulate footstep-like audio: 3 segments of 50ms bursts spaced 150ms apart,
    // with 1000ms silence between segments.
    const burst_ms: usize = 50;
    const intra_gap_ms: usize = 150;
    const inter_gap_ms: usize = 1000;
    const segment_dur_ms: usize = 2000;

    const burst_s = msToSamples(@intCast(burst_ms), sr);
    const intra_gap_s = msToSamples(@intCast(intra_gap_ms), sr);
    const inter_gap_s = msToSamples(@intCast(inter_gap_ms), sr);
    const segment_s = msToSamples(@intCast(segment_dur_ms), sr);

    const total = inter_gap_s + segment_s + inter_gap_s + segment_s + inter_gap_s + segment_s;
    const buf = try std.testing.allocator.alloc(f32, total);
    defer std.testing.allocator.free(buf);
    @memset(buf, 0.0);

    // Fill 3 segments with burst patterns
    var cursor: usize = inter_gap_s;
    fillTransientRegion(buf[cursor .. cursor + segment_s], sr, burst_s, intra_gap_s, 200.0, 0.3);
    cursor = inter_gap_s + segment_s + inter_gap_s;
    fillTransientRegion(buf[cursor .. cursor + segment_s], sr, burst_s, intra_gap_s, 400.0, 0.3);
    cursor = inter_gap_s + segment_s + inter_gap_s + segment_s + inter_gap_s;
    fillTransientRegion(buf[cursor .. cursor + segment_s], sr, burst_s, intra_gap_s, 600.0, 0.3);

    // Default merge_gap_ms=50: bursts won't merge → fragments < 200ms → 0 filtered.
    // Progressive retry at 4x (200ms) bridges the 150ms+frame_boundary gaps → 3 segments.
    const clips = try extractThreeLargestSegments(buf, sr, .{});

    try std.testing.expect(clips[0].samples.len > 0);
    try std.testing.expect(clips[1].samples.len > 0);
    try std.testing.expect(clips[2].samples.len > 0);

    const p0 = @intFromPtr(clips[0].samples.ptr);
    const p1 = @intFromPtr(clips[1].samples.ptr);
    const p2 = @intFromPtr(clips[2].samples.ptr);
    try std.testing.expect(p0 < p1);
    try std.testing.expect(p1 < p2);

    // Each clip should be at least 1 second (meaningful sub-segment of the 2s region)
    const min_clip_ms: usize = 1000 * sr / 1000;
    try std.testing.expect(clips[0].samples.len >= min_clip_ms);
    try std.testing.expect(clips[1].samples.len >= min_clip_ms);
    try std.testing.expect(clips[2].samples.len >= min_clip_ms);
}

test "fft_analyzer: extractThreeLargestSegments returns error on only 2 segments" {
    const sr: u32 = 44100;
    const gap: usize = sr / 2; // 500ms silence
    const clip: usize = sr; // 1000ms active
    const total = gap + clip + gap + clip + gap; // 2 clips only
    const buf = try std.testing.allocator.alloc(f32, total);
    defer std.testing.allocator.free(buf);
    @memset(buf, 0.0);
    for (buf[gap .. gap + clip]) |*s| s.* = 0.8;
    for (buf[gap + clip + gap .. gap + clip + gap + clip]) |*s| s.* = 0.8;
    const result = extractThreeLargestSegments(buf, sr, .{});
    try std.testing.expectError(error.InsufficientSegments, result);
}

test "fft_analyzer: real Arkose file keeps late third animal clip" {
    const allocator = std.testing.allocator;
    var io_impl = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();
    const cwd = std.Io.Dir.cwd();

    const file = cwd.openFile(io, "tmp/audio_challenge_1777644017_0.f32", .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer file.close(io);

    const file_size = try file.length(io);
    const raw_bytes = try allocator.alloc(u8, file_size);
    defer allocator.free(raw_bytes);
    _ = try std.Io.File.readPositionalAll(file, io, raw_bytes, 0);

    const samples = @as([]const f32, @alignCast(std.mem.bytesAsSlice(f32, raw_bytes)));
    const clips = try extractThreeLargestSegments(samples, 44100, .{});

    const sample_rate: usize = 44100;
    const base_ptr = @intFromPtr(samples.ptr);
    const late_clip_start_samples = (@intFromPtr(clips[2].samples.ptr) - base_ptr) / @sizeOf(f32);

    // SOURCE: handoff forensic dump for audio_challenge_1777644017_0.f32
    // Expected third animal clip begins late in the file; exact duration can vary
    // under the current 50ms merge-gap strategy, but it must still be a substantial
    // late candidate rather than an early tiny fragment.
    try std.testing.expect(late_clip_start_samples >= sample_rate * 10);
    try std.testing.expect(clips[2].samples.len >= sample_rate * 7 / 10);
}

test "fft_analyzer: real Arkose odd-animal file rejects tiny fragment candidates" {
    const allocator = std.testing.allocator;
    var io_impl = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();
    const cwd = std.Io.Dir.cwd();

    const file = cwd.openFile(io, "tmp/audio_challenge_1777657494_0.f32", .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer file.close(io);

    const file_size = try file.length(io);
    const raw_bytes = try allocator.alloc(u8, file_size);
    defer allocator.free(raw_bytes);
    _ = try std.Io.File.readPositionalAll(file, io, raw_bytes, 0);

    const samples = @as([]const f32, @alignCast(std.mem.bytesAsSlice(f32, raw_bytes)));
    const clips = try extractThreeLargestSegments(samples, 44100, .{});

    const min_reasonable_clip = 600 * 44100 / 1000;
    try std.testing.expect(clips[0].samples.len >= min_reasonable_clip);
    try std.testing.expect(clips[1].samples.len >= min_reasonable_clip);
    try std.testing.expect(clips[2].samples.len >= min_reasonable_clip);
}

test "fft_analyzer: live odd-animal files avoid repeated short-fragment trio" {
    const allocator = std.testing.allocator;
    const paths = [_][]const u8{
        "tmp/audio_challenge_1777661761_0.f32",
        "tmp/audio_challenge_1777661763_0.f32",
        "tmp/audio_challenge_1777661765_0.f32",
        "tmp/audio_challenge_1777661766_0.f32",
        "tmp/audio_challenge_1777661768_0.f32",
        "tmp/audio_challenge_1777661769_0.f32",
        "tmp/audio_challenge_1777661771_0.f32",
        "tmp/audio_challenge_1777661773_0.f32",
        "tmp/audio_challenge_1777661774_0.f32",
        "tmp/audio_challenge_1777661776_0.f32",
    };

    var io_impl = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();
    const cwd = std.Io.Dir.cwd();
    const min_reasonable_clip = 600 * 44100 / 1000;

    for (paths) |path| {
        const file = cwd.openFile(io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer file.close(io);

        const file_size = try file.length(io);
        const raw_bytes = try allocator.alloc(u8, file_size);
        defer allocator.free(raw_bytes);
        _ = try std.Io.File.readPositionalAll(file, io, raw_bytes, 0);

        const samples = @as([]const f32, @alignCast(std.mem.bytesAsSlice(f32, raw_bytes)));
        const clips = try extractThreeLargestSegments(samples, 44100, .{});

        try std.testing.expect(clips[0].samples.len >= min_reasonable_clip);
        try std.testing.expect(clips[1].samples.len >= min_reasonable_clip);
        try std.testing.expect(clips[2].samples.len >= min_reasonable_clip);
    }
}

test "fft_analyzer: live odd-animal files produce stable non-ambiguous outlier result" {
    const allocator = std.testing.allocator;
    const paths = [_][]const u8{
        "tmp/audio_challenge_1777661761_0.f32",
        "tmp/audio_challenge_1777661766_0.f32",
    };

    var io_impl = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();
    const cwd = std.Io.Dir.cwd();

    for (paths) |path| {
        const file = cwd.openFile(io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer file.close(io);

        const file_size = try file.length(io);
        const raw_bytes = try allocator.alloc(u8, file_size);
        defer allocator.free(raw_bytes);
        _ = try std.Io.File.readPositionalAll(file, io, raw_bytes, 0);

        const samples = @as([]const f32, @alignCast(std.mem.bytesAsSlice(f32, raw_bytes)));
        const clips = try extractThreeLargestSegments(samples, 44100, .{});
        const clip_inputs = [_]ClipInput{
            .{ .samples = clips[0].samples, .sample_rate = 44100 },
            .{ .samples = clips[1].samples, .sample_rate = 44100 },
            .{ .samples = clips[2].samples, .sample_rate = 44100 },
        };
        const result = try analyzeOutlier(&clip_inputs, .different, .{});
        try std.testing.expect(result.guess >= 1 and result.guess <= 3);
        try std.testing.expect(result.confidence >= 0.05);
    }
}

test "fft_analyzer: gerçek Arkose audio verisi ile analiz" {
    const allocator = std.testing.allocator;
    var io_impl = std.Io.Threaded.init(std.testing.allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();
    const cwd = std.Io.Dir.cwd();

    const file = cwd.openFile(io, "tmp/audio_live.f32", .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
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
