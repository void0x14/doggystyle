// =============================================================================
// Module — Arkose Audio CAPTCHA Bypass: Otomatik Pipeline
// =============================================================================
//
// WIRE-TRUTH ANALYSIS (LIVE TEST 2026-04-24):
// - Arkose Labs Audio CAPTCHA serves a SINGLE MP3 (~18-21s, 44100Hz mono)
// - Single MP3 contains 3 speaker segments concatenated
// - Pipeline splits PCM into 3 equal parts for spectral flux comparison
// - Answer = index of segment with highest spectral flux delta + 1
//
// Pipeline akışı (her challenge için):
//   1. captureAudioUrl(s) → rtag/audio?challenge=N URL'sini CDP Fetch ile yakala
//   2. downloadAudioClip → MP3'ü TLS HTTP/1.1 üzerinden indir
//   3. saveAudioDataToDisk → tmp/audio_challenge_N.mp3 olarak kaydet
//   4. probeAudioMetadata → ffprobe ile sample_rate, channels, duration
//   5. convertToPcmF32 → ffmpeg ile MP3 → PCM f32le (44100Hz mono)
//   6. peakNormalize → 0dBFS tepe noktasına normalize et
//   7. analyze → 3 parçaya böl, spectral flux hesapla, en yüksek delta'yı bul
//   8. guess+1 = answer → browser'a inject et, Submit'e tıkla
//   9. 5/5 challenge tamamlanana kadar tekrarla (max 10)
//
// SOURCE: Live test 2026-04-24 — rtag/audio endpoint, 44100Hz mono MP3, 18-21s
// SOURCE: RFC 7916 — Spectral Flux analysis (Scheirer & Slaney, 1997)

const std = @import("std");
const audio_downloader = @import("audio_downloader.zig");
const audio_decoder = @import("audio_decoder.zig");
const fft_analyzer = @import("../audio/fft_analyzer.zig");
const audio_injector = @import("audio_injector.zig");
const browser_bridge = @import("../browser_bridge.zig");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of audio challenges to solve
pub const MAX_CHALLENGES: u8 = 10;

/// Target number of challenges to complete
pub const TARGET_CHALLENGES: u8 = 5;

/// Number of equal clips to split audio into
pub const CLIP_SPLIT: u8 = 3;

/// Maximum execution time for the entire pipeline (5 minutes)
pub const PIPELINE_TIMEOUT_MS: u64 = 300000;

// ---------------------------------------------------------------------------
// AudioBypassResult
// ---------------------------------------------------------------------------

// SOURCE: Pipeline output format — structured result for main.zig
pub const AudioBypassResult = struct {
    /// Last challenge's 0-indexed guess (add 1 for 1-indexed answer)
    guess: u8,
    /// Total execution time in milliseconds
    execution_time_ms: u64,
    /// Total challenges processed (max MAX_CHALLENGES)
    total_challenges: u8,
    /// Whether all target challenges completed successfully
    success: bool,
};

comptime {
    std.debug.assert(@sizeOf(AudioBypassResult) > 0);
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

fn currentMonotonicMs() u64 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1000 + @as(u64, @intCast(ts.nsec)) / 1000000;
}

// ---------------------------------------------------------------------------
// runAudioBypass — Ana pipeline orkestratörü
// ---------------------------------------------------------------------------
//
// SOURCE: Arkose Labs Audio CAPTCHA — 5 challenge sequence (live test 2026-04-24)
//
// Tüm audio bypass sürecini otomatikleştirir:
//   1. Her challenge için audio URL yakala, MP3 indir, decode et
//   2. Spectral flux analizi ile hangi segmentin farklı olduğunu bul
//   3. Cevabı browser'a inject et ve submit et
//   4. Hata olursa challenge'ı atla (ilk challenge hatası fatal)
//   5. Max 10 challenge, 5 başarılı yeter
//
pub fn runAudioBypass(
    bridge: *browser_bridge.BrowserBridge,
    allocator: std.mem.Allocator,
    io: std.Io,
) !AudioBypassResult {
    const start_ms = currentMonotonicMs();
    var last_guess: u8 = 0;
    var successful: u8 = 0;
    var total_attempted: u8 = 0;

    std.debug.print("\n[AUDIO BYPASS] Starting pipeline ({d} targets, max {d} attempts)...\n", .{
        TARGET_CHALLENGES, MAX_CHALLENGES,
    });

    while (successful < TARGET_CHALLENGES and total_attempted < MAX_CHALLENGES) : (total_attempted += 1) {
        const elapsed = currentMonotonicMs() - start_ms;
        if (elapsed > PIPELINE_TIMEOUT_MS) {
            std.debug.print("[AUDIO BYPASS] Pipeline timeout after {d}ms\n", .{elapsed});
            break;
        }

        std.debug.print("\n[AUDIO BYPASS] Attempt {d}/{d} (successful: {d}/{d})...\n", .{
            total_attempted + 1, MAX_CHALLENGES, successful, TARGET_CHALLENGES,
        });

        // Step 1-3: Capture URL, download MP3, save to disk
        const result = audio_downloader.downloadAndSaveAudio(bridge, allocator, total_attempted) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: download failed: {}\n", .{ total_attempted, err });
            if (total_attempted == 0) return err;
            std.debug.print("[AUDIO BYPASS] Skipping to next attempt...\n", .{});
            continue;
        };
        defer {
            allocator.free(result.url);
            allocator.free(result.path);
            allocator.free(result.data);
        }

        // Step 4: Probe metadata
        const meta = audio_decoder.probeAudioMetadata(allocator, io, result.path) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: probeAudioMetadata failed: {}\n", .{ total_attempted, err });
            continue;
        };
        std.debug.print("[AUDIO BYPASS] Metadata: {d}Hz, {d}ch, {d}bit, {d:.2}s, {s}\n", .{
            meta.sample_rate, meta.channels, meta.bit_depth, meta.duration_seconds, meta.format,
        });

        // Step 5: Convert to PCM f32le
        const decoded = audio_decoder.convertToPcmF32(allocator, io, result.path, meta.sample_rate) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: convertToPcmF32 failed: {}\n", .{ total_attempted, err });
            continue;
        };
        defer allocator.free(decoded.samples);
        std.debug.print("[AUDIO BYPASS] Decoded: {d} f32 samples ({d:.2}s)\n", .{ decoded.total_samples, meta.duration_seconds });

        // Step 6: Peak normalize
        const normalized = audio_decoder.peakNormalize(allocator, decoded.samples) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: peakNormalize failed: {}\n", .{ total_attempted, err });
            continue;
        };
        defer allocator.free(normalized.normalized);
        std.debug.print("[AUDIO BYPASS] Normalized: scale={d:.4}\n", .{normalized.scale});

        // Step 7: Split into 3 equal clips and analyze spectral flux
        if (normalized.normalized.len < CLIP_SPLIT) {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: audio too short ({d} samples)\n", .{ total_attempted, normalized.normalized.len });
            continue;
        }
        const clip_len = normalized.normalized.len / CLIP_SPLIT;
        const clips = [_][]const f32{
            normalized.normalized[0..clip_len],
            normalized.normalized[clip_len .. 2 * clip_len],
            normalized.normalized[2 * clip_len ..],
        };

        const flux_result = fft_analyzer.analyze(allocator, &clips, meta.sample_rate) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: FFT analyze failed: {}\n", .{ total_attempted, err });
            continue;
        };

        // Step 8: Answer = guess + 1 (1-indexed)
        last_guess = flux_result.guess;
        const answer: u8 = flux_result.guess + 1;
        std.debug.print("[AUDIO BYPASS] Spectral flux: [{d:.6}, {d:.6}, {d:.6}]\n", .{
            flux_result.deltas[0], flux_result.deltas[1], flux_result.deltas[2],
        });
        std.debug.print("[AUDIO BYPASS] Guess (highest delta): {d} -> Answer: {d}\n", .{ flux_result.guess, answer });
        std.debug.print("[AUDIO BYPASS] Analysis time: {d}ms\n", .{flux_result.execution_time_ms});

        // Step 9: Inject answer into browser and submit
        audio_injector.injectAnswer(bridge, answer) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: inject/submit failed: {}\n", .{ total_attempted, err });
            continue;
        };

        successful += 1;
        std.debug.print("[AUDIO BYPASS] Challenge {d}/{d} DONE\n", .{ successful, TARGET_CHALLENGES });
    }

    const end_ms = currentMonotonicMs();
    const elapsed = end_ms - start_ms;
    const all_success = successful >= TARGET_CHALLENGES;

    std.debug.print("[AUDIO BYPASS] Pipeline complete: {d}/{d} challenges, {d}ms\n", .{
        successful, TARGET_CHALLENGES, elapsed,
    });

    return AudioBypassResult{
        .guess = last_guess,
        .execution_time_ms = elapsed,
        .total_challenges = successful,
        .success = all_success,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "audio_bypass: AudioBypassResult struct size" {
    try std.testing.expect(@sizeOf(AudioBypassResult) > 0);
}

test "audio_bypass: constants are valid" {
    try std.testing.expect(MAX_CHALLENGES >= TARGET_CHALLENGES);
    try std.testing.expect(TARGET_CHALLENGES > 0);
    try std.testing.expect(CLIP_SPLIT == 3);
    try std.testing.expect(PIPELINE_TIMEOUT_MS > 0);
}

test "audio_bypass: runAudioBypass returns error without bridge" {
    try std.testing.expect(@TypeOf(runAudioBypass) == fn (
        *browser_bridge.BrowserBridge,
        std.mem.Allocator,
        std.Io,
    ) anyerror!AudioBypassResult);
}
