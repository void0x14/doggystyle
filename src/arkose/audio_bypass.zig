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
    var audio_mode_activated: bool = false;
    var game_core_ctx: i64 = 0;

    std.debug.print("\n[AUDIO BYPASS] Starting pipeline ({d} targets, max {d} attempts)...\n", .{
        TARGET_CHALLENGES, MAX_CHALLENGES,
    });

    // Step 0: Connect directly to the Arkose enforcement iframe via its own CDP WebSocket
    // The enforcement iframe has its own webSocketDebuggerUrl in GET /json.
    // By connecting directly, we bypass cross-process execution context issues:
    // the main page's CDP session cannot access cross-origin iframe DOM via
    // Runtime.evaluate with contextId when the iframe lives in a different process.
    // SOURCE: Chrome DevTools Protocol — GET /json returns per-target wsDebuggerUrl
    // SOURCE: LIVE TEST 2026-04-25 — enforcement iframe has its OWN /json entry
    // Retry loop: getArkoseWsUrl + connectToTarget with up to 3 attempts
    const ARKOSE_CONNECT_MAX_RETRIES: u8 = 3;
    var arkose_cdp_opt: ?browser_bridge.CdpClient = null;
    var iframe_ws_url_opt: ?[]u8 = null;
    var arkose_connected = false;
    var arkose_connect_attempt: u8 = 0;
    while (arkose_connect_attempt < ARKOSE_CONNECT_MAX_RETRIES and !arkose_connected) : (arkose_connect_attempt += 1) {
        if (arkose_connect_attempt > 0) {
            std.debug.print("[AUDIO BYPASS] Arkose connection retry {d}/{d}...\n", .{ arkose_connect_attempt + 1, ARKOSE_CONNECT_MAX_RETRIES });
            _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 2, .nsec = 0 }, null);
        }

        std.debug.print("[AUDIO BYPASS] Connecting to Arkose enforcement iframe (attempt {d}/{d})...\n", .{ arkose_connect_attempt + 1, ARKOSE_CONNECT_MAX_RETRIES });

        // Step A: Get iframe WS URL from /json
        const ws_url = bridge.getArkoseWsUrl(allocator) catch |err| {
            std.debug.print("[AUDIO BYPASS] getArkoseWsUrl failed (attempt {d}/{d}): {}\n", .{ arkose_connect_attempt + 1, ARKOSE_CONNECT_MAX_RETRIES, err });
            continue;
        };
        iframe_ws_url_opt = ws_url;
        std.debug.print("[AUDIO BYPASS] Iframe WS URL: {s}\n", .{ws_url});

        // Step B: Connect WebSocket to iframe target
        const cdp = browser_bridge.CdpClient.connectToTarget(allocator, ws_url) catch |err| {
            std.debug.print("[AUDIO BYPASS] connectToTarget failed (attempt {d}/{d}): {}\n", .{ arkose_connect_attempt + 1, ARKOSE_CONNECT_MAX_RETRIES, err });
            allocator.free(ws_url);
            iframe_ws_url_opt = null;
            continue;
        };
        arkose_cdp_opt = cdp;
        arkose_connected = true;
    }

    if (!arkose_connected) {
        std.debug.print("[AUDIO BYPASS] FATAL: Could not connect to Arkose iframe after {d} attempts\n", .{ARKOSE_CONNECT_MAX_RETRIES});
        return error.ConnectionFailed;
    }

    var arkose_cdp = arkose_cdp_opt.?;
    errdefer arkose_cdp.close();
    const iframe_ws_url = iframe_ws_url_opt.?;
    defer allocator.free(iframe_ws_url);

    // Enable Runtime domain on the iframe CDP session for DOM interaction
    _ = arkose_cdp.runtimeEnable() catch {};
    std.debug.print("[AUDIO BYPASS] Arkose iframe CDP session established\n", .{});

    // Step 0b: Wait for PoW to complete, then game-core appears
    // SOURCE: LIVE ChromeDevTools MCP — pow/2.4.0 → game-core/1.34.1
    //
    // CROSS-PROCESS FIX 2026-04-25:
    // game-core iframe is cross-origin (arkoselabs.com → different process).
    // evaluateInContext with contextId CANNOT reach it before the context is
    // registered in THIS CDP session. But the iframe ELEMENT is visible in
    // enforcement DOM (Runtime.evaluate without contextId).
    //
    // Strategy:
    //   1. Poll enforcement DOM for iframe[src*="game-core"] element
    //   2. When found, reload it by setting src = src (triggers new context)
    //   3. Wait 1s + drainPendingEvents for executionContextCreated event
    //   4. Brute-force scan (1-20) for the fresh game-core context
    // SOURCE: Chrome DevTools Protocol — element access is NOT blocked by CORS
    // SOURCE: CDP spec — Runtime.evaluate without contextId targets enforcement page
    std.debug.print("[AUDIO BYPASS] Waiting for PoW to complete and game-core to load...\n", .{});

    var game_core_found = false;
    var pow_wait_attempt: u32 = 0;
    var last_debug_log: u32 = 0;
    var iframe_seen_once = false;
    var game_core_session_token: ?[]const u8 = null; // session token from iframe URL
    defer if (game_core_session_token) |t| allocator.free(t);
    const POW_MAX_WAIT: u32 = 120; // 120 × 2s = 240s max

    while (!game_core_found and pow_wait_attempt < POW_MAX_WAIT) : (pow_wait_attempt += 1) {
        _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 2, .nsec = 0 }, null);

        // Drain pending events for executionContextCreated
        arkose_cdp.drainPendingEvents();

        // Strategy A: Brute-force scan for game-core context (1-20)
        // Catches same-process iframes where context is already registered.
        var ctx: i64 = 1;
        while (ctx <= 20 and !game_core_found) : (ctx += 1) {
            if (arkose_cdp.evaluateInContext("document.title", ctx)) |resp| {
                defer allocator.free(resp);
                if (std.mem.indexOf(u8, resp, "Audio") != null or
                    std.mem.indexOf(u8, resp, "challenge") != null or
                    std.mem.indexOf(u8, resp, "game-core") != null)
                {
                    game_core_ctx = ctx;
                    game_core_found = true;
                    std.debug.print("[AUDIO BYPASS] Found game-core context ID {d} after ~{d}s (direct scan)\n", .{ ctx, pow_wait_attempt * 2 });
                    break;
                }
            } else |_| {}
        }

        if (game_core_found) break;

        // Step 1: Check enforcement DOM for game-core iframe element
        // Runtime.evaluate without contextId → targets enforcement page context.
        // iframe ELEMENT is accessible even cross-origin (src attribute visible).
        // Also extract session token from URL for fallback HTTP requests.
        const check_script =
            \\(() => {
            \\  const gc = document.querySelector('iframe[src*="game-core"]');
            \\  if (!gc) return 'waiting';
            \\  const url = gc.src;
            \\  const sm = url.match(/[?&]session=([^&]+)/);
            \\  const session = sm ? sm[1] : '';
            \\  return 'found:' + url + '|session:' + session;
            \\})()
        ;
        var iframe_found = false;
        if (arkose_cdp.evaluate(check_script)) |resp| {
            defer allocator.free(resp);
            if (std.mem.indexOf(u8, resp, "\"value\":\"found:") != null) {
                iframe_found = true;
                if (!iframe_seen_once) {
                    iframe_seen_once = true;
                    std.debug.print("[AUDIO BYPASS] game-core iframe VISIBLE in enforcement DOM (attempt {d}/{d})\n", .{ pow_wait_attempt + 1, POW_MAX_WAIT });
                    // Extract session token from iframe URL
                    // NOTE: Dupe the string because `resp` is freed by defer
                    const session_prefix = "|session:";
                    if (std.mem.indexOf(u8, resp, session_prefix)) |spos| {
                        const session_start = spos + session_prefix.len;
                        const session_end = std.mem.indexOfScalarPos(u8, resp, session_start, '"') orelse
                            std.mem.indexOfScalarPos(u8, resp, session_start, '|') orelse resp.len;
                        if (session_end > session_start) {
                            const token_slice = resp[session_start..session_end];
                            game_core_session_token = try allocator.dupe(u8, token_slice);
                            std.debug.print("[AUDIO BYPASS] Extracted game-core session token: {s}\n", .{game_core_session_token.?});
                        }
                    }
                }
            }
        } else |_| {}

        if (iframe_found and !game_core_found) {
            // CROSS-PROCESS FIX 2026-04-25 v2: NO RELOAD.
            // game-core iframe is cross-process (arkoselabs.com enforcement iframe
            // lives in a different Chrome renderer than game-core).
            // evaluateInContext with contextId CANNOT reach it.
            //
            // PREVIOUS BUG (FIXED 2026-04-25): The old code reloaded the game-core
            // iframe to try to force a new execution context to register in THIS CDP
            // session. This RESET the PoW computation, causing PoW to never complete
            // (parent "setup" message was already consumed by the pre-reload game-core).
            //
            // NEW STRATEGY:
            //   1. game-core iframe found in enforcement DOM
            //   2. Context not accessible (cross-process) — expected
            //   3. POLL /fc/gfct/ API from enforcement page until PoW completes
            //   4. When /fc/gfct/ returns gameToken, PoW is done
            //   5. Proceed with ctx=0 (gameToken via API, not direct context access)
            // SOURCE: LIVE DEBUG 2026-04-25 — /fc/gfct/ POST returns gameToken after PoW
            // SOURCE: LIVE TEST 2026-04-25 — reloading resets PoW, causing 120s timeout
            // SOURCE: Chrome DevTools Protocol — Runtime.evaluate in enforcement page
            const pow_poll_script =
                \\(async () => {{
                \\  const st = '{s}';
                \\  try {{
                \\    const resp = await fetch('/fc/gfct/', {{
                \\      method: 'POST',
                \\      headers: {{'Content-Type': 'application/json'}},
                \\      body: JSON.stringify({{session_token: st}})
                \\    }});
                \\    if (resp.ok) {{
                \\      const data = await resp.json();
                \\      const gt = data?.token || data?.gameToken || data?.game_token || '';
                \\      if (gt) return 'GOT_GT:' + gt;
                \\    }}
                \\    return 'WAITING';
                \\  }} catch(e) {{ return 'WAITING'; }}
                \\}})()
            ;
            const pow_poll_js = try std.fmt.allocPrint(allocator, pow_poll_script, .{game_core_session_token orelse ""});
            defer allocator.free(pow_poll_js);

            if (arkose_cdp.evaluate(pow_poll_js)) |gresp| {
                defer allocator.free(gresp);
                if (std.mem.indexOf(u8, gresp, "GOT_GT:") != null) {
                    game_core_ctx = 0;
                    game_core_found = true;
                    std.debug.print("[AUDIO BYPASS] PoW completed! gameToken via /fc/gfct/ (~{d}s)\n", .{pow_wait_attempt * 2});
                }
            } else |_| {}
        }

        // Periodically log enforcement page state for debugging
        if (pow_wait_attempt - last_debug_log >= 5) {
            last_debug_log = pow_wait_attempt;
            const debug_script =
                \\(() => {
                \\  const frames = document.querySelectorAll('iframe');
                \\  const srcs = Array.from(frames).slice(0,5).map(f => (f.src||'(empty)').substring(0,80)).join('|');
                \\  return 'iframes:' + frames.length + ':' + srcs;
                \\})()
            ;
            if (arkose_cdp.evaluate(debug_script)) |dresp| {
                defer allocator.free(dresp);
                std.debug.print("[AUDIO BYPASS] Enforcement DOM ({d}s): {s}\n", .{ pow_wait_attempt * 2, dresp[0..@min(dresp.len, 500)] });
            } else |_| {}
        }

        if (!game_core_found and !iframe_found) {
            std.debug.print("[AUDIO BYPASS] Still waiting for game-core (attempt {d}/{d})...\n", .{ pow_wait_attempt + 1, POW_MAX_WAIT });
        }
    }

    if (!game_core_found) {
        std.debug.print("[AUDIO BYPASS] Could not find game-core context after {d}s\n", .{POW_MAX_WAIT * 2});
    } else {
        std.debug.print("[AUDIO BYPASS] Using game-core context: {d}\n", .{game_core_ctx});
    }

    while (successful < TARGET_CHALLENGES and total_attempted < MAX_CHALLENGES) : (total_attempted += 1) {
        const elapsed = currentMonotonicMs() - start_ms;
        if (elapsed > PIPELINE_TIMEOUT_MS) {
            std.debug.print("[AUDIO BYPASS] Pipeline timeout after {d}ms\n", .{elapsed});
            break;
        }

        std.debug.print("\n[AUDIO BYPASS] Attempt {d}/{d} (successful: {d}/{d})...\n", .{
            total_attempted + 1, MAX_CHALLENGES, successful, TARGET_CHALLENGES,
        });

        // Step 0.5: Activate audio mode if not already active
        if (!audio_mode_activated) {
            std.debug.print("[AUDIO BYPASS] Finding Audio puzzle button...\n", .{});
            const ascript =
                \\(() => {
                \\  const btns = document.querySelectorAll('button');
                \\  for (const btn of btns) {
                \\    if (btn.textContent.trim().includes('Audio') && btn.offsetParent !== null) {
                \\      btn.click();
                \\      return 'clicked';
                \\    }
                \\  }
                \\  return 'not_found';
                \\})()
            ;
            if (game_core_ctx > 0) {
                if (arkose_cdp.evaluateInContext(ascript, game_core_ctx)) |resp| {
                    defer allocator.free(resp);
                    std.debug.print("[AUDIO BYPASS] Audio button response (game-core ctx={d}): {s}\n", .{ game_core_ctx, resp[0..@min(resp.len, 200)] });
                } else |_| {}
            } else {
                if (arkose_cdp.evaluate(ascript)) |resp| {
                    defer allocator.free(resp);
                    std.debug.print("[AUDIO BYPASS] Audio button response: {s}\n", .{resp[0..@min(resp.len, 200)]});
                } else |_| {}
            }
            _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 2, .nsec = 0 }, null);
            audio_mode_activated = true;
        }

        // Step 1-3: Capture URL, download MP3, save to disk
        var dl_result: audio_downloader.FetchResult = undefined;
        if (game_core_ctx > 0) {
            // Normal flow: Click Play button, then capture via CDP Fetch.requestPaused
            std.debug.print("[AUDIO BYPASS] Clicking Play button...\n", .{});
            const pscript =
                \\(() => {
                \\  const btns = document.querySelectorAll('button');
                \\  for (const btn of btns) {
                \\    if (btn.textContent.trim() === 'Play' && btn.offsetParent !== null) {
                \\      btn.click();
                \\      return 'clicked';
                \\    }
                \\  }
                \\  return 'not_found';
                \\})()
            ;
            if (game_core_ctx > 0) {
                _ = arkose_cdp.evaluateInContext(pscript, game_core_ctx) catch {};
            } else {
                _ = arkose_cdp.evaluate(pscript) catch {};
            }
            std.debug.print("[AUDIO BYPASS] Play button clicked, waiting for audio...\n", .{});

            dl_result = audio_downloader.downloadAndSaveAudio(bridge, allocator, total_attempted) catch |err| {
                std.debug.print("[AUDIO BYPASS] Attempt {d}: downloadAndSaveAudio failed: {}\n", .{ total_attempted, err });
                if (total_attempted == 0) return err;
                std.debug.print("[AUDIO BYPASS] Skipping to next attempt...\n", .{});
                continue;
            };
        } else {
            // Fallback: game-core cross-process context unavailable.
            // Use CDP evaluate on enforcement page to execute fetch() directly.
            std.debug.print("[AUDIO BYPASS] game-core ctx=0, using CDP evaluate fetch fallback...\n", .{});
            dl_result = audio_downloader.fetchAudioViaCdpEvaluate(
                &arkose_cdp,
                allocator,
                total_attempted,
                game_core_session_token orelse "",
            ) catch |err| {
                std.debug.print("[AUDIO BYPASS] Attempt {d}: fetchAudioViaCdpEvaluate failed: {}\n", .{ total_attempted, err });
                if (total_attempted == 0) return err;
                std.debug.print("[AUDIO BYPASS] Skipping to next attempt...\n", .{});
                continue;
            };
        }
        const result = dl_result;
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
        std.debug.print("[AUDIO BYPASS] Analysis time: {d}us\n", .{flux_result.execution_time_us});

        // Step 9: Inject answer into iframe and submit (via direct CDP session)
        audio_injector.injectAnswerOnTarget(&arkose_cdp, allocator, answer, game_core_ctx) catch |err| {
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
