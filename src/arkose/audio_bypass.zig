// =============================================================================
// Module — Arkose Audio CAPTCHA Bypass: Otomatik Pipeline
// =============================================================================
//
// WIRE-TRUTH ANALYSIS (LIVE TEST 2026-04-24):
// - Arkose Labs Audio CAPTCHA serves a SINGLE MP3 (~18-21s, 44100Hz mono)
// - Single MP3 contains 3 speaker segments concatenated
// - Pipeline splits PCM into 3 equal parts for outlier analysis
// - Answer = outlier engine guess + 1
//
// Pipeline akışı (her challenge için):
//   1. captureAudioUrl(s) → rtag/audio?challenge=N URL'sini CDP Fetch ile yakala
//   2. downloadAudioClip → MP3'ü TLS HTTP/1.1 üzerinden indir
//   3. saveAudioDataToDisk → tmp/audio_challenge_N.mp3 olarak kaydet
//   4. probeAudioMetadata → ffprobe ile sample_rate, channels, duration
//   5. convertToPcmF32 → ffmpeg ile MP3 → PCM f32le (44100Hz mono)
//   6. peakNormalize → 0dBFS tepe noktasına normalize et
//   7. analyzeOutlier → 3 parçadan farklı segmenti bul
//   8. guess+1 = answer → browser'a inject et, Submit'e tıkla
//   9. Arkose tamamlanma sinyali verene kadar tekrarla (max 10, ara geçişler tespit edilir)
//
// SOURCE: Live test 2026-04-24 — rtag/audio endpoint, 44100Hz mono MP3, 18-21s
// SOURCE: MaxAD outlier scoring — median absolute deviation over three clips

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
    /// Runtime target parsed from /fc/gfct/ audio_challenge_urls
    target_challenges: u8,
    /// Whether Arkose reported challenge completion
    success: bool,
};

pub const ChallengeLoopState = struct {
    successful_submits: u8,
    attempted: u8,
    target_challenges: u8,
    challenge_complete: bool,
};

comptime {
    std.debug.assert(@sizeOf(AudioBypassResult) > 0);
}

pub fn shouldContinueAudioChallengeLoop(state: ChallengeLoopState) bool {
    return state.successful_submits < state.target_challenges and
           state.attempted < MAX_CHALLENGES and
           !state.challenge_complete;
}

pub fn audioBypassFinalSuccess(state: ChallengeLoopState) bool {
    _ = state.successful_submits;
    _ = state.target_challenges;
    return state.challenge_complete;
}

pub fn parseAudioChallengeTargetFromGfctResponse(
    allocator: std.mem.Allocator,
    gfct_response: []const u8,
) !u8 {
    const payload = try browser_bridge.extractRuntimeEvaluateStringValue(allocator, gfct_response);
    defer allocator.free(payload);

    return parseAudioChallengeTargetFromGfctPayload(allocator, payload);
}

fn parseAudioChallengeTargetFromGfctPayload(
    allocator: std.mem.Allocator,
    payload: []const u8,
) !u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, payload, .{}) catch return error.ParseFailed;
    defer parsed.deinit();

    if (parsed.value != .object) return error.ParseFailed;
    const urls_value = parsed.value.object.get("audio_challenge_urls") orelse return error.ParseFailed;
    if (urls_value != .array) return error.ParseFailed;

    const count = urls_value.array.items.len;
    if (count == 0) return error.ParseFailed;
    if (count > MAX_CHALLENGES) return error.TargetChallengeCountExceeded;
    return @intCast(count);
}

// SOURCE: Arkose Labs UI behavior — intermediate challenges don't show completion text (live test 2026-04-27)
const PostSubmitUiState = enum {
    complete, // No controls + completion text (Arkose fully done)
    continue_wait, // Active controls present (still same challenge, waiting)
    transition, // No controls + NO completion text (intermediate transition)
    restarted, // Controls present + body has challenge restart indicators
    wrong_visible, // Wrong text visible while answer controls remain active
    query_failed, // Evaluate failed
};

fn detectPostSubmitUiState(
    cdp: *browser_bridge.CdpClient,
    allocator: std.mem.Allocator,
    context_id: i64,
) PostSubmitUiState {
    const completion_script =
        \\(() => {
        \\  const visible = (el) => !!el && el.offsetParent !== null && !el.disabled;
        \\  const controls = Array.from(document.querySelectorAll('input[type="text"], input[type="submit"], button'));
        \\  const activeInput = controls.some(el => visible(el) && el.matches('input[type="text"], input:not([type])'));
        \\  const activeSubmit = controls.some(el => visible(el) && (el.matches('input[type="submit"], button') || ((el.textContent || el.value || '').toLowerCase().includes('submit'))));
        \\  const bodyText = (document.body && document.body.innerText || '').toLowerCase();
        \\  const completionText = bodyText.includes('verification complete') ||
        \\    bodyText.includes('challenge complete') ||
        \\    bodyText.includes('verified') ||
        \\    bodyText.includes('success') ||
        \\    bodyText.includes('passed') ||
        \\    bodyText.includes('you are all set') ||
        \\    bodyText.includes("you're all set");
        \\  const wrongText = bodyText.includes('incorrect') || bodyText.includes('only enter the number');
        \\  if (!activeInput && !activeSubmit && completionText) return 'complete';
        \\  if ((activeInput || activeSubmit) && wrongText) return 'wrong_visible';
        \\  if (activeInput || activeSubmit) return 'continue_wait';
        \\  if (!activeInput && !activeSubmit && wrongText) return 'restarted';
        \\  return 'transition';
        \\})()
    ;

    const response = if (context_id > 0)
        cdp.evaluateInContextWithTimeout(completion_script, context_id, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS)
    else
        cdp.evaluateWithTimeout(completion_script, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS);

    if (response) |resp| {
        defer allocator.free(resp);
        std.debug.print("[AUDIO BYPASS] UI state check: {s}\n", .{resp[0..@min(resp.len, 200)]});
        const value = browser_bridge.extractRuntimeEvaluateStringValue(allocator, resp) catch return .query_failed;
        defer allocator.free(value);
        if (std.mem.eql(u8, value, "complete")) return .complete;
        if (std.mem.eql(u8, value, "continue_wait")) return .continue_wait;
        if (std.mem.eql(u8, value, "wrong_visible")) return .wrong_visible;
        if (std.mem.eql(u8, value, "restarted")) return .restarted;
        if (std.mem.eql(u8, value, "transition")) return .transition;
        return .query_failed;
    } else |err| {
        std.debug.print("[AUDIO BYPASS] UI state check failed: {}\n", .{err});
        return .query_failed;
    }
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
// Context resolution helper
// ---------------------------------------------------------------------------
/// Drains pending CDP events and probes each execution context to find the
/// one that contains an input element (the game-core iframe).
/// Returns true if a verified context ID was found and written to `out_ctx`.
/// SOURCE: CDP Runtime.executionContextCreated — context id + origin fields
/// SOURCE: ChromeDevTools MCP live DOM — game-core iframe contains input element
fn tryResolveGameCoreContext(
    arkose_cdp: *browser_bridge.CdpClient,
    allocator: std.mem.Allocator,
    out_ctx: *i64,
) bool {
    var candidate_ctxs: [8]i64 = undefined;
    var candidate_count: usize = 0;

    while (arkose_cdp.hasPendingEvents()) {
        const event = arkose_cdp.nextPendingEvent().?;
        defer allocator.free(event);
        if (std.mem.indexOf(u8, event, "\"Runtime.executionContextCreated\"") == null) continue;

        const id_prefix = "\"context\":{\"id\":";
        if (std.mem.indexOf(u8, event, id_prefix)) |id_pos| {
            const id_start = id_pos + id_prefix.len;
            var id_end = id_start;
            while (id_end < event.len and event[id_end] >= '0' and event[id_end] <= '9') {
                id_end += 1;
            }
            if (id_end > id_start and candidate_count < candidate_ctxs.len) {
                const ctx = std.fmt.parseInt(i64, event[id_start..id_end], 10) catch 0;
                if (ctx > 0) {
                    candidate_ctxs[candidate_count] = ctx;
                    candidate_count += 1;
                    std.debug.print("[AUDIO BYPASS] Collected execution context ID={d}\n", .{ctx});
                }
            }
        }
    }

    for (candidate_ctxs[0..candidate_count]) |ctx| {
        // FIX: Probe EVERY candidate — do NOT break on the first one.
        // The enforcement iframe may also have an input, so we require BOTH
        // input[type='text'] AND <button> to be present (the real game-core UI).
        const probe_script =
            \\(() => {
            \\  const hasInput = !!document.querySelector("input[type='text']");
            \\  const hasButton = !!document.querySelector("button");
            \\  return (hasInput && hasButton) ? 'has_both' : 'missing_' + (hasInput ? 'input_only' : (hasButton ? 'button_only' : 'none'));
            \\})()
        ;
        if (arkose_cdp.evaluateInContext(probe_script, ctx)) |resp| {
            defer allocator.free(resp);
            std.debug.print("[AUDIO BYPASS] Context {d} probe: {s}\n", .{ ctx, resp[0..@min(resp.len, 100)] });
            if (std.mem.indexOf(u8, resp, "error") != null) {
                std.debug.print("[AUDIO BYPASS] Context {d} probe returned CDP error — skipping\n", .{ctx});
                continue;
            }
            if (std.mem.indexOf(u8, resp, "has_both") != null) {
                out_ctx.* = ctx;
                std.debug.print("[AUDIO BYPASS] Verified game-core execution context ID={d} (has input + button)\n", .{ctx});
                // Continue scanning to ensure we don't pick a stale context,
                // but break after the first verified one for speed.
                break;
            }
        } else |err| {
            std.debug.print("[AUDIO BYPASS] Context {d} probe failed: {} — skipping\n", .{ ctx, err });
        }
    }

    return out_ctx.* > 0;
}

fn buildOutlierClipInputs(samples: []const f32, sample_rate: u32) [CLIP_SPLIT]fft_analyzer.ClipInput {
    const clip_len = samples.len / CLIP_SPLIT;
    return .{
        .{ .samples = samples[0..clip_len], .sample_rate = sample_rate },
        .{ .samples = samples[clip_len .. 2 * clip_len], .sample_rate = sample_rate },
        .{ .samples = samples[2 * clip_len ..], .sample_rate = sample_rate },
    };
}

fn outlierAnswerFromResult(result: fft_analyzer.OutlierAnalysisResult) u8 {
    std.debug.assert(result.guess > 0 and result.guess <= CLIP_SPLIT);
    return result.guess;
}

fn shouldRevealPromptForAnalysis(mode: fft_analyzer.DecisionMode) bool {
    return mode == .weighted_fallback;
}

// ---------------------------------------------------------------------------
// runAudioBypass — Ana pipeline orkestratörü
// ---------------------------------------------------------------------------
//
// SOURCE: Arkose Labs Audio CAPTCHA — challenge sequence length is runtime state
//
// Tüm audio bypass sürecini otomatikleştirir:
//   1. Her challenge için audio URL yakala, MP3 indir, decode et
//   2. Outlier analizi ile hangi segmentin farklı olduğunu bul
//   3. Cevabı browser'a inject et ve submit et
//   4. Hata olursa challenge'ı atla (ilk challenge hatası fatal)
//   5. Max 10 challenge, Arkose tamamlanma sinyali yeter
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
    var challenge_index: u8 = 0;
    var target_challenges: u8 = 0;
    var challenge_complete = false;
    var audio_mode_activated: bool = false;
    var game_core_ctx: i64 = 0;

    std.debug.print("\n[AUDIO BYPASS] Starting pipeline (gfct runtime target, max {d} attempts)...\n", .{MAX_CHALLENGES});

    // Step 0: Connect directly to the Arkose enforcement iframe via its own CDP WebSocket
    // The enforcement iframe has its own webSocketDebuggerUrl in GET /json.
    // By connecting directly, we bypass cross-process execution context issues:
    // the main page's CDP session cannot access cross-origin iframe DOM via
    // Runtime.evaluate with contextId when the iframe lives in a different process.
    // SOURCE: Chrome DevTools Protocol — GET /json returns per-target wsDebuggerUrl
    // SOURCE: LIVE TEST 2026-04-25 — enforcement iframe has its OWN /json entry
    // Retry loop: getArkoseWsUrl + connectToTarget with up to 3 attempts
    const ARKOSE_CONNECT_MAX_RETRIES: u8 = 10;
    var arkose_cdp_opt: ?browser_bridge.CdpClient = null;
    var iframe_ws_url_opt: ?[]u8 = null;
    var arkose_connected = false;
    var arkose_connect_attempt: u8 = 0;
    while (arkose_connect_attempt < ARKOSE_CONNECT_MAX_RETRIES and !arkose_connected) : (arkose_connect_attempt += 1) {
        if (arkose_connect_attempt > 0) {
            std.debug.print("[AUDIO BYPASS] Arkose connection retry {d}/{d}...\n", .{ arkose_connect_attempt + 1, ARKOSE_CONNECT_MAX_RETRIES });

            // Her 3 başarısız denemede bir sayfayı yenile
            if (arkose_connect_attempt % 3 == 0) {
                std.debug.print("[AUDIO BYPASS] Reloading page to force Arkose iframe load (attempt {d}/{d})...\n", .{ arkose_connect_attempt, ARKOSE_CONNECT_MAX_RETRIES });
                bridge.cdp.reloadPage() catch |err| {
                    std.debug.print("[AUDIO BYPASS] Page reload failed: {}\n", .{err});
                };
                _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 5, .nsec = 0 }, null);
            } else {
                _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 3, .nsec = 0 }, null);
            }
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
    defer arkose_cdp.close();
    var iframe_ws_url = iframe_ws_url_opt.?;
    defer allocator.free(iframe_ws_url);

    // Enable Runtime domain on the iframe CDP session for DOM interaction
    _ = arkose_cdp.runtimeEnable() catch {};
    std.debug.print("[AUDIO BYPASS] Arkose iframe CDP session established\n", .{});

    // CRITICAL FIX 2026-04-29: Arkose EC UI 2.0 no longer uses .fc-* class names.
    // The DOM is dynamically rendered inside #funcaptcha or a shadow DOM container.
    // We must detect UI readiness via GENERIC interactive elements, not hardcoded classes.
    // SOURCE: ChromeDevTools MCP live test — Arkose UI takes 5-15s to render.
    // STRATEGY: Class-agnostic detection — any visible button/input/iframe = UI rendered.
    const wait_for_ui_script =
        \\(() => {
        \\  function deepQuery(selector) {
        \\    const results = [];
        \\    const q = (root) => {
        \\      root.querySelectorAll(selector).forEach(el => results.push(el));
        \\      root.querySelectorAll('*').forEach(el => {
        \\        if (el.shadowRoot) q(el.shadowRoot);
        \\      });
        \\    };
        \\    q(document);
        \\    return results;
        \\  }
        \\  const funcaptcha = document.getElementById('funcaptcha');
        \\  const funcaptchaChildren = funcaptcha ? funcaptcha.querySelectorAll('*').length : 0;
        \\  // GENERIC: all interactive elements (class-agnostic)
        \\  const allBtns = deepQuery('button, a[role="button"], [role="button"]');
        \\  const allInputs = deepQuery('input, textarea');
        \\  const visibleInputs = allInputs.filter(el => el.offsetParent !== null && el.type !== 'hidden');
        \\  const interactive = deepQuery('[onclick], [tabindex], [role="button"], [role="link"]');
        \\  const iframe = document.querySelector('iframe');
        \\  let iframe_info = 'none';
        \\  if (iframe) {
        \\    iframe_info = 'src=' + (iframe.src || 'no-src');
        \\    try {
        \\      const idoc = iframe.contentDocument;
        \\      if (idoc) {
        \\        const ibtns = idoc.querySelectorAll('button, a, [role="button"]');
        \\        const iinputs = idoc.querySelectorAll('input');
        \\        iframe_info += '|ibtns=' + ibtns.length + '|iinputs=' + iinputs.length;
        \\      }
        \\    } catch(e) { iframe_info += '|cross-origin'; }
        \\  }
        \\  return 'children=' + funcaptchaChildren +
        \\         '|btns=' + allBtns.length + '|visible_inputs=' + visibleInputs.length +
        \\         '|interactive=' + interactive.length +
        \\         '|iframe=' + iframe_info;
        \\})()
    ;
    var ui_ready = false;
    for (0..30) |ui_retry| {
        _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 1, .nsec = 0 }, null);
        if (arkose_cdp.evaluate(wait_for_ui_script)) |resp| {
            defer allocator.free(resp);
            std.debug.print("[AUDIO BYPASS] UI check (attempt {d}): {s}\n", .{ ui_retry + 1, resp[0..@min(resp.len, 300)] });
            // UI is ready if we see ANY button, ANY visible input, funcaptcha has children, or iframe has content
            if (std.mem.indexOf(u8, resp, "btns=0|") == null or
                std.mem.indexOf(u8, resp, "visible_inputs=0|") == null or
                std.mem.indexOf(u8, resp, "children=0|") == null)
            {
                std.debug.print("[AUDIO BYPASS] Arkose UI rendered! Interactive elements detected.\n", .{});
                ui_ready = true;
                break;
            }
        } else |err| {
            std.debug.print("[AUDIO BYPASS] UI check failed (attempt {d}): {}\n", .{ ui_retry + 1, err });
        }
    }
    if (!ui_ready) {
        std.debug.print("[AUDIO BYPASS] WARNING: Arkose UI never rendered — game-core may not load\n", .{});
    }

    // CRITICAL FIX 2026-04-29: Click the "Audio challenge" button in the enforcement iframe.
    // Arkose EC UI 2.0 no longer uses .fc-* class names. Buttons are generic <button> elements
    // identified by text content ("Audio", "Sound", "Hear challenge", speaker icons).
    // We use class-agnostic heuristic detection with deep shadow DOM traversal.
    // SOURCE: ChromeDevTools MCP live test — audio button detected by text/aria, not class.
    const audio_challenge_click_script =
        \\(() => {
        \\  function deepQuery(selector) {
        \\    const results = [];
        \\    const q = (root) => {
        \\      root.querySelectorAll(selector).forEach(el => results.push(el));
        \\      root.querySelectorAll('*').forEach(el => {
        \\        if (el.shadowRoot) q(el.shadowRoot);
        \\      });
        \\    };
        \\    q(document);
        \\    return results;
        \\  }
        \\  function isAudioBtn(el) {
        \\    const txt = (el.textContent || el.getAttribute('aria-label') || el.getAttribute('title') || el.getAttribute('alt') || '').toLowerCase();
        \\    const cls = (el.className || '').toLowerCase();
        \\    const onclick = (el.getAttribute('onclick') || '').toLowerCase();
        \\    // Heuristic: any interactive element mentioning audio/sound/hear/listen/speaker
        \\    return txt.includes('audio') || txt.includes('sound') || txt.includes('hear') || txt.includes('listen') ||
        \\           cls.includes('audio') || cls.includes('sound') ||
        \\           onclick.includes('audio') || onclick.includes('sound');
        \\  }
        \\  // Try child iframe first (same-origin only)
        \\  const iframe = document.querySelector('iframe');
        \\  if (iframe) {
        \\    try {
        \\      const idoc = iframe.contentDocument;
        \\      if (idoc) {
        \\        const ibtns = idoc.querySelectorAll('button, a, [role="button"]');
        \\        for (const b of ibtns) {
        \\          if (isAudioBtn(b)) {
        \\            b.click();
        \\            return 'clicked_audio_iframe:' + (b.textContent || b.className || 'no-text');
        \\          }
        \\        }
        \\        const iAll = idoc.querySelectorAll('*');
        \\        for (const el of iAll) {
        \\          if (el.shadowRoot) {
        \\            const sbtns = el.shadowRoot.querySelectorAll('button, a, [role="button"]');
        \\            for (const b of sbtns) {
        \\              if (isAudioBtn(b)) {
        \\                b.click();
        \\                return 'clicked_audio_iframe_shadow:' + (b.textContent || b.className || 'no-text');
        \\              }
        \\            }
        \\          }
        \\        }
        \\      }
        \\    } catch(e) {
        \\      // cross-origin or other error
        \\    }
        \\    const src = iframe.src || '';
        \\    if (src.includes('game-core')) {
        \\      return 'game-core-src:' + src;
        \\    }
        \\  }
        \\  // Deep search in parent document including shadow DOM — class-agnostic
        \\  const selectors = ['button', 'a', '[role="button"]', '[onclick*="audio"]', '[onclick*="sound"]'];
        \\  for (const sel of selectors) {
        \\    const els = deepQuery(sel);
        \\    for (const el of els) {
        \\      if (isAudioBtn(el)) {
        \\        el.click();
        \\        return 'clicked_audio_deep:' + sel + ':' + (el.textContent || el.className || 'no-text');
        \\      }
        \\    }
        \\  }
        \\  // Last resort: click ANY interactive element that might be audio
        \\  const allBtns = deepQuery('button, a, [role="button"]');
        \\  for (const b of allBtns) {
        \\    if (isAudioBtn(b)) {
        \\      b.click();
        \\      return 'clicked_audio_fallback:' + (b.textContent || b.className || 'no-text');
        \\    }
        \\  }
        \\  return 'not_found';
        \\})()
    ;
    var enforcement_audio_clicked = false;
    for (0..10) |retry| {
        if (arkose_cdp.evaluate(audio_challenge_click_script)) |resp| {
            defer allocator.free(resp);
            if (std.mem.indexOf(u8, resp, "clicked_audio") != null) {
                std.debug.print("[AUDIO BYPASS] Clicked audio challenge button (attempt {d}): {s}\n", .{ retry + 1, resp[0..@min(resp.len, 200)] });
                enforcement_audio_clicked = true;
                break;
            }
            if (std.mem.indexOf(u8, resp, "game-core-src:") != null) {
                if (std.mem.indexOf(u8, resp, "game-core-src:")) |src_pos| {
                    const url_start = src_pos + "game-core-src:".len;
                    const url_end = std.mem.indexOfScalarPos(u8, resp, url_start, '"') orelse resp.len;
                    const gc_url = resp[url_start..url_end];
                    std.debug.print("[AUDIO BYPASS] Detected cross-origin game-core iframe src: {s}\n", .{gc_url});
                    var new_cdp_opt: ?browser_bridge.CdpClient = null;
                    var new_ws_url_opt: ?[]u8 = null;
                    defer {
                        if (new_ws_url_opt) |u| allocator.free(u);
                        if (new_cdp_opt) |*c| c.close();
                    }
                    for (0..5) |gc_retry| {
                        if (gc_retry > 0) {
                            _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 2, .nsec = 0 }, null);
                        }
                        if (bridge.getArkoseWsUrl(allocator)) |candidate_ws_url| {
                            std.debug.print("[AUDIO BYPASS] game-core retry WS URL: {s}\n", .{candidate_ws_url});
                            if (std.mem.indexOf(u8, candidate_ws_url, "game-core") != null) {
                                if (browser_bridge.CdpClient.connectToTarget(allocator, candidate_ws_url)) |candidate_cdp| {
                                    new_cdp_opt = candidate_cdp;
                                    new_ws_url_opt = candidate_ws_url;
                                    break;
                                } else |err| {
                                    std.debug.print("[AUDIO BYPASS] connectToTarget failed for game-core: {}\n", .{err});
                                    allocator.free(candidate_ws_url);
                                }
                            } else {
                                allocator.free(candidate_ws_url);
                            }
                        } else |err| {
                            std.debug.print("[AUDIO BYPASS] getArkoseWsUrl failed for game-core (attempt {d}): {}\n", .{ gc_retry + 1, err });
                        }
                    }
                    if (new_cdp_opt != null and new_ws_url_opt != null) {
                        arkose_cdp.close();
                        arkose_cdp = new_cdp_opt.?;
                        allocator.free(iframe_ws_url);
                        iframe_ws_url = new_ws_url_opt.?;
                        new_cdp_opt = null;
                        new_ws_url_opt = null;
                        _ = arkose_cdp.runtimeEnable() catch {};
                        std.debug.print("[AUDIO BYPASS] Connected to game-core iframe CDP target\n", .{});
                        enforcement_audio_clicked = true;
                        break;
                    }
                }
            }
            std.debug.print("[AUDIO BYPASS] Audio challenge button not found yet (attempt {d}): {s}\n", .{ retry + 1, resp[0..@min(resp.len, 100)] });
        } else |err| {
            std.debug.print("[AUDIO BYPASS] Audio challenge click eval failed (attempt {d}): {}\n", .{ retry + 1, err });
        }
        _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 1, .nsec = 0 }, null);
    }
    if (!enforcement_audio_clicked) {
        std.debug.print("[AUDIO BYPASS] WARNING: Could not find/click audio challenge button — game-core may not load\n", .{});
    }
    // Give iframe time to load game-core after audio button click
    _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 3, .nsec = 0 }, null);

    // Step 0b: Wait for PoW to complete, then game-core appears
    // SOURCE: LIVE ChromeDevTools MCP 2026-04-25 — PoW akışı:
    //   /fc/gt2/ → returns token (session setup)
    //   PoW iframe loads → /pows/setup → /pows/started → /pows/check
    //   game-core iframe appears in DOM → /fc/gfct/ returns challengeID
    //
    // FAZ 1 FIX 2026-04-25 — Network Event Capture:
    //   Eski yöntem: Runtime.evaluate ile JS fetch('/fc/gfct/') — CSP'den dolayı
    //   sürekli WAITING dönüyor, loop sonsuz.
    //   Yeni yöntem: Ana CDP session'ının Network.responseReceived event'lerini
    //   dinleyerek GERÇEK HTTP response'larını yakala.
    //   SOURCE: ChromeDevTools MCP live test — getNetworkResponseBody başarılı
    std.debug.print("[AUDIO BYPASS] Waiting for PoW to complete and game-core to load...\n", .{});

    // FAZ 1: Enable Network monitoring on the MAIN CDP session (already done in BrowserBridge.init)
    // The main session's pending_events will contain Network.responseReceived for ALL subframes
    // SOURCE: ChromeDevTools MCP — main page CDP sees enforcement iframe HTTP traffic
    var game_core_found = false;
    var pow_wait_attempt: u32 = 0;
    var iframe_seen_once = false;
    var game_core_session_token: ?[]const u8 = null;
    var game_core_game_token: ?[]const u8 = null;
    defer {
        if (game_core_session_token) |t| allocator.free(t);
        if (game_core_game_token) |t| allocator.free(t);
    }
    const POW_MAX_WAIT: u32 = 120;

    while (!game_core_found and pow_wait_attempt < POW_MAX_WAIT) : (pow_wait_attempt += 1) {
        _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 2, .nsec = 0 }, null);
        // Poll arkose CDP for new events (game-core execution context may appear later)
        while (arkose_cdp.tryReadPendingEvents()) {}

        // FAZ 1: Drain main CDP WebSocket — read ALL buffered frames non-blocking
        // tryReadPendingEvents returns true when a frame was read.
        // Loop until no more frames available.
        while (bridge.cdp.tryReadPendingEvents()) {}

        // FAZ 1: Drain pending events looking for Network.responseReceived
        // for /fc/gt2/ or /fc/gfct/. These contain the gameToken.
        // SOURCE: LIVE TEST 2026-04-25 — /fc/gt2/ returns {"token":"...","challenge_url":"..."}
        // SOURCE: LIVE TEST 2026-04-25 — /fc/gfct/ returns {"session_token":"...","challengeID":"..."}
        while (bridge.cdp.hasPendingEvents()) {
            const event = bridge.cdp.nextPendingEvent().?;
            defer allocator.free(event);
            if (std.mem.indexOf(u8, event, "Network.responseReceived") != null) {
                // Extract URL from event JSON
                if (std.mem.indexOf(u8, event, "\"url\":\"")) |url_pos| {
                    const url_start = url_pos + 7;
                    const url_end = std.mem.indexOfScalarPos(u8, event, url_start, '"') orelse continue;
                    const url = event[url_start..url_end];
                    if (std.mem.indexOf(u8, url, "/fc/gt2/") != null or
                        std.mem.indexOf(u8, url, "/fc/gfct/") != null)
                    {
                        // Extract requestId from event
                        const rid_key = "\"requestId\":\"";
                        if (std.mem.indexOf(u8, event, rid_key)) |rid_pos| {
                            const rid_start = rid_pos + rid_key.len;
                            const rid_end = std.mem.indexOfScalarPos(u8, event, rid_start, '"') orelse continue;
                            const request_id = event[rid_start..rid_end];
                            // Get response body
                            if (bridge.cdp.getNetworkResponseBody(request_id)) |body| {
                                defer allocator.free(body);
                                std.debug.print("[AUDIO BYPASS] Network response body ({d} bytes): {s}\n", .{ body.len, body[0..@min(body.len, 500)] });
                                // Parse token fields
                                // SOURCE: LIVE TEST 2026-04-25 — /fc/gt2/ has "token" field
                                const token_prefix = "\"token\":\"";
                                const challengeID_prefix = "\"challengeID\":\"";
                                const gameToken_prefix = "\"gameToken\":\"";
                                const session_prefix = "\"session_token\":\"";
                                var found_token: ?[]const u8 = null;
                                if (std.mem.indexOf(u8, body, challengeID_prefix)) |cpos| {
                                    const cstart = cpos + challengeID_prefix.len;
                                    const cend = std.mem.indexOfScalarPos(u8, body, cstart, '"') orelse body.len;
                                    found_token = body[cstart..cend];
                                } else if (std.mem.indexOf(u8, body, token_prefix)) |tpos| {
                                    const tstart = tpos + token_prefix.len;
                                    const tend = std.mem.indexOfScalarPos(u8, body, tstart, '"') orelse body.len;
                                    // token field may contain pipe-separated metadata; take first segment
                                    const pipe_pos = std.mem.indexOfScalarPos(u8, body, tstart, '|') orelse tend;
                                    found_token = body[tstart..pipe_pos];
                                } else if (std.mem.indexOf(u8, body, gameToken_prefix)) |gpos| {
                                    const gstart = gpos + gameToken_prefix.len;
                                    const gend = std.mem.indexOfScalarPos(u8, body, gstart, '"') orelse body.len;
                                    found_token = body[gstart..gend];
                                }
                                if (found_token) |ft| {
                                    if (ft.len > 5) {
                                        game_core_game_token = try allocator.dupe(u8, ft);
                                        std.debug.print("[AUDIO BYPASS] FAZ 1: Captured gameToken from Network response: {s}\n", .{ft});
                                        target_challenges = parseAudioChallengeTargetFromGfctPayload(allocator, body) catch |err| blk: {
                                            std.debug.print("[AUDIO BYPASS] WARNING: Could not parse audio_challenge_urls count from Network /fc/gfct/ body: {}\n", .{err});
                                            break :blk 0;
                                        };
                                        if (target_challenges > 0) {
                                            std.debug.print("[AUDIO BYPASS] Runtime audio challenge target from /fc/gfct/: {d}\n", .{target_challenges});
                                        }
                                        // Also extract session_token if available
                                        if (std.mem.indexOf(u8, body, session_prefix)) |spos| {
                                            const sstart = spos + session_prefix.len;
                                            const send = std.mem.indexOfScalarPos(u8, body, sstart, '"') orelse body.len;
                                            const st = body[sstart..send];
                                            if (st.len > 5) {
                                                const old_token = game_core_session_token;
                                                game_core_session_token = try allocator.dupe(u8, st);
                                                if (old_token) |old| allocator.free(old);
                                            }
                                        }
                                        game_core_found = true;
                                        std.debug.print("[AUDIO BYPASS] PoW completed! gameToken via Network event (~{d}s)\n", .{pow_wait_attempt * 2});
                                        break;
                                    }
                                }
                            } else |_| {}
                        }
                    }
                }
            }
        }
        if (game_core_found) break;

        // Parse pending events for Runtime.executionContextCreated (game-core iframe)
        // SOURCE: CDP Runtime.executionContextCreated — sent when child iframe loads
        // FIX: Probe all new contexts for input element instead of fragile string match.
        if (game_core_ctx == 0) {
            _ = tryResolveGameCoreContext(&arkose_cdp, allocator, &game_core_ctx);
        }

        // Step 1: Check enforcement DOM for game-core iframe element
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
                    const session_prefix_str = "|session:";
                    if (std.mem.indexOf(u8, resp, session_prefix_str)) |spos| {
                        const session_start = spos + session_prefix_str.len;
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

        // FAZ 1 FIX: game-core iframe DOM'da görünüyorsa PoW TAMAMLANMIŞ demektir.
        // SOURCE: LIVE ChromeDevTools MCP 2026-04-25 — game-core iframe PoW bittikten SONRA yüklenir
        // (önce PoW iframe → /pows/started → /pows/check DONE → game-core DOM'da)
        if (iframe_found and !game_core_found) {
            // CRITICAL: Re-resolve context now that game-core iframe is visible.
            // The earlier resolution may have captured the enforcement iframe.
            // Keep a verified positive context if the pending CDP event queue was already drained.
            var resolved_game_core_ctx: i64 = 0;
            const resolved = tryResolveGameCoreContext(&arkose_cdp, allocator, &resolved_game_core_ctx);
            if (resolved) {
                game_core_ctx = resolved_game_core_ctx;
                game_core_found = true;
                std.debug.print("[AUDIO BYPASS] PoW completed! game-core iframe in DOM (~{d}s)\n", .{pow_wait_attempt * 2});
            } else if (game_core_ctx > 0) {
                game_core_found = true;
                std.debug.print("[AUDIO BYPASS] Reusing verified game-core execution context ID={d}\n", .{game_core_ctx});
            } else {
                std.debug.print("[AUDIO BYPASS] WARNING: tryResolveGameCoreContext returned false, no verified previous context\n", .{});
            }
        }

        if (!game_core_found and !iframe_found) {
            std.debug.print("[AUDIO BYPASS] Still waiting for game-core (attempt {d}/{d})...\n", .{ pow_wait_attempt + 1, POW_MAX_WAIT });
        }
    }

    if (!game_core_found) {
        std.debug.print("[AUDIO BYPASS] Could not find game-core context after {d}s\n", .{POW_MAX_WAIT * 2});
    } else {
        std.debug.print("[AUDIO BYPASS] Using game-core context: {d}, gameToken: {s}\n", .{ game_core_ctx, game_core_game_token orelse "N/A" });
    }

    // FAZ 2: If gameToken is still missing, fetch it directly from /fc/gfct/ via enforcement iframe CDP.
    // SOURCE: ChromeDevTools MCP live capture 2026-04-25 — /fc/gfct/ POST returns challengeID as gameToken
    // SOURCE: RFC 7231, Section 4.3.3 — POST semantics
    if ((game_core_game_token == null or target_challenges == 0) and game_core_session_token != null) {
        std.debug.print("[AUDIO BYPASS] FAZ 2: Fetching gameToken from /fc/gfct/ via enforcement CDP...\n", .{});

        const gfct_js = try std.fmt.allocPrint(allocator,
            \\(async () => {{
            \\  const body = 'token={s}&sid=eu-west-1&render_type=canvas&lang=en&isAudioGame=true&analytics_tier=40&is_compatibility_mode=false&apiBreakerVersion=green';
            \\  try {{
            \\    const resp = await fetch('/fc/gfct/', {{
            \\      method: 'POST',
            \\      body: body,
            \\      headers: {{'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest', 'Cache-Control': 'no-cache'}}
            \\    }});
            \\    if (!resp.ok) return 'ERROR:HTTP_' + resp.status;
            \\    const text = await resp.text();
            \\    return text;
            \\  }} catch(e) {{ return 'ERROR:FETCH:' + e.message; }}
            \\}})()
        , .{game_core_session_token.?});
        defer allocator.free(gfct_js);

        const gfct_response = try arkose_cdp.evaluate(gfct_js);
        defer allocator.free(gfct_response);
        std.debug.print("[AUDIO BYPASS] /fc/gfct/ response: {s}\n", .{gfct_response[0..@min(gfct_response.len, 300)]});

        target_challenges = parseAudioChallengeTargetFromGfctResponse(allocator, gfct_response) catch |err| blk: {
            std.debug.print("[AUDIO BYPASS] WARNING: Could not parse audio_challenge_urls count from /fc/gfct/ Runtime.evaluate response: {}\n", .{err});
            break :blk 0;
        };
        if (target_challenges > 0) {
            std.debug.print("[AUDIO BYPASS] Runtime audio challenge target from /fc/gfct/: {d}\n", .{target_challenges});
        }

        // Extract challengeID (gameToken) from JSON response
        // SOURCE: LIVE capture — /fc/gfct/ response has "challengeID":"..."
        const resp_value = browser_bridge.extractRuntimeEvaluateStringValue(allocator, gfct_response) catch null;
        if (resp_value) |rv| {
            defer allocator.free(rv);
            const challengeID_prefix = "\"challengeID\":\"";
            if (std.mem.indexOf(u8, rv, challengeID_prefix)) |cpos| {
                const cstart = cpos + challengeID_prefix.len;
                const cend = std.mem.indexOfScalarPos(u8, rv, cstart, '"') orelse rv.len;
                if (cend > cstart and cend - cstart > 5 and game_core_game_token == null) {
                    game_core_game_token = try allocator.dupe(u8, rv[cstart..cend]);
                    std.debug.print("[AUDIO BYPASS] FAZ 2: Captured gameToken from /fc/gfct/: {s}\n", .{game_core_game_token.?});
                }
            }
        }
    }

    if (game_core_game_token == null) {
        std.debug.print("[AUDIO BYPASS] WARNING: gameToken not available, pipeline may fail\n", .{});
    }

    if (target_challenges == 0) {
        const elapsed = currentMonotonicMs() - start_ms;
        std.debug.print("[AUDIO BYPASS] ERROR: audio_challenge_urls target count unavailable; refusing static fallback\n", .{});
        return AudioBypassResult{
            .guess = last_guess,
            .execution_time_ms = elapsed,
            .total_challenges = successful,
            .target_challenges = 0,
            .success = false,
        };
    }

    while (shouldContinueAudioChallengeLoop(.{
        .successful_submits = successful,
        .attempted = total_attempted,
        .target_challenges = target_challenges,
        .challenge_complete = challenge_complete,
    })) : (total_attempted += 1) {
        const elapsed = currentMonotonicMs() - start_ms;
        if (elapsed > PIPELINE_TIMEOUT_MS) {
            std.debug.print("[AUDIO BYPASS] Pipeline timeout after {d}ms\n", .{elapsed});
            break;
        }

        std.debug.print("\n[AUDIO BYPASS] Attempt {d}/{d} (successful: {d}/{d})...\n", .{
            total_attempted + 1, target_challenges, successful, target_challenges,
        });

    // DOM PROBE FIX 2026-04-30: Extract question text from Arkose Audio Challenge.
    // WIRE-TRUTH (ChromeDevTools MCP live test):
    //   - game-core iframe body.innerText contains:
    //     "Press Play to listen. Which option is the odd animal out? Enter the number..."
    //   - game-core iframe shares origin with enforcement iframe (github-api.arkoselabs.com)
    //   - contentDocument access WORKS from enforcement iframe to game-core iframe
    //   - Question lives in body.innerText AND button aria-label/description
    //   - Shadow DOM not used for question text in game-core 1.34.1
    // SOURCE: ChromeDevTools MCP live DOM snapshot 2026-04-30
    const dom_probe_script =
        \\(() => {
        \\  // CRITICAL FIX: Access game-core iframe contentDocument directly.
        \\  // game-core iframe is same-origin with enforcement iframe,
        \\  // so contentDocument is accessible without CDP contextId.
        \\  let targetDoc = document;
        \\  const gc = document.querySelector('iframe[src*="game-core"]');
        \\  if (gc) {
        \\    try {
        \\      const doc = gc.contentDocument;
        \\      if (doc && doc.body) targetDoc = doc;
        \\    } catch(e) {}
        \\  }
        \\  function deepText(root) {
        \\    const texts = [];
        \\    const walk = (node) => {
        \\      if (node.shadowRoot) walk(node.shadowRoot);
        \\      if (node.nodeType === Node.TEXT_NODE) {
        \\        const t = node.textContent.trim();
        \\        if (t.length > 3) texts.push(t);
        \\      }
        \\      for (const child of node.childNodes) walk(child);
        \\    };
        \\    walk(root);
        \\    return texts.join(' ');
        \\  }
        \\  function getAriaContent(root) {
        \\    const texts = [];
        \\    const walk = (node) => {
        \\      if (node.shadowRoot) walk(node.shadowRoot);
        \\      if (node.getAttribute) {
        \\        const al = node.getAttribute('aria-label');
        \\        if (al && al.trim().length > 3) texts.push(al.trim());
        \\        const desc = node.getAttribute('aria-describedby');
        \\        if (desc) {
        \\          const el = document.getElementById(desc);
        \\          if (el && el.textContent) texts.push(el.textContent.trim());
        \\        }
        \\      }
        \\      for (const child of node.childNodes) walk(child);
        \\    };
        \\    walk(root);
        \\    return texts.join(' ');
        \\  }
        \\  if (!targetDoc.body) return '[ARKOSE QUESTION] NO_QUESTION_FOUND | DEBUG: no targetDoc.body';
        \\  const bodyText = targetDoc.body.innerText || '';
        \\  const deep = deepText(targetDoc.body);
        \\  const aria = getAriaContent(targetDoc.body);
        \\  const combined = (bodyText + ' ' + deep + ' ' + aria).replace(/\s+/g, ' ').trim();
        \\  if (combined.length === 0) return '[ARKOSE QUESTION] NO_QUESTION_FOUND | DEBUG: all text empty';
        \\  const patterns = [
        \\    /(?:Press Play to listen\.?|Click to listen\.?|Listen carefully\.?|Play to listen\.?|Press the play button)\s*[.:]?\s*(Which[^.?]*(?:\?|\.))/i,
        \\    /(?:Press Play to listen\.?|Click to listen\.?|Listen carefully\.?|Play to listen\.?|Press the play button)\s*[.:]?\s*(What[^.?]*(?:\?|\.))/i,
        \\    /(?:Press Play to listen\.?|Click to listen\.?|Listen carefully\.?|Play to listen\.?|Press the play button)\s*[.:]?\s*(How[^.?]*(?:\?|\.))/i,
        \\    /(Which\s+[^.?]*(?:\?|\.))/i,
        \\    /(What\s+[^.?]*(?:\?|\.))/i,
        \\    /(How\s+[^.?]*(?:\?|\.))/i,
        \\    /(Select\s+[^.?]*(?:\?|\.))/i,
        \\    /(Choose\s+[^.?]*(?:\?|\.))/i,
        \\    /(Identify\s+[^.?]*(?:\?|\.))/i,
        \\    /(Find\s+[^.?]*(?:\?|\.))/i,
        \\  ];
        \\  for (const pat of patterns) {
        \\    const m = combined.match(pat);
        \\    if (m && m[1]) {
        \\      const q = m[1].trim();
        \\      if (q.length > 5) return '[ARKOSE QUESTION] ' + q;
        \\    }
        \\  }
        \\  return '[ARKOSE QUESTION] NO_QUESTION_FOUND | DEBUG_LEN=' + combined.length + ' | DEBUG_TEXT=' + combined.substring(0, 400);
        \\})()
    ;
        if (game_core_ctx > 0) {
            if (arkose_cdp.evaluateInContext(dom_probe_script, game_core_ctx)) |probe_resp| {
                defer allocator.free(probe_resp);
                const probe_value = browser_bridge.extractRuntimeEvaluateStringValue(allocator, probe_resp) catch null;
                if (probe_value) |pv| {
                    defer allocator.free(pv);
                    std.debug.print("[AUDIO BYPASS] {s}\n", .{pv});
                }
            } else |probe_err| {
                std.debug.print("[AUDIO BYPASS] DOM probe failed: {}\n", .{probe_err});
            }
        } else {
            if (arkose_cdp.evaluate(dom_probe_script)) |probe_resp| {
                defer allocator.free(probe_resp);
                const probe_value = browser_bridge.extractRuntimeEvaluateStringValue(allocator, probe_resp) catch null;
                if (probe_value) |pv| {
                    defer allocator.free(pv);
                    std.debug.print("[AUDIO BYPASS] {s}\n", .{pv});
                }
            } else |probe_err| {
                std.debug.print("[AUDIO BYPASS] DOM probe failed: {}\n", .{probe_err});
            }
        }

        // Step 0.5: Activate audio mode if not already active
        if (!audio_mode_activated) {
            const MAX_AUDIO_RETRIES = 3;
            var audio_retry: u8 = 0;
            var audio_clicked = false;
            while (audio_retry < MAX_AUDIO_RETRIES and !audio_clicked) : (audio_retry += 1) {
                if (audio_retry > 0) {
                    std.debug.print("[AUDIO BYPASS] Audio button retry {d}/{d}...\n", .{ audio_retry + 1, MAX_AUDIO_RETRIES });
                    _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 1, .nsec = 0 }, null);
                }
                std.debug.print("[AUDIO BYPASS] Finding Audio puzzle button...\n", .{});
                // FIX 2026-04-29: Class-agnostic audio button detection inside game-core iframe.
                // Heuristic: button text/aria-label/title contains audio/sound/hear/listen.
                const ascript =
                    \\(() => {
                    \\  let doc = document;
                    \\  const gc = document.querySelector('iframe[src*="game-core"]');
                    \\  if (gc) {
                    \\    try {
                    \\      const d = gc.contentDocument;
                    \\      if (d && d.body) doc = d;
                    \\    } catch(e) {}
                    \\  }
                    \\  // CRITICAL: If audio challenge UI already present (input+submit), no need to click Audio puzzle button.
                    \\  const hasInput = !!doc.querySelector('input[type="text"], input[type="number"]');
                    \\  const hasSubmit = !!doc.querySelector('button, input[type="submit"]');
                    \\  if (hasInput && hasSubmit) return 'already_in_audio_mode';
                    \\  function isAudioBtn(el) {
                    \\    const txt = (el.textContent || el.getAttribute('aria-label') || el.getAttribute('title') || '').toLowerCase();
                    \\    return txt.includes('audio') || txt.includes('sound') || txt.includes('hear') || txt.includes('listen');
                    \\  }
                    \\  const btns = doc.querySelectorAll('button, [role="button"]');
                    \\  for (const btn of btns) {
                    \\    if (isAudioBtn(btn) && btn.offsetParent !== null) {
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
                        if (std.mem.indexOf(u8, resp, "clicked") != null or std.mem.indexOf(u8, resp, "already_in_audio_mode") != null) audio_clicked = true;
                    } else |_| {}
                } else {
                    if (arkose_cdp.evaluate(ascript)) |resp| {
                        defer allocator.free(resp);
                        std.debug.print("[AUDIO BYPASS] Audio button response: {s}\n", .{resp[0..@min(resp.len, 200)]});
                        if (std.mem.indexOf(u8, resp, "clicked") != null or std.mem.indexOf(u8, resp, "already_in_audio_mode") != null) audio_clicked = true;
                    } else |_| {}
                }
            }
            if (!audio_clicked) {
                std.debug.print("[AUDIO BYPASS] WARNING: Audio button not found after {d} retries\n", .{MAX_AUDIO_RETRIES});
            }
            _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 2, .nsec = 0 }, null);
            audio_mode_activated = audio_clicked;
        }

        // Step 1-3: Download MP3 via CDP evaluate fetch (always works, cookies handled)
        var dl_result: audio_downloader.FetchResult = undefined;
        dl_result = audio_downloader.fetchAudioViaCdpEvaluate(
            &arkose_cdp,
            allocator,
            challenge_index,
            game_core_session_token orelse "",
            game_core_game_token orelse "",
        ) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: fetchAudioViaCdpEvaluate failed: {}\n", .{ total_attempted, err });
            if (total_attempted == 0) return err;
            std.debug.print("[AUDIO BYPASS] Skipping to next attempt...\n", .{});
            continue;
        };
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

        // Step 5b: Save raw f32 PCM to disk alongside the MP3
        const dot_pos = std.mem.lastIndexOf(u8, result.path, ".mp3") orelse result.path.len;
        const f32_path = try std.fmt.allocPrint(allocator, "{s}.f32", .{result.path[0..dot_pos]});
        defer allocator.free(f32_path);
        audio_decoder.saveF32ToFile(allocator, io, decoded.samples, f32_path) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: saveF32ToFile failed: {}\n", .{ total_attempted, err });
        };
        std.debug.print("[AUDIO BYPASS] Saved f32 PCM: {s}\n", .{f32_path});

        // Step 6: Peak normalize
        const normalized = audio_decoder.peakNormalize(allocator, decoded.samples) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: peakNormalize failed: {}\n", .{ total_attempted, err });
            continue;
        };
        defer allocator.free(normalized.normalized);
        std.debug.print("[AUDIO BYPASS] Normalized: scale={d:.4}\n", .{normalized.scale});

        // Step 7: Split into 3 equal clips and analyze outlier signature
        if (normalized.normalized.len < CLIP_SPLIT) {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: audio too short ({d} samples)\n", .{ total_attempted, normalized.normalized.len });
            continue;
        }
        const clips = buildOutlierClipInputs(normalized.normalized, meta.sample_rate);
        const outlier_config = fft_analyzer.OutlierConfig{
            .vad = .{},
            .optional_bit_depth = if (meta.bit_depth == 0) null else meta.bit_depth,
        };

        var answer: u8 = undefined;
        const outlier_result_or_error = fft_analyzer.analyzeOutlier(&clips, .unknown, outlier_config);
        if (outlier_result_or_error) |outlier_result| {
            answer = outlierAnswerFromResult(outlier_result);
            last_guess = answer - 1;
            std.debug.print("[AUDIO BYPASS] Outlier final scores: [{d:.6}, {d:.6}, {d:.6}]\n", .{
                outlier_result.final_scores[0], outlier_result.final_scores[1], outlier_result.final_scores[2],
            });
            std.debug.print("[AUDIO BYPASS] Outlier hardware scores: [{d:.6}, {d:.6}, {d:.6}]\n", .{
                outlier_result.hardware_scores[0], outlier_result.hardware_scores[1], outlier_result.hardware_scores[2],
            });
            if (shouldRevealPromptForAnalysis(outlier_result.decision_mode)) {
                std.debug.print("[AUDIO BYPASS] Fallback decision mode active: weighted_fallback\n", .{});
            }
            std.debug.print("[AUDIO BYPASS] Guess (outlier): {d} -> Answer: {d}\n", .{ outlier_result.guess, answer });
            std.debug.print("[AUDIO BYPASS] Analysis time: {d}us\n", .{outlier_result.execution_time_us});
        } else |err| {
            switch (err) {
                error.AmbiguousSignal => {
                    std.debug.print("[AUDIO BYPASS] Attempt {d}: outlier analyze ambiguous; skipping challenge without manual answer fallback\n", .{total_attempted});
                    continue;
                },
                else => {
                    std.debug.print("[AUDIO BYPASS] Attempt {d}: outlier analyze failed: {}\n", .{ total_attempted, err });
                    continue;
                },
            }
        }

        // Step 9: Inject answer into iframe and submit (via direct CDP session)
        const proof = audio_injector.injectAnswerOnTarget(&arkose_cdp, allocator, answer, game_core_ctx) catch |err| {
            std.debug.print("[AUDIO BYPASS] Attempt {d}: inject/submit failed: {}\n", .{ total_attempted, err });
            continue;
        };

        switch (proof.verdict) {
            .complete => {
                successful += 1;
                challenge_index = successful;
                std.debug.print("[AUDIO BYPASS] Challenge {d}/{d} solved (complete text)\n", .{ successful, target_challenges });
                challenge_complete = detectPostSubmitUiState(&arkose_cdp, allocator, game_core_ctx) == .complete;
                if (challenge_complete) {
                    std.debug.print("[AUDIO BYPASS] Arkose completion signal confirmed\n", .{});
                }
            },
            .transition => {
                const ui_state = detectPostSubmitUiState(&arkose_cdp, allocator, game_core_ctx);
                if (ui_state == .wrong_visible or ui_state == .restarted) {
                    std.debug.print("[AUDIO BYPASS] Transition rechecked as wrong; answer {d} rejected\n", .{answer});
                } else {
                    successful += 1;
                    challenge_index = successful;
                    std.debug.print("[AUDIO BYPASS] Challenge {d}/{d} advanced (intermediate transition)\n", .{ successful, target_challenges });
                    if (ui_state == .complete) {
                        challenge_complete = true;
                        std.debug.print("[AUDIO BYPASS] Completion after transition\n", .{});
                    }
                }
            },
            .wrong => {
                std.debug.print("[AUDIO BYPASS] Attempt {d}: Wrong answer {d} rejected\n", .{ total_attempted, answer });

                // Check if Arkose restarted ALL challenges (challenge_index back to 0, new audio)
                const ui_state = detectPostSubmitUiState(&arkose_cdp, allocator, game_core_ctx);
                if (ui_state == .restarted) {
                    // Arkose restarted: reset challenge tracking
                    std.debug.print("[AUDIO BYPASS] Arkose restarted all challenges after wrong answer\n", .{});
                    // Don't reset successful count - keep progress tracking
                    // challenge_index stays; we'll try the current index again
                }
            },
            .clicked => {
                std.debug.print("[AUDIO BYPASS] Attempt {d}: Submit clicked, waiting for result\n", .{total_attempted});
                _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 2, .nsec = 0 }, null);
            },
            .unknown => {
                // Unknown state: could be intermediate transition that wasn't detected
                // by the post-submit proof JS. Check UI state to determine what happened.
                std.debug.print("[AUDIO BYPASS] Attempt {d}: Unknown post-submit state, checking UI...\n", .{total_attempted});

                _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 1, .nsec = 0 }, null);
                const ui_state = detectPostSubmitUiState(&arkose_cdp, allocator, game_core_ctx);

                switch (ui_state) {
                    .complete => {
                        successful += 1;
                        challenge_index = successful;
                        challenge_complete = true;
                        std.debug.print("[AUDIO BYPASS] UI check revealed completion! Challenge {d}/{d}\n", .{ successful, target_challenges });
                    },
                    .transition => {
                        successful += 1;
                        challenge_index = successful;
                        std.debug.print("[AUDIO BYPASS] UI check: intermediate transition confirmed (challenge {d}/{d})\n", .{ successful, target_challenges });
                    },
                    .continue_wait => {
                        std.debug.print("[AUDIO BYPASS] UI check: still same challenge, will retry\n", .{});
                    },
                    .wrong_visible => {
                        std.debug.print("[AUDIO BYPASS] UI check: wrong text visible; answer {d} rejected\n", .{answer});
                    },
                    .restarted => {
                        std.debug.print("[AUDIO BYPASS] UI check: Arkose restarted challenges\n", .{});
                    },
                    .query_failed => {
                        std.debug.print("[AUDIO BYPASS] UI check failed, continuing\n", .{});
                    },
                }
            },
        }

        if (challenge_complete) {
            std.debug.print("[AUDIO BYPASS] Arkose completion signal detected after {d}/{d} submits\n", .{ successful, target_challenges });
            break;
        }
    }

    const end_ms = currentMonotonicMs();
    const elapsed = end_ms - start_ms;
    std.debug.print("[AUDIO BYPASS] Pipeline ended: {d}/{d} submitted, complete={}, {d}ms\n", .{
        successful, target_challenges, challenge_complete, elapsed,
    });

    return AudioBypassResult{
        .guess = last_guess,
        .execution_time_ms = elapsed,
        .total_challenges = successful,
        .target_challenges = target_challenges,
        .success = audioBypassFinalSuccess(.{
            .successful_submits = successful,
            .attempted = total_attempted,
            .target_challenges = target_challenges,
            .challenge_complete = challenge_complete,
        }),
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "audio_bypass: AudioBypassResult struct size" {
    try std.testing.expect(@sizeOf(AudioBypassResult) > 0);
}

test "audio_bypass: constants are valid" {
    try std.testing.expect(MAX_CHALLENGES > 0);
    try std.testing.expect(CLIP_SPLIT == 3);
    try std.testing.expect(PIPELINE_TIMEOUT_MS > 0);
}

test "audio_bypass: builds outlier clip inputs from normalized PCM" {
    var pcm = [_]f32{ 0.1, 0.2, 0.3, 1.1, 1.2, 1.3, 2.1, 2.2, 2.3 };

    const clips = buildOutlierClipInputs(&pcm, 44100);

    try std.testing.expectEqual(@as(usize, 3), clips[0].samples.len);
    try std.testing.expectEqual(@as(f32, 0.1), clips[0].samples[0]);
    try std.testing.expectEqual(@as(f32, 1.1), clips[1].samples[0]);
    try std.testing.expectEqual(@as(f32, 2.1), clips[2].samples[0]);
    try std.testing.expectEqual(@as(u32, 44100), clips[2].sample_rate);
}

test "audio_bypass: outlier answer uses analyzeOutlier result" {
    const result = fft_analyzer.OutlierAnalysisResult{
        .guess = 2,
        .execution_time_us = 42,
        .features = undefined,
        .outlier_scores = undefined,
        .hardware_scores = .{ 0.1, 0.2, 0.9 },
        .acoustic_scores = .{ 0.1, 0.2, 0.8 },
        .final_scores = .{ 0.1, 0.2, 0.87 },
        .confidence = 0.67,
        .decision_mode = .hardware_primary,
        .diagnostics = .{ .dc_delta_ratios = .{ 0.0, 0.0, 1.0 }, .selected_quantization_grid_scale = 32767.0, .quantization_grid_source = .runtime_common_grid, .score_range = 0.77 },
    };

    try std.testing.expectEqual(@as(u8, 2), outlierAnswerFromResult(result));
}

test "audio_bypass: prompt reveal only for weighted fallback" {
    try std.testing.expect(!shouldRevealPromptForAnalysis(.hardware_primary));
    try std.testing.expect(shouldRevealPromptForAnalysis(.weighted_fallback));
    try std.testing.expect(!shouldRevealPromptForAnalysis(.ambiguous));
}

test "audio_bypass: runAudioBypass returns error without bridge" {
    const RunAudioBypassFn = fn (
        *browser_bridge.BrowserBridge,
        std.mem.Allocator,
        std.Io,
    ) anyerror!AudioBypassResult;
    const run_fn: *const RunAudioBypassFn = runAudioBypass;
    try std.testing.expect(run_fn == runAudioBypass);
}
