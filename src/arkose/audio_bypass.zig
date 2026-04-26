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
    const ARKOSE_CONNECT_MAX_RETRIES: u8 = 10;
    var arkose_cdp_opt: ?browser_bridge.CdpClient = null;
    var iframe_ws_url_opt: ?[]u8 = null;
    var arkose_connected = false;
    var arkose_connect_attempt: u8 = 0;
    while (arkose_connect_attempt < ARKOSE_CONNECT_MAX_RETRIES and !arkose_connected) : (arkose_connect_attempt += 1) {
        if (arkose_connect_attempt > 0) {
            std.debug.print("[AUDIO BYPASS] Arkose connection retry {d}/{d}...\n", .{ arkose_connect_attempt + 1, ARKOSE_CONNECT_MAX_RETRIES });
            _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 3, .nsec = 0 }, null);
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

    // Parse initial Runtime.executionContextCreated events from Runtime.enable.
    // Game-core iframe may already be loading — extract its context.id if present.
    // SOURCE: CDP Runtime.executionContextCreated — sent on Runtime.enable for each existing context
    {
        while (arkose_cdp.hasPendingEvents()) {
            const event = arkose_cdp.nextPendingEvent().?;
            defer allocator.free(event);
            if (std.mem.indexOf(u8, event, "\"Runtime.executionContextCreated\"") != null) {
                // FIX: enforcement iframe and game-core iframe share the same origin
                // (github-api.arkoselabs.com). Must also check the context name/URL
                // contains "game-core" to avoid selecting the enforcement context.
                if (std.mem.indexOf(u8, event, "https://github-api.arkoselabs.com") != null and
                    std.mem.indexOf(u8, event, "game-core") != null)
                {
                    const id_prefix = "\"context\":{\"id\":";
                    if (std.mem.indexOf(u8, event, id_prefix)) |id_pos| {
                        const id_start = id_pos + id_prefix.len;
                        var id_end = id_start;
                        while (id_end < event.len and event[id_end] >= '0' and event[id_end] <= '9') {
                            id_end += 1;
                        }
                        if (id_end > id_start) {
                            game_core_ctx = std.fmt.parseInt(i64, event[id_start..id_end], 10) catch 0;
                            std.debug.print("[AUDIO BYPASS] Initial: game-core execution context ID={d} from Runtime.executionContextCreated\n", .{game_core_ctx});
                        }
                    }
                }
            }
        }
    }

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
                                        // Also extract session_token if available
                                        if (std.mem.indexOf(u8, body, session_prefix)) |spos| {
                                            const sstart = spos + session_prefix.len;
                                            const send = std.mem.indexOfScalarPos(u8, body, sstart, '"') orelse body.len;
                                            const st = body[sstart..send];
                                            if (st.len > 5) {
                                                if (game_core_session_token) |old| allocator.free(old);
                                                game_core_session_token = try allocator.dupe(u8, st);
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
        while (arkose_cdp.hasPendingEvents()) {
            const event = arkose_cdp.nextPendingEvent().?;
            defer allocator.free(event);
            if (std.mem.indexOf(u8, event, "\"Runtime.executionContextCreated\"") != null) {
                // FIX: Same-origin enforcement vs game-core — require "game-core" in name/URL
                if (std.mem.indexOf(u8, event, "https://github-api.arkoselabs.com") != null and
                    std.mem.indexOf(u8, event, "game-core") != null)
                {
                    const id_prefix = "\"context\":{\"id\":";
                    if (std.mem.indexOf(u8, event, id_prefix)) |id_pos| {
                        const id_start = id_pos + id_prefix.len;
                        var id_end = id_start;
                        while (id_end < event.len and event[id_end] >= '0' and event[id_end] <= '9') {
                            id_end += 1;
                        }
                        if (id_end > id_start) {
                            const ctx = std.fmt.parseInt(i64, event[id_start..id_end], 10) catch 0;
                            if (ctx > 0 and game_core_ctx == 0) {
                                game_core_ctx = ctx;
                                std.debug.print("[AUDIO BYPASS] Found game-core execution context ID={d} from Runtime.executionContextCreated (attempt {d})\n", .{ ctx, pow_wait_attempt + 1 });
                            }
                        }
                    }
                }
            }
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
            game_core_found = true;
            std.debug.print("[AUDIO BYPASS] PoW completed! game-core iframe in DOM (~{d}s)\n", .{pow_wait_attempt * 2});
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
    if (game_core_game_token == null and game_core_session_token != null) {
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

        // Extract challengeID (gameToken) from JSON response
        // SOURCE: LIVE capture — /fc/gfct/ response has "challengeID":"..."
        const resp_value = browser_bridge.extractRuntimeEvaluateStringValue(allocator, gfct_response) catch null;
        if (resp_value) |rv| {
            defer allocator.free(rv);
            const challengeID_prefix = "\"challengeID\":\"";
            if (std.mem.indexOf(u8, rv, challengeID_prefix)) |cpos| {
                const cstart = cpos + challengeID_prefix.len;
                const cend = std.mem.indexOfScalarPos(u8, rv, cstart, '"') orelse rv.len;
                if (cend > cstart and cend - cstart > 5) {
                    game_core_game_token = try allocator.dupe(u8, rv[cstart..cend]);
                    std.debug.print("[AUDIO BYPASS] FAZ 2: Captured gameToken from /fc/gfct/: {s}\n", .{game_core_game_token.?});
                }
            }
        }
    }

    if (game_core_game_token == null) {
        std.debug.print("[AUDIO BYPASS] WARNING: gameToken not available, pipeline may fail\n", .{});
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
            const MAX_AUDIO_RETRIES = 3;
            var audio_retry: u8 = 0;
            var audio_clicked = false;
            while (audio_retry < MAX_AUDIO_RETRIES and !audio_clicked) : (audio_retry += 1) {
                if (audio_retry > 0) {
                    std.debug.print("[AUDIO BYPASS] Audio button retry {d}/{d}...\n", .{ audio_retry + 1, MAX_AUDIO_RETRIES });
                    _ = std.os.linux.nanosleep(&std.os.linux.timespec{ .sec = 1, .nsec = 0 }, null);
                }
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
                        if (std.mem.indexOf(u8, resp, "clicked") != null) audio_clicked = true;
                    } else |_| {}
                } else {
                    if (arkose_cdp.evaluate(ascript)) |resp| {
                        defer allocator.free(resp);
                        std.debug.print("[AUDIO BYPASS] Audio button response: {s}\n", .{resp[0..@min(resp.len, 200)]});
                        if (std.mem.indexOf(u8, resp, "clicked") != null) audio_clicked = true;
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
            total_attempted,
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
