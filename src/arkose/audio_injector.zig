// =============================================================================
// Module — Arkose Audio Bypass: Browser Enjeksiyon
// Target: Arkose Labs Audio CAPTCHA — answer input + submit button
// =============================================================================
//
// WIRE-TRUTH ANALYSIS (LIVE TEST 2026-04-25 via ChromeDevTools MCP):
// - CDP /json endpoint reveals 3 targets: 1 page + 2 iframe chain
//   github.com/signup → octocaptcha.com → github-api.arkoselabs.com/enforcement
// - Cross-origin iframes: contentDocument returns null from main page JS context
// - CDP Runtime.evaluate with contextId is REQUIRED for iframe JS injection
// - Audio button lives inside the arkoselabs.com enforcement iframe
//
// DOM DISCOVERY (ChromeDevTools MCP snapshot, 2026-04-25):
// - github.com/signup: form has email/password/username inputs + "Create account" button
// - octocaptcha iframe: class="js-octocaptcha-frame", src populated after form submit
// - arkoselabs iframe: nested inside octocaptcha, contains Arkose challenge UI
//
// SOURCE: Chrome DevTools Protocol — Runtime.evaluate with contextId for subframes
// SOURCE: Chrome DevTools Protocol — Runtime.enable sends executionContextCreated events
// SOURCE: Arkose Labs audio CAPTCHA UI — answer input + submit button (live test 2026-04-24)
// SOURCE: RFC 6455, Section 5.2 — WebSocket framing (CDP transport)

const std = @import("std");
const mem = std.mem;
const browser_bridge = @import("../browser_bridge.zig");

// =============================================================================
// Audio Button Selectors — Arkose Captcha Iframe (arkoselabs.com)
// =============================================================================
// SOURCE: Arkose Labs enforcement UI — audio challenge button variants
// SOURCE: LIVE ChromeDevTools MCP DOM snapshot 2026-04-25:
//   enforcement iframe → game-core/1.34.1/standard/index.html
//   button text "Audio puzzle" (NO aria-label!)
//   button text "Visual puzzle" description="Visual challenge. Audio challenge is available below..."
//
// NOTE: Arkose does NOT use aria-label on the audio button. The button text is
// "Audio puzzle". We use textContent-based matching because CSS can't select by text.
//
// JAVASCRIPT: These are injected via CDP Runtime.evaluate. The template uses
// document.querySelectorAll + textContent.includes() pattern.
pub const AUDIO_BUTTON_SELECTORS = [_][]const u8{
    "button[aria-label*=\"Audio\"]",
    "button[aria-label*=\"audio\"]",
    "button[class*=\"audio\"]",
    "button[class*=\"Audio\"]",
    "[data-testid*=\"audio\"]",
    "[data-testid*=\"Audio\"]",
    "button[id*=\"audio\"]",
};

// TEXT-based audio button finder (real Arkose uses text "Audio puzzle", no aria-label)
// SOURCE: LIVE DOM 2026-04-25 — button text "Audio puzzle" in game-core iframe
pub const AUDIO_BTN_TEXT_MATCHER =
    \\(() => {
    \\  const btns = document.querySelectorAll('button');
    \\  for (const btn of btns) {
    \\    if (btn.textContent.trim().includes('Audio') && btn.offsetParent !== null) {
    \\      btn.click();
    \\      return 'clicked_text_audio';
    \\    }
    \\  }
    \\  return 'no_text_audio_button';
    \\})()
;

// ANSWER INPUT SELECTORS — real DOM: textbox "Answer field", required, type number
// SOURCE: LIVE DOM 2026-04-25 — game-core iframe audio challenge UI
pub const ANSWER_INPUT_SELECTORS = [_][]const u8{
    "input[type=\"text\"]",
    "input[aria-label*=\"Answer\"]",
    "input[aria-label*=\"answer\"]",
    "input[aria-label*=\"Answer field\"]",
    "input[placeholder*=\"answer\"]",
    "input[placeholder*=\"Answer\"]",
};

// SUBMIT BUTTON SELECTORS — real DOM: button text "Submit", game-core iframe
// SOURCE: LIVE DOM 2026-04-25
// NOTE: Arkose commonly uses <input type="submit">, not <button>. Also include
// input[type="button"] and [role="button"] for modern framework compatibility.
// EVIDENCE: browser_bridge.zig:2855 already queries input[type="submit"]
pub const SUBMIT_BUTTON_SELECTORS = [_][]const u8{
    "input[type=\"submit\"]",
    "button[type=\"submit\"]",
    "button[class*=\"submit\"]",
    "button[class*=\"Submit\"]",
    "button[id*=\"submit\"]",
    "input[type=\"button\"][value*=\"Submit\"]",
    "[role=\"button\"]",
};

// TEXT-based submit button finder: queries ALL interactive elements and checks
// both .textContent (for <button>) and .value (for <input>)
pub const SUBMIT_BTN_TEXT_MATCHER =
    \\(() => {
    \\  const btns = document.querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"]');
    \\  for (const btn of btns) {
    \\    const txt = (btn.textContent || btn.value || '').trim();
    \\    if (txt === 'Submit' && btn.offsetParent !== null) {
    \\      btn.click();
    \\      return 'clicked_submit';
    \\    }
    \\  }
    \\  return 'no_submit_button';
    \\})()
;

/// Build JSON array string from Zig selector slices: `["s1","s2",...]`
fn selectorsToJson(allocator: std.mem.Allocator, selectors: []const []const u8) ![]u8 {
    var total: usize = 1;
    for (selectors, 0..) |sel, i| {
        total += 2; // quotes around value
        if (i > 0) total += 1; // comma
        for (sel) |ch| {
            total += 1;
            if (ch == '\\' or ch == '"') total += 1; // escape
        }
    }
    total += 1; // closing bracket
    const buf = try allocator.alloc(u8, total);
    var pos: usize = 0;
    buf[pos] = '[';
    pos += 1;
    for (selectors, 0..) |sel, i| {
        if (i > 0) {
            buf[pos] = ',';
            pos += 1;
        }
        buf[pos] = '"';
        pos += 1;
        for (sel) |ch| {
            if (ch == '\\' or ch == '"') {
                buf[pos] = '\\';
                pos += 1;
            }
            buf[pos] = ch;
            pos += 1;
        }
        buf[pos] = '"';
        pos += 1;
    }
    buf[pos] = ']';
    std.debug.assert(pos + 1 == total);
    return buf[0 .. pos + 1];
}

// =============================================================================
// findAudioButton — Arkose captcha iframe'inde audio butonunu bul
// =============================================================================
// SOURCE: CDP Runtime.evaluate with contextId — targets iframe execution context
// SOURCE: Arkose Labs enforcement UI DOM structure (live MCP discovery 2026-04-25)
// SOURCE: Real DOM: button text "Audio puzzle" (NO aria-label!), enforcement→game-core iframe
//
// Strategy: Try CSS selectors first, fallback to textContent-based matching.
// Returns: true if audio button was found and clicked, false otherwise.
pub fn findAudioButton(bridge: *browser_bridge.BrowserBridge, context_id: i64) !bool {
    const selectors_json = try selectorsToJson(bridge.allocator, &AUDIO_BUTTON_SELECTORS);
    defer bridge.allocator.free(selectors_json);

    const find_script = try std.fmt.allocPrint(bridge.allocator,
        \\(() => {{
        \\  const selectors = {s};
        \\  for (const sel of selectors) {{
        \\    const btn = document.querySelector(sel);
        \\    if (btn && btn.offsetParent !== null) {{
        \\      btn.click();
        \\      return 'clicked_audio_' + sel;
        \\    }}
        \\  }}
        \\  // TEXT fallback: real Arkose button has text "Audio puzzle", no aria-label
        \\  const btns = document.querySelectorAll('button');
        \\  for (const btn of btns) {{
        \\    if (btn.textContent.trim().includes('Audio') && btn.offsetParent !== null) {{
        \\      btn.click();
        \\      return 'clicked_text_Audio';
        \\    }}
        \\  }}
        \\  return 'no_audio_button_visible';
        \\}})()
    , .{selectors_json});
    defer bridge.allocator.free(find_script);

    const response = try bridge.cdp.evaluateInContext(find_script, context_id);
    defer bridge.allocator.free(response);
    std.debug.print("[AUDIO INJECTOR] findAudioButton (ctx={d}): {s}\n", .{ context_id, response[0..@min(response.len, 200)] });

    return mem.indexOf(u8, response, "clicked_") != null;
}

// =============================================================================
// injectAnswerInContext — CDP contextId ile iframe icine cevap enjekte et
// =============================================================================
// SOURCE: Chrome DevTools Protocol — Runtime.evaluate with contextId for iframes
// SOURCE: Arkose Labs audio CAPTCHA — answer input + submit button (live test)
//
// Cross-origin iframe'lerde (octocaptcha.com, arkoselabs.com) contentDocument null
// dondurdugu icin ana sayfadaki JS kodu iframe icine erisemez. Bu yuzden CDP'nin
// Runtime.evaluate metodu contextId parametresiyle dogrudan iframe execution
// context'inde calistirilir.
//
// Steps:
//   1. context_id: CDP execution context ID (Runtime.executionContextCreated event'inden)
//   2. Fill answer input with the digit (1-3)
//   3. Dispatch input/change events for framework reactivity
//   4. Click submit button
//   5. Sleep 1.5s for Arkose to process
pub fn injectAnswerInContext(bridge: *browser_bridge.BrowserBridge, answer: u8, context_id: i64) !void {
    const answer_selectors_json = try selectorsToJson(bridge.allocator, &ANSWER_INPUT_SELECTORS);
    defer bridge.allocator.free(answer_selectors_json);
    const submit_selectors_json = try selectorsToJson(bridge.allocator, &SUBMIT_BUTTON_SELECTORS);
    defer bridge.allocator.free(submit_selectors_json);

    const answer_script = try std.fmt.allocPrint(bridge.allocator,
        \\(() => {{
        \\  const selectors = {s};
        \\  for (const sel of selectors) {{
        \\    const el = document.querySelector(sel);
        \\    if (el) {{
        \\      el.value = {any};
        \\      el.dispatchEvent(new Event('input', {{ bubbles: true }}));
        \\      el.dispatchEvent(new Event('change', {{ bubbles: true }}));
        \\      return 'filled_ctx_' + sel;
        \\    }}
        \\  }}
        \\  return 'no_input_in_context';
        \\}})()
    , .{ answer_selectors_json, answer });
    defer bridge.allocator.free(answer_script);

    const fill_response = try bridge.cdp.evaluateInContext(answer_script, context_id);
    defer bridge.allocator.free(fill_response);
    std.debug.print("[AUDIO INJECTOR] Answer inject (ctx={d}): {s}\n", .{ context_id, fill_response[0..@min(fill_response.len, 200)] });

    const submit_script = try std.fmt.allocPrint(bridge.allocator,
        \\(() => {{
        \\  const selectors = {s};
        \\  for (const sel of selectors) {{
        \\    const btn = document.querySelector(sel);
        \\    if (btn && btn.offsetParent !== null) {{
        \\      btn.click();
        \\      return 'clicked_ctx_' + sel;
        \\    }}
        \\  }}
        \\  // TEXT fallback: real Arkose game-core uses <input type="submit" value="Submit">
        \\  const btns = document.querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"]');
        \\  for (const btn of btns) {{
        \\    const txt = (btn.textContent || btn.value || '').trim();
        \\    if (txt === 'Submit' && btn.offsetParent !== null) {{
        \\      btn.click();
        \\      return 'clicked_text_Submit';
        \\    }}
        \\  }}
        \\  return 'no_submit_in_context';
        \\}})()
    , .{submit_selectors_json});
    defer bridge.allocator.free(submit_script);

    const submit_response = try bridge.cdp.evaluateInContext(submit_script, context_id);
    defer bridge.allocator.free(submit_response);
    std.debug.print("[AUDIO INJECTOR] Submit (ctx={d}): {s}\n", .{ context_id, submit_response[0..@min(submit_response.len, 200)] });

    const submit_grace = std.os.linux.timespec{ .sec = 1, .nsec = 500 * std.time.ns_per_ms };
    _ = std.os.linux.nanosleep(&submit_grace, null);
}

// =============================================================================
// injectAnswer — Cevabi browser'a Runtime.evaluate ile inject eder (ana sayfa)
// =============================================================================
// SOURCE: Chrome DevTools Protocol — Runtime.evaluate with context targeting
// SOURCE: Arkose Labs audio CAPTCHA — answer input mutiple selector fallback
//
// NOTE: Bu fonksiyon ANA SAYFA context'inde calisir. Cross-origin arkose iframe'leri
// icin injectAnswerInContext kullanilmalidir. Bu fonksiyon yalnizca same-origin
// iframe'lerde veya captcha'nin ana sayfaya embed edildigi durumlarda calisir.
//
// Steps:
//   1. Fill answer input with the digit (1-3)
//   2. Dispatch input/change events for framework reactivity
//   3. Click submit button
//   4. Sleep 1.5s for Arkose to process
pub fn injectAnswer(bridge: *browser_bridge.BrowserBridge, answer: u8) !void {
    const ans_json = try selectorsToJson(bridge.allocator, &ANSWER_INPUT_SELECTORS);
    defer bridge.allocator.free(ans_json);
    const sub_json = try selectorsToJson(bridge.allocator, &SUBMIT_BUTTON_SELECTORS);
    defer bridge.allocator.free(sub_json);

    const answer_script = try std.fmt.allocPrint(bridge.allocator,
        \\(() => {{
        \\  const selectors = {s};
        \\  for (const sel of selectors) {{
        \\    const el = document.querySelector(sel);
        \\    if (el) {{
        \\      el.value = {any};
        \\      el.dispatchEvent(new Event('input', {{ bubbles: true }}));
        \\      el.dispatchEvent(new Event('change', {{ bubbles: true }}));
        \\      return 'filled_' + sel;
        \\    }}
        \\  }}
        \\  return 'no_input_found';
        \\}})()
    , .{ ans_json, answer });
    defer bridge.allocator.free(answer_script);

    const fill_response = try bridge.cdp.evaluateWithTimeout(answer_script, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS);
    defer bridge.allocator.free(fill_response);
    std.debug.print("[AUDIO INJECTOR] Answer injection: {s}\n", .{fill_response[0..@min(fill_response.len, 200)]});

    const submit_script = try std.fmt.allocPrint(bridge.allocator,
        \\(() => {{
        \\  const selectors = {s};
        \\  for (const sel of selectors) {{
        \\    const btn = document.querySelector(sel);
        \\    if (btn) {{
        \\      btn.click();
        \\      return 'clicked_' + sel;
        \\    }}
        \\  }}
        \\  // Fallback for <input type="submit"> and [role="button"]
        \\  const btns = document.querySelectorAll('input[type="submit"], input[type="button"], [role="button"]');
        \\  for (const btn of btns) {{
        \\    const txt = (btn.value || btn.textContent || '').trim();
        \\    if (txt.toLowerCase().includes('submit')) {{
        \\      btn.click();
        \\      return 'clicked_fallback_' + txt;
        \\    }}
        \\  }}
        \\  return 'no_submit_found';
        \\}})()
    , .{sub_json});
    defer bridge.allocator.free(submit_script);

    const submit_response = try bridge.cdp.evaluateWithTimeout(submit_script, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS);
    defer bridge.allocator.free(submit_response);
    std.debug.print("[AUDIO INJECTOR] Submit action: {s}\n", .{submit_response[0..@min(submit_response.len, 200)]});

    const submit_grace = std.os.linux.timespec{ .sec = 1, .nsec = 500 * std.time.ns_per_ms };
    _ = std.os.linux.nanosleep(&submit_grace, null);
}

/// Inject answer and submit using a DIRECT CDP connection to the target iframe context.
/// Unlike injectAnswer() which goes through BrowserBridge (main page context),
/// this function sends JS directly into the iframe via its execution context ID.
/// SOURCE: CDP Runtime.evaluate — execute JavaScript in specific execution context
/// SOURCE: Arkose Labs audio CAPTCHA — answer input + submit button (live test)
pub fn injectAnswerOnTarget(
    cdp: *browser_bridge.CdpClient,
    allocator: std.mem.Allocator,
    answer: u8,
    context_id: i64,
) !void {
    // SESSION VALIDATION TEST: 1+1 evaluate before injection
    // If this drops silently → session invalid (timing değil escape)
    // If returns 2 → session valid, look elsewhere (escape or JS error)
    std.debug.print("[AUDIO INJECTOR] SESSION TEST: Evaluating 1+1 (ctx={d})...\n", .{context_id});
    const session_test = if (context_id > 0)
        cdp.evaluateInContext("1+1", context_id)
    else
        cdp.evaluate("1+1");
    if (session_test) |test_result| {
        defer allocator.free(test_result);
        std.debug.print("[AUDIO INJECTOR] SESSION TEST RESULT: {s}\n", .{test_result[0..@min(test_result.len, 50)]});
        if (test_result.len == 0) {
            std.debug.print("[AUDIO INJECTOR] SESSION INVALID: 1+1 returned empty → session dropped, not timing!\n", .{});
            return error.CdpSessionInvalid;
        }
    } else |err| {
        std.debug.print("[AUDIO INJECTOR] SESSION TEST FAILED: {} → session invalid\n", .{err});
        return error.CdpSessionInvalid;
    }

    // FIX: Always use the discovered context_id for injection (matches audio_bypass.zig pattern)
    // FIX: Wrap JS in IIFE to avoid "Illegal return statement" SyntaxError in global scope
    // FIX: Use direct document selectors since contextId is the game-core execution context itself
    // FIX: Use evaluateWithTimeout / evaluateInContextWithTimeout for infinite-loop protection

    const answer_script = try std.fmt.allocPrint(allocator,
        \\(() => {{
        \\  const inp = document.querySelector('input[type="text"]') || document.querySelector('input');
        \\  if (!inp) return 'no_input';
        \\  inp.value = {d};
        \\  inp.dispatchEvent(new Event('input', {{ bubbles: true }}));
        \\  inp.dispatchEvent(new Event('change', {{ bubbles: true }}));
        \\  return 'filled';
        \\}})()
    , .{answer});
    defer allocator.free(answer_script);

    const fill_response = if (context_id > 0)
        try cdp.evaluateInContextWithTimeout(answer_script, context_id, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS)
    else
        try cdp.evaluateWithTimeout(answer_script, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS);
    defer allocator.free(fill_response);
    std.debug.print("[AUDIO INJECTOR] Answer injection (target): {s}\n", .{fill_response[0..@min(fill_response.len, 200)]});

    const submit_script = try std.fmt.allocPrint(allocator,
        \\(() => {{
        \\  // Primary: <button>Submit</button> (no type attr) or <input type="submit" value="Submit">
        \\  // We search BOTH button and input[type="submit"] and match by visible text.
        \\  const allBtns = document.querySelectorAll('button, input[type="submit"]');
        \\  for (const bt of allBtns) {{
        \\    const txt = (bt.textContent || bt.value || '').trim();
        \\    if (txt === 'Submit' && bt.offsetParent !== null && !bt.disabled) {{
        \\      bt.click();
        \\      return 'clicked_text_submit';
        \\    }}
        \\  }}
        \\  // Fallback 1: generic input[type="submit"] (catches value-less or non-Submit text)
        \\  const inpSubmit = document.querySelector('input[type="submit"]');
        \\  if (inpSubmit && inpSubmit.offsetParent !== null && !inpSubmit.disabled) {{
        \\    inpSubmit.click();
        \\    return 'clicked_input_submit';
        \\  }}
        \\  // Fallback 2: button[type="submit"]
        \\  const btn = document.querySelector('button[type="submit"]');
        \\  if (btn && btn.offsetParent !== null && !btn.disabled) {{
        \\    btn.click();
        \\    return 'clicked_type_submit';
        \\  }}
        \\  // Fallback 3: ANY interactive element with submit/verify/next text
        \\  const btns = document.querySelectorAll('button, input[type="submit"], input[type="button"], [role="button"]');
        \\  for (const bt of btns) {{
        \\    const txt = (bt.textContent || bt.value || '').trim().toLowerCase();
        \\    if (bt.offsetParent !== null && !bt.disabled && (txt.includes('submit') || txt.includes('verify') || txt.includes('next'))) {{
        \\      bt.click();
        \\      return 'clicked_text_' + txt;
        \\    }}
        \\  }}
        \\  // Last resort: first visible non-audio button
        \\  for (const bt of btns) {{
        \\    const txt = (bt.textContent || bt.value || '').trim().toLowerCase();
        \\    if (bt.offsetParent !== null && !bt.disabled && !txt.includes('audio') && !txt.includes('play')) {{
        \\      bt.click();
        \\      return 'clicked_fallback';
        \\    }}
        \\  }}
        \\  return 'no_submit';
        \\}})()
    , .{});
    defer allocator.free(submit_script);

    const submit_response = if (context_id > 0)
        try cdp.evaluateInContextWithTimeout(submit_script, context_id, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS)
    else
        try cdp.evaluateWithTimeout(submit_script, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS);
    defer allocator.free(submit_response);
    std.debug.print("[AUDIO INJECTOR] Submit (target): {s}\n", .{submit_response[0..@min(submit_response.len, 200)]});

    const submit_grace = std.os.linux.timespec{ .sec = 1, .nsec = 500 * std.time.ns_per_ms };
    _ = std.os.linux.nanosleep(&submit_grace, null);
}

comptime {
    std.debug.assert(@sizeOf(browser_bridge.BrowserBridge) > 0);
    std.debug.assert(@sizeOf(browser_bridge.CdpClient) > 0);
}
