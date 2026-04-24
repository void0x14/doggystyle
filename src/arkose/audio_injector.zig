// =============================================================================
// Module — Arkose Audio Bypass: Browser Enjeksiyon
// Target: Arkose Labs Audio CAPTCHA — answer input + submit button
// =============================================================================
//
// WIRE-TRUTH ANALYSIS (LIVE TEST 2026-04-24):
// - Arkose audio CAPTCHA has a text input for the answer (1-3)
// - Submit button triggers the next challenge or completes
// - CDP Runtime.evaluate injects answer + clicks submit
// - Multiple selector fallbacks for different Arkose UI versions
//
// SOURCE: Chrome DevTools Protocol — Runtime.evaluate
// SOURCE: Arkose Labs audio CAPTCHA UI — answer input + submit button (live test 2026-04-24)
// SOURCE: RFC 6455, Section 5.2 — WebSocket framing (CDP transport)

const std = @import("std");
const browser_bridge = @import("../browser_bridge.zig");

// =============================================================================
// injectAnswer — Cevabı browser'a Runtime.evaluate ile inject eder
// =============================================================================
// SOURCE: Chrome DevTools Protocol — Runtime.evaluate with context targeting
// SOURCE: Arkose Labs audio CAPTCHA — answer input mutiple selector fallback
//
// Steps:
//   1. Fill answer input with the digit (1-3)
//   2. Dispatch input/change events for framework reactivity
//   3. Click submit button
//   4. Sleep 1.5s for Arkose to process
pub fn injectAnswer(bridge: *browser_bridge.BrowserBridge, answer: u8) !void {
    const answer_script = try std.fmt.allocPrint(bridge.allocator,
        \\(() => {{
        \\  const selectors = [
        \\    'input[type="text"]',
        \\    'input[data-an="audio-response"]',
        \\    '#audio-fallback-response',
        \\    '.audio-captcha-input',
        \\    'input[aria-label*="answer" i]',
        \\    'input[aria-label*="audio" i]',
        \\  ];
        \\  for (const sel of selectors) {{
        \\    const el = document.querySelector(sel);
        \\    if (el) {{
        \\      el.value = '{d}';
        \\      el.dispatchEvent(new Event('input', {{ bubbles: true }}));
        \\      el.dispatchEvent(new Event('change', {{ bubbles: true }}));
        \\      return 'filled_' + sel;
        \\    }}
        \\  }}
        \\  const frames = document.querySelectorAll('iframe');
        \\  for (const f of frames) {{
        \\    try {{
        \\      const idoc = f.contentDocument || f.contentWindow.document;
        \\      if (idoc) {{
        \\        for (const sel of selectors) {{
        \\          const el = idoc.querySelector(sel);
        \\          if (el) {{
        \\            el.value = '{d}';
        \\            el.dispatchEvent(new Event('input', {{ bubbles: true }}));
        \\            el.dispatchEvent(new Event('change', {{ bubbles: true }}));
        \\            return 'filled_iframe_' + sel;
        \\          }}
        \\        }}
        \\      }}
        \\    }} catch(e) {{ continue; }}
        \\  }}
        \\  return 'no_input_found';
        \\}})()
    , .{ answer, answer });
    defer bridge.allocator.free(answer_script);

    const fill_response = try bridge.cdp.evaluateWithTimeout(answer_script, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS);
    defer bridge.allocator.free(fill_response);
    std.debug.print("[AUDIO INJECTOR] Answer injection: {s}\n", .{fill_response[0..@min(fill_response.len, 200)]});

    const submit_script =
        \\(() => {
        \\  const submitSelectors = [
        \\    'button[type="submit"]',
        \\    'button:has-text("Submit")',
        \\    'button:has-text("Verify")',
        \\    'button:has-text("OK")',
        \\    '[data-an="audio-submit"]',
        \\    '#audio-submit',
        \\    '.audio-captcha-submit',
        \\  ];
        \\  for (const sel of submitSelectors) {
        \\    const btn = document.querySelector(sel);
        \\    if (btn) {
        \\      btn.click();
        \\      return 'clicked_' + sel;
        \\    }
        \\  }
        \\  const frames = document.querySelectorAll('iframe');
        \\  for (const f of frames) {
        \\    try {
        \\      const idoc = f.contentDocument || f.contentWindow.document;
        \\      if (idoc) {
        \\        for (const sel of submitSelectors) {
        \\          const el = idoc.querySelector(sel);
        \\          if (el) {
        \\            el.click();
        \\            return 'clicked_iframe_' + sel;
        \\          }
        \\        }
        \\      }
        \\    } catch(e) { continue; }
        \\  }
        \\  return 'no_submit_found';
        \\})()
    ;

    const submit_response = try bridge.cdp.evaluateWithTimeout(submit_script, browser_bridge.HUMAN_ACTION_EVALUATE_TIMEOUT_MS);
    defer bridge.allocator.free(submit_response);
    std.debug.print("[AUDIO INJECTOR] Submit action: {s}\n", .{submit_response[0..@min(submit_response.len, 200)]});

    const submit_grace = std.os.linux.timespec{ .sec = 1, .nsec = 500 * std.time.ns_per_ms };
    _ = std.os.linux.nanosleep(&submit_grace, null);
}

comptime {
    std.debug.assert(@sizeOf(browser_bridge.BrowserBridge) > 0);
}
