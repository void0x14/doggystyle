# CDP Flatten Session Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Move Arkose/CDP iframe handling from direct iframe WebSocket guessing to explicit `Target.attachToTarget({ flatten: true })` session routing.

**Architecture:** Keep existing direct WebSocket path until new session-aware path is proven with tests and live diagnostics. Add session-aware CDP command routing, target discovery, execution-context mapping, then switch Arkose injection behind one feature flag or narrow call-site change.

**Tech Stack:** Zig 0.16.0-dev vendored compiler, Chrome DevTools Protocol Target/Runtime/Page domains, RFC 6455 WebSocket transport, existing `CdpClient` in `src/browser_bridge.zig`.

---

## Source Grounding

- Chrome DevTools Protocol `Target.attachToTarget`: returns `sessionId`; `flatten: true` routes child target traffic via top-level CDP messages.
- Chrome DevTools Protocol `Target.setAutoAttach`: attaches to related targets; recursive auto-attach is needed for nested OOPIF chains.
- Chrome DevTools Protocol `Runtime.enable`: emits existing `Runtime.executionContextCreated` events for that session.
- Chrome DevTools Protocol `Runtime.evaluate`: supports `contextId`, `uniqueContextId`, `timeout`, `awaitPromise`, `returnByValue`.
- Existing project failure log: `docs/failure_log.md` warns CDP response/event parsing bugs are recurring; all changes must be tested at wire-message level.

## Phase 0: Baseline Diagnostics Before Architecture Change

**Files:**
- Modify: `src/browser_bridge.zig`
- Modify: `src/arkose/audio_bypass.zig`
- Test: `src/browser_bridge.zig`

- [ ] **Step 1: Add failing test for session id extraction from flattened CDP messages**

```zig
test "extractTopLevelSessionId: reads flattened CDP sessionId" {
    const allocator = std.testing.allocator;
    const message = "{\"sessionId\":\"S1\",\"id\":7,\"result\":{}}";

    const session_id = try extractTopLevelSessionId(allocator, message);
    defer allocator.free(session_id.?);

    try std.testing.expect(session_id != null);
    try std.testing.expectEqualStrings("S1", session_id.?);
}
```

- [ ] **Step 2: Run red test**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: FAIL with `use of undeclared identifier 'extractTopLevelSessionId'`.

- [ ] **Step 3: Implement minimal session id parser**

```zig
const TopLevelSessionIdEnvelope = struct {
    sessionId: ?[]const u8 = null,
};

fn extractTopLevelSessionId(allocator: std.mem.Allocator, response: []const u8) !?[]u8 {
    var parsed = std.json.parseFromSlice(TopLevelSessionIdEnvelope, allocator, response, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return null;
    defer parsed.deinit();
    if (parsed.value.sessionId) |session_id| return try allocator.dupe(u8, session_id);
    return null;
}
```

- [ ] **Step 4: Verify green**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: all tests pass.

- [ ] **Step 5: Add diagnostic-only logging for CDP session fields**

In `sendCommand()`, when reading each response frame, log `method`, expected id, response id, `sessionId` presence, action `return`, `buffer_event`, or `drop_unmatched_response`. Do not change behavior in this phase.

Expected log format:

```zig
std.debug.print("[CDP WIRE] recv expected_id={d} response_id={?d} session={s} action={s} len={d}\n", .{
    self.msg_id,
    resp_id_opt,
    session_id_opt orelse "none",
    action,
    response.len,
});
```

- [ ] **Step 6: Verify diagnostics do not break tests**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: all tests pass.

## Phase 1: Session-Aware Command Construction

**Files:**
- Modify: `src/browser_bridge.zig`
- Test: `src/browser_bridge.zig`

- [ ] **Step 1: Add failing test for command JSON with top-level sessionId**

```zig
test "buildCdpCommand: puts sessionId at top level for flattened target sessions" {
    var buf: [1024]u8 = undefined;
    const msg = try buildCdpCommand(&buf, 3, "Runtime.enable", "{}", "SESSION-1");

    try std.testing.expectEqualStrings(
        "{\"id\":3,\"method\":\"Runtime.enable\",\"params\":{},\"sessionId\":\"SESSION-1\"}",
        msg,
    );
}
```

- [ ] **Step 2: Run red test**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: FAIL with `use of undeclared identifier 'buildCdpCommand'`.

- [ ] **Step 3: Implement command builder**

```zig
fn buildCdpCommand(buf: []u8, id: u32, method: []const u8, params: []const u8, session_id: ?[]const u8) ![]u8 {
    if (session_id) |sid| {
        if (params.len > 0) {
            return std.fmt.bufPrint(buf, "{{\"id\":{d},\"method\":\"{s}\",\"params\":{s},\"sessionId\":\"{s}\"}}", .{ id, method, params, sid });
        }
        return std.fmt.bufPrint(buf, "{{\"id\":{d},\"method\":\"{s}\",\"sessionId\":\"{s}\"}}", .{ id, method, sid });
    }
    if (params.len > 0) {
        return std.fmt.bufPrint(buf, "{{\"id\":{d},\"method\":\"{s}\",\"params\":{s}}}", .{ id, method, params });
    }
    return std.fmt.bufPrint(buf, "{{\"id\":{d},\"method\":\"{s}\"}}", .{ id, method });
}
```

- [ ] **Step 4: Refactor `sendCommand()` to use builder with `null` session**

Replace manual `std.fmt.bufPrint()` message construction in `sendCommand()` with:

```zig
const msg = buildCdpCommand(&msg_buf, self.msg_id, method, params, null) catch return error.OutOfMemory;
```

- [ ] **Step 5: Add `sendCommandInSession()`**

```zig
pub fn sendCommandInSession(self: *CdpClient, session_id: []const u8, method: []const u8, params: []const u8) ![]u8 {
    self.msg_id += 1;
    var msg_buf: [MAX_CDP_BUF]u8 = undefined;
    const msg = buildCdpCommand(&msg_buf, self.msg_id, method, params, session_id) catch return error.OutOfMemory;
    try self.sendWsText(msg);
    return self.readCommandResponse(self.msg_id, session_id);
}
```

- [ ] **Step 6: Extract response loop into `readCommandResponse()`**

```zig
fn readCommandResponse(self: *CdpClient, expected_id: u32, expected_session_id: ?[]const u8) ![]u8 {
    while (true) {
        const response = try self.recvWsTextAlloc();
        const resp_id_opt = extractTopLevelMessageId(self.allocator, response);
        if (resp_id_opt) |resp_id| {
            const session_match = true; // Replace in Phase 2 after tests cover session filtering.
            if (resp_id == expected_id and session_match) return response;
            self.allocator.free(response);
        } else {
            try self.pending_events.append(response);
        }
    }
}
```

- [ ] **Step 7: Verify green**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: all tests pass.

## Phase 2: Session-Aware Response Matching

**Files:**
- Modify: `src/browser_bridge.zig`
- Test: `src/browser_bridge.zig`

- [ ] **Step 1: Add failing test for same id but wrong session**

```zig
test "sendCommandInSession: ignores same id response from different session" {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
    if (rc == std.math.maxInt(usize)) return error.SocketFailed;
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    const allocator = std.testing.allocator;
    var client = CdpClient{
        .fd = fds[0],
        .allocator = allocator,
        .msg_id = 0,
        .pending_events = std.array_list.Managed([]u8).init(allocator),
    };
    defer {
        for (client.pending_events.items) |event| allocator.free(event);
        client.pending_events.deinit();
    }

    const wrong = "{\"sessionId\":\"OTHER\",\"id\":1,\"result\":{}}";
    const right = "{\"sessionId\":\"TARGET\",\"id\":1,\"result\":{}}";
    var wrong_header: [2]u8 = .{ WS_FIN_BIT | WS_OPCODE_TEXT, @intCast(wrong.len) };
    var right_header: [2]u8 = .{ WS_FIN_BIT | WS_OPCODE_TEXT, @intCast(right.len) };
    try writeAll(fds[1], &wrong_header, wrong_header.len);
    try writeAll(fds[1], wrong.ptr, wrong.len);
    try writeAll(fds[1], &right_header, right_header.len);
    try writeAll(fds[1], right.ptr, right.len);

    const response = try client.sendCommandInSession("TARGET", "Runtime.enable", "{}");
    defer allocator.free(response);
    try std.testing.expectEqualStrings(right, response);
}
```

- [ ] **Step 2: Run red test**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: FAIL because wrong-session response is returned or dropped incorrectly.

- [ ] **Step 3: Implement session match in response loop**

```zig
const session_match = blk: {
    if (expected_session_id) |expected| {
        const actual_opt = try extractTopLevelSessionId(self.allocator, response);
        defer if (actual_opt) |actual| self.allocator.free(actual);
        break :blk actual_opt != null and std.mem.eql(u8, actual_opt.?, expected);
    }
    break :blk true;
};
```

- [ ] **Step 4: Preserve wrong-session response as event or diagnostic drop**

Wrong-session id responses must not be treated as matching. For first implementation, log and free them; later task can add per-session pending response map if needed.

- [ ] **Step 5: Verify green**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: all tests pass.

## Phase 3: Target Discovery and Attach

**Files:**
- Modify: `src/browser_bridge.zig`
- Modify: `src/arkose/audio_bypass.zig`
- Test: `src/browser_bridge.zig`

- [ ] **Step 1: Add `TargetInfo` parser test for `/json` target dump**

Test should parse target `id`, `type`, `url`, and `webSocketDebuggerUrl` from existing `/json` response shape. Keep current `getArkoseWsUrl()` behavior unchanged.

- [ ] **Step 2: Add `targetGetTargets()` wrapper**

```zig
pub fn targetGetTargets(self: *CdpClient) ![]u8 {
    return self.sendCommand("Target.getTargets", "{}");
}
```

- [ ] **Step 3: Add `attachToTargetFlattened()` wrapper**

```zig
pub fn attachToTargetFlattened(self: *CdpClient, target_id: []const u8) ![]u8 {
    var target_esc: [512]u8 = undefined;
    const target_len = escapeJsonString(target_id, &target_esc);
    var params_buf: [1024]u8 = undefined;
    const params = std.fmt.bufPrint(
        &params_buf,
        "{{\"targetId\":\"{s}\",\"flatten\":true}}",
        .{target_esc[0..target_len]},
    ) catch return error.OutOfMemory;
    return self.sendCommand("Target.attachToTarget", params);
}
```

- [ ] **Step 4: Add `extractAttachSessionId()` parser**

Parse response shape:

```json
{"id":35,"result":{"sessionId":"SESSION_ID"}}
```

Return owned `[]u8`.

- [ ] **Step 5: Verify green**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: all tests pass.

## Phase 4: Runtime Context Mapping Per Session

**Files:**
- Modify: `src/browser_bridge.zig`
- Modify: `src/arkose/audio_bypass.zig`
- Test: `src/browser_bridge.zig`

- [ ] **Step 1: Add parser for `Runtime.executionContextCreated`**

Extract `sessionId`, `params.context.id`, `params.context.uniqueId`, `params.context.origin`, `params.context.auxData.frameId`, `params.context.auxData.isDefault`.

- [ ] **Step 2: Add session `Runtime.enable` wrapper**

```zig
pub fn runtimeEnableInSession(self: *CdpClient, session_id: []const u8) ![]u8 {
    return self.sendCommandInSession(session_id, "Runtime.enable", "{}");
}
```

- [ ] **Step 3: Add context dump diagnostic**

During Arkose setup, after attaching to target and enabling runtime, drain pending events and log context records:

```zig
std.debug.print("[ARKOSE CDP] context session={s} id={d} origin={s} frame={s} default={}\n", .{
    session_id,
    context.id,
    context.origin,
    context.frame_id orelse "none",
    context.is_default,
});
```

- [ ] **Step 4: Verify green**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: all tests pass.

## Phase 5: Session-Based Arkose Injection Behind Narrow Switch

**Files:**
- Modify: `src/arkose/audio_bypass.zig`
- Modify: `src/arkose/audio_injector.zig`
- Modify: `src/browser_bridge.zig`
- Test: `src/browser_bridge.zig`

- [ ] **Step 1: Keep direct iframe path as default**

Do not delete `getArkoseWsUrl()` or `connectToTarget()` yet.

- [ ] **Step 2: Add opt-in constant**

```zig
const USE_FLATTENED_ARKOSE_SESSION = false;
```

- [ ] **Step 3: Add session evaluate wrapper**

```zig
pub fn evaluateInSessionContextWithTimeout(
    self: *CdpClient,
    session_id: []const u8,
    expression: []const u8,
    context_id: i64,
    timeout_ms: u64,
) ![]u8 {
    const cdp_timeout = @min(timeout_ms, @as(u64, 8000));
    const sock_timeout = @min(timeout_ms, @as(u64, 5000));
    self.setReceiveTimeoutMs(sock_timeout);
    defer self.setReceiveTimeoutMs(DEFAULT_CDP_RECEIVE_TIMEOUT_MS);

    var params_buf: [MAX_CDP_BUF]u8 = undefined;
    var expr_escaped: [MAX_CDP_BUF]u8 = undefined;
    const params = buildRuntimeEvaluateParams(&params_buf, &expr_escaped, expression, .{
        .context_id = context_id,
        .timeout_ms = cdp_timeout,
    }) catch return error.OutOfMemory;
    return self.sendCommandInSession(session_id, "Runtime.evaluate", params);
}
```

- [ ] **Step 4: Add `injectAnswerOnSessionTarget()`**

Mirror `injectAnswerOnTarget()` but call `evaluateInSessionContextWithTimeout()`.

- [ ] **Step 5: Run direct path tests**

Run: `vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc`

Expected: all tests pass.

- [ ] **Step 6: Live diagnostic run with switch disabled**

Run project normal path and confirm logs still use direct iframe WS URL path.

Expected evidence: `[AUDIO BYPASS] Iframe WS URL:` still appears and no `Target.attachToTarget` session path is used.

## Phase 6: Live A/B Proof and Cutover

**Files:**
- Modify: `src/arkose/audio_bypass.zig`
- Modify: `docs/failure_log.md` only if bug fixed or new failure found

- [ ] **Step 1: Enable flattened session in one live diagnostic branch**

Set:

```zig
const USE_FLATTENED_ARKOSE_SESSION = true;
```

- [ ] **Step 2: Capture manual-vs-engine comparison table**

Log these fields:

```text
targetId
```

- [ ] **Step 3: Prove one of three outcomes**

Outcome A: flattened session succeeds, direct path fails. Keep flattened path, update failure log.

Outcome B: both paths fail same way. Session routing is not root cause; inspect context/promise/target.

Outcome C: both paths succeed. Keep direct path for now, leave flattened session as future hardening branch.

- [ ] **Step 4: Remove feature flag only after Outcome A repeats**

Repeat live run at least twice. Remove direct path only if flattened path succeeds twice and direct path fails or remains less deterministic.

- [ ] **Step 5: Full verification**

Run:

```bash
vendor/zig/zig test src/browser_bridge.zig --zig-lib-dir vendor/zig-std -lc
vendor/zig/zig build --zig-lib-dir vendor/zig-std
```

Expected: tests pass and build exits 0.

## Self-Review

- Spec coverage: plan covers session-aware command building, response matching, target attach, runtime context mapping, Arkose injection, and live A/B proof.
- Placeholder scan: no `TBD`, no generic “handle edge cases” step without exact diagnostic/action.
- Type consistency: planned helpers use existing `CdpClient`, `MAX_CDP_BUF`, `escapeJsonString`, `buildRuntimeEvaluateParams`, `sendCommand`, and `sendCommandInSession` names consistently.
- Scope check: plan intentionally leaves direct iframe path until live evidence proves flattened session routing is better.
