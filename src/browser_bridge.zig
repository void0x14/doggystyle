// =============================================================================
// Module — Browser Bridge (CDP-based token harvesting via Chrome DevTools Protocol)
// Target: google-chrome-stable (Xvfb + --remote-debugging-port)
// =============================================================================
//
// WIRE-TRUTH ANALYSIS (Chrome DevTools Protocol, 2026-04-10):
// - Chrome headless=new does NOT support extensions (confirmed by Chrome team)
// - Chrome headless=new does NOT write console.log to stdout/stderr
// - CDP Runtime.evaluate is the ONLY reliable way to inject JS and read results
// - WebSocket (RFC 6455) is required for CDP communication
//
// SOURCE: RFC 6455 — The WebSocket Protocol (framing, handshake, masking)
// SOURCE: Chrome DevTools Protocol spec — https://chromedevtools.github.io/devtools-protocol/
// SOURCE: CDP Runtime.evaluate — evaluate JavaScript in page context
// SOURCE: CDP Target.getTargetTargets — list open tabs
//
// NETWORK STACK ANALYSIS:
// [1] Chrome: --remote-debugging-port=CDP_PORT + --remote-allow-origins=*
// [2] CDP HTTP: GET /json → list tabs with WebSocket debugger URLs
// [3] CDP WebSocket: RFC 6455 client → connect to tab's wsDebuggerUrl
// [4] Runtime.evaluate: inject harvest.js, read window.__ghost_* globals
// [5] UFW/iptables: No firewall rules needed (localhost only, loopback interface)

const std = @import("std");
const mem = std.mem;
const linux = std.os.linux;
const posix = std.posix;
const browser_bundle = @import("browser_bundle.zig");

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

pub const BridgeError = error{
    OutOfMemory,
    ReadFailed,
    WriteFailed,
    ParseFailed,
    Timeout,
    ProcessTerminated,
    InvalidToken,
    SocketFailed,
    ConnectFailed,
    HandshakeFailed,
    WsFrameError,
    CdpError,
    NoTarget,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// CDP remote debugging port
/// SOURCE: Chrome DevTools Protocol — --remote-debugging-port flag
pub const CDP_PORT: u16 = 9222;

/// Maximum timeout for token extraction (15 seconds)
/// NOTE: Kept under typical TLS idle timeout (~20-30s) to prevent TlsAlertReceived
pub const EXTRACTION_TIMEOUT_MS: u64 = 15000;

/// Maximum time to wait for browser-generated request capture
pub const REQUEST_CAPTURE_TIMEOUT_MS: u64 = 30000;

/// Poll timeout for CDP WebSocket checking (100ms)
/// SOURCE: man 2 poll — timeout in milliseconds
pub const POLL_TIMEOUT_MS: i32 = 100;

/// Maximum buffer size for CDP responses
pub const MAX_CDP_BUF: usize = 65536;

/// Maximum buffer size for harvest.js source file
pub const MAX_HARVEST_SIZE: usize = 65536;

/// Maximum buffer size for browser_session_bridge.js source file
pub const MAX_BRIDGE_SCRIPT_SIZE: usize = 32768;

/// WebSocket opcodes
/// SOURCE: RFC 6455, Section 5.2 — Base Framing Protocol
const WS_OPCODE_TEXT: u8 = 0x01;
const WS_OPCODE_CLOSE: u8 = 0x08;
const WS_FIN_BIT: u8 = 0x80;
const WS_MASK_BIT: u8 = 0x80;

// ---------------------------------------------------------------------------
// CDP Client — WebSocket + Chrome DevTools Protocol
// ---------------------------------------------------------------------------

/// Minimal CDP client that connects to Chrome's remote debugging WebSocket,
/// sends Runtime.evaluate commands, and reads responses.
///
/// SOURCE: RFC 6455 — WebSocket Protocol (handshake, framing, masking)
/// SOURCE: Chrome DevTools Protocol — Runtime.evaluate method
/// SOURCE: CDP HTTP endpoint — GET /json returns tab list with wsDebuggerUrl
pub const CdpClient = struct {
    fd: i32,
    allocator: std.mem.Allocator,
    msg_id: u32 = 0,

    /// Connect to Chrome's CDP WebSocket for a specific tab.
    /// Steps:
    ///   1. HTTP GET /json to find the signup tab's wsDebuggerUrl
    ///   2. Parse the wsDebuggerUrl to extract host:port/path
    ///   3. TCP connect to the WebSocket endpoint
    ///   4. Send HTTP Upgrade request (WebSocket handshake)
    ///   5. Read 101 Switching Protocols response
    ///
    /// SOURCE: RFC 6455, Section 4.1 — Client-initiated handshake
    /// SOURCE: RFC 6455, Section 4.2 — Server handshake response
    pub fn connect(allocator: std.mem.Allocator, target_url_prefix: []const u8) !CdpClient {
        // Step 1: HTTP GET /json to find the target tab
        std.debug.print("[CDP] Step 1: Finding target tab via /json...\n", .{});
        const tab_info = try findTargetTab(allocator, target_url_prefix);
        defer allocator.free(tab_info.ws_url);

        std.debug.print("[CDP] Found target tab: {s}\n", .{tab_info.ws_url});

        // Step 2: Parse ws://host:port/path from wsDebuggerUrl
        const ws_url = tab_info.ws_url;
        // Format: ws://127.0.0.1:9222/devtools/page/TARGET_ID
        if (!mem.startsWith(u8, ws_url, "ws://")) return error.ParseFailed;
        const after_scheme = ws_url["ws://".len..];

        // Find path separator
        const path_start = mem.indexOfScalar(u8, after_scheme, '/') orelse return error.ParseFailed;
        const host_port = after_scheme[0..path_start];
        const path = after_scheme[path_start..];

        // Parse host:port
        const colon_idx = mem.lastIndexOfScalar(u8, host_port, ':') orelse return error.ParseFailed;
        const host_str = host_port[0..colon_idx];
        const port_str = host_port[colon_idx + 1 ..];
        const port = std.fmt.parseInt(u16, port_str, 10) catch return error.ParseFailed;

        std.debug.print("[CDP] Step 2: Parsed ws_url host={s} port={d} path={s}\n", .{ host_str, port, path });

        // Step 3: TCP connect via getaddrinfo — handles IPv4 and IPv6
        // SOURCE: man 3 getaddrinfo — protocol-independent name resolution
        var hints: std.c.addrinfo = .{
            .flags = .{ .NUMERICSERV = true },
            .family = std.posix.AF.UNSPEC,
            .socktype = std.posix.SOCK.STREAM,
            .protocol = 0,
            .addrlen = 0,
            .canonname = null,
            .addr = null,
            .next = null,
        };
        var gai_port_buf: [8]u8 = undefined;
        const gai_port_len = std.fmt.bufPrint(&gai_port_buf, "{d}\x00", .{port}) catch return error.OutOfMemory;
        const gai_port_z: [:0]u8 = gai_port_buf[0 .. gai_port_len.len - 1 :0];

        // host_str is a slice; need null-terminated for getaddrinfo
        var host_buf: [256:0]u8 = undefined;
        if (host_str.len >= host_buf.len) return error.ParseFailed;
        @memcpy(host_buf[0..host_str.len], host_str);
        host_buf[host_str.len] = 0;

        var result: ?*std.c.addrinfo = null;
        const gai_rc = std.c.getaddrinfo(host_buf[0..host_str.len :0].ptr, gai_port_z.ptr, &hints, &result);
        // SOURCE: man 3 getaddrinfo — returns 0 on success, nonzero error code on failure
        if (@intFromEnum(gai_rc) != 0) return error.ResolveFailed;
        defer std.c.freeaddrinfo(result.?);

        const ai = result orelse return error.ResolveFailed;

        // Iterate through getaddrinfo results — Chrome CDP may listen on IPv4 only
        var current_ai: ?*std.c.addrinfo = ai;
        var connected_fd: i32 = -1;
        while (current_ai) |cai| : (current_ai = cai.next) {
            if (cai.addr == null) continue;

            std.debug.print("[CDP] Step 3: TCP trying {s}:{d} family={d}...\n", .{ host_str, port, cai.family });

            const rc_socket = linux.socket(@bitCast(cai.family), @bitCast(cai.socktype), @bitCast(cai.protocol));
            if (@as(isize, @bitCast(rc_socket)) < 0) continue;
            const try_fd: i32 = @intCast(rc_socket);

            const rc_connect = linux.connect(try_fd, cai.addr.?, cai.addrlen);
            if (@as(isize, @bitCast(rc_connect)) < 0) {
                _ = std.c.close(try_fd);
                std.debug.print("[CDP] Step 3: connect failed family={d} (isize={d})\n", .{ cai.family, @as(isize, @bitCast(rc_connect)) });
                continue;
            }

            connected_fd = try_fd;
            std.debug.print("[CDP] Step 3: TCP connected (fd={d}, family={d})\n", .{ try_fd, cai.family });
            break;
        }

        if (connected_fd < 0) return error.ConnectFailed;
        const fd: i32 = connected_fd;
        errdefer _ = std.c.close(fd);

        // Step 4: Send WebSocket upgrade handshake
        // SOURCE: RFC 6455, Section 4.1 — Client handshake
        const ws_key = "dGhlIHNhbXBsZSBub25jZQ=="; // "the sample nonce" base64 — acceptable for localhost CDP
        var handshake_buf: [1024]u8 = undefined;
        const handshake = std.fmt.bufPrint(
            &handshake_buf,
            "GET {s} HTTP/1.1\r\n" ++
                "Host: {s}\r\n" ++
                "Upgrade: websocket\r\n" ++
                "Connection: Upgrade\r\n" ++
                "Sec-WebSocket-Key: {s}\r\n" ++
                "Sec-WebSocket-Version: 13\r\n\r\n",
            .{ path, host_port, ws_key },
        ) catch return error.OutOfMemory;

        std.debug.print("[CDP] Step 4: Sending WebSocket upgrade...\n", .{});
        try writeAll(fd, handshake.ptr, handshake.len);

        // Step 5: Read 101 Switching Protocols response
        std.debug.print("[CDP] Step 5: Waiting for 101 response...\n", .{});
        var resp_buf: [512]u8 = undefined;
        const resp_n = std.posix.read(fd, &resp_buf) catch return error.HandshakeFailed;
        if (resp_n < 15 or !mem.startsWith(u8, resp_buf[0..resp_n], "HTTP/1.1 101")) {
            std.debug.print("[CDP] Handshake failed: got {d} bytes: {s}\n", .{ resp_n, resp_buf[0..@min(resp_n, 64)] });
            return error.HandshakeFailed;
        }

        std.debug.print("[CDP] WebSocket connected to Chrome\n", .{});

        // Set socket receive timeout for WebSocket operations
        // SOURCE: man 7 socket — SO_RCVTIMEO prevents recvExact from blocking forever
        const ws_timeout = std.os.linux.timeval{ .sec = 1, .usec = 0 };
        _ = std.os.linux.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&ws_timeout), @sizeOf(std.os.linux.timeval));

        return .{
            .fd = fd,
            .allocator = allocator,
            .msg_id = 0,
        };
    }

    /// Close the CDP WebSocket connection
    /// SOURCE: RFC 6455, Section 5.5.1 — Close frame
    pub fn close(self: *CdpClient) void {
        // Send WebSocket close frame
        self.sendWsFrame(&[_]u8{ 0x88, 0x00 }) catch {};
        _ = std.c.close(self.fd);
        std.debug.print("[CDP] WebSocket closed\n", .{});
    }

    /// Send a CDP command via WebSocket and return the response
    /// SOURCE: CDP spec — commands are JSON-RPC style: {"id":N,"method":"...","params":{...}}
    pub fn sendCommand(self: *CdpClient, method: []const u8, params: []const u8) ![]u8 {
        self.msg_id += 1;

        // Build CDP JSON-RPC message
        var msg_buf: [MAX_CDP_BUF]u8 = undefined;
        const msg = if (params.len > 0)
            std.fmt.bufPrint(&msg_buf, "{{\"id\":{d},\"method\":\"{s}\",\"params\":{s}}}", .{ self.msg_id, method, params }) catch return error.OutOfMemory
        else
            std.fmt.bufPrint(&msg_buf, "{{\"id\":{d},\"method\":\"{s}\"}}", .{ self.msg_id, method }) catch return error.OutOfMemory;

        // Send via WebSocket text frame
        try self.sendWsText(msg);

        // Read response (match message id)
        while (true) {
            const response = try self.recvWsTextAlloc();
            if (extractTopLevelMessageId(self.allocator, response)) |resp_id| {
                if (resp_id == self.msg_id) {
                    return response;
                }
            }
            self.allocator.free(response);
        }
    }

    /// Evaluate JavaScript in the page context via CDP Runtime.evaluate
    /// SOURCE: CDP spec — Runtime.evaluate returns {result:{type,value}}
    pub fn evaluate(self: *CdpClient, expression: []const u8) ![]u8 {
        // Build params JSON with the expression
        var params_buf: [MAX_CDP_BUF]u8 = undefined;
        // Escape double quotes in expression for JSON
        var expr_escaped: [MAX_CDP_BUF]u8 = undefined;
        const escaped_len = escapeJsonString(expression, &expr_escaped);
        const params = std.fmt.bufPrint(
            &params_buf,
            "{{\"expression\":\"{s}\",\"returnByValue\":true,\"awaitPromise\":true}}",
            .{expr_escaped[0..escaped_len]},
        ) catch {
            std.debug.print("[CDP] evaluate: params bufPrint failed (expr_len={d}, escaped_len={d})\n", .{ expression.len, escaped_len });
            return error.OutOfMemory;
        };

        std.debug.print("[CDP] evaluate: sending Runtime.evaluate (expr_len={d}, params_len={d})\n", .{ expression.len, params.len });
        const response = self.sendCommand("Runtime.evaluate", params) catch |err| {
            std.debug.print("[CDP] evaluate: sendCommand failed: {}\n", .{err});
            return err;
        };
        std.debug.print("[CDP] evaluate: got response ({d} bytes)\n", .{response.len});
        return response;
    }

    // SOURCE: Chrome DevTools Protocol Page.addScriptToEvaluateOnNewDocument — evaluate before frame scripts.
    pub fn addScriptOnNewDocument(self: *CdpClient, source: []const u8) !void {
        var source_escaped: [MAX_CDP_BUF]u8 = undefined;
        const escaped_len = escapeJsonString(source, &source_escaped);
        var params_buf: [MAX_CDP_BUF]u8 = undefined;
        const params = std.fmt.bufPrint(
            &params_buf,
            "{{\"source\":\"{s}\"}}",
            .{source_escaped[0..escaped_len]},
        ) catch return error.OutOfMemory;
        const response = try self.sendCommand("Page.addScriptToEvaluateOnNewDocument", params);
        defer self.allocator.free(response);
    }

    // SOURCE: Chrome DevTools Protocol Page.reload — reload the inspected page.
    pub fn reloadPage(self: *CdpClient) !void {
        const response = try self.sendCommand("Page.reload", "{}");
        defer self.allocator.free(response);
    }

    // SOURCE: Chrome DevTools Protocol Page.navigate — navigate the inspected page to a URL.
    pub fn navigatePage(self: *CdpClient, url: []const u8) !void {
        var url_escaped: [2048]u8 = undefined;
        const escaped_len = escapeJsonString(url, &url_escaped);
        var params_buf: [4096]u8 = undefined;
        const params = std.fmt.bufPrint(
            &params_buf,
            "{{\"url\":\"{s}\"}}",
            .{url_escaped[0..escaped_len]},
        ) catch return error.OutOfMemory;
        const response = try self.sendCommand("Page.navigate", params);
        defer self.allocator.free(response);
    }

    // SOURCE: Chrome DevTools Protocol Fetch.enable — pause matching requests at request stage.
    pub fn enableFetchInterception(self: *CdpClient, url_pattern: []const u8) !void {
        var pattern_escaped: [1024]u8 = undefined;
        const escaped_len = escapeJsonString(url_pattern, &pattern_escaped);
        var params_buf: [4096]u8 = undefined;
        const params = std.fmt.bufPrint(
            &params_buf,
            "{{\"patterns\":[{{\"urlPattern\":\"{s}\",\"requestStage\":\"Request\"}}]}}",
            .{pattern_escaped[0..escaped_len]},
        ) catch return error.OutOfMemory;
        const response = try self.sendCommand("Fetch.enable", params);
        defer self.allocator.free(response);
    }

    pub fn disableFetchInterception(self: *CdpClient) !void {
        const response = try self.sendCommand("Fetch.disable", "{}");
        defer self.allocator.free(response);
    }

    // SOURCE: Chrome DevTools Protocol Fetch.failRequest — abort paused browser request.
    pub fn failPausedRequest(self: *CdpClient, request_id: []const u8) !void {
        var reqid_escaped: [1024]u8 = undefined;
        const escaped_len = escapeJsonString(request_id, &reqid_escaped);
        var params_buf: [2048]u8 = undefined;
        const params = std.fmt.bufPrint(
            &params_buf,
            "{{\"requestId\":\"{s}\",\"errorReason\":\"Aborted\"}}",
            .{reqid_escaped[0..escaped_len]},
        ) catch return error.OutOfMemory;
        const response = try self.sendCommand("Fetch.failRequest", params);
        defer self.allocator.free(response);
    }

    // SOURCE: Chrome DevTools Protocol Network.setCookie — set browser cookie for a URL-derived scope.
    pub fn setCookie(self: *CdpClient, name: []const u8, value: []const u8, url: []const u8) !void {
        var name_esc: [512]u8 = undefined;
        var value_esc: [2048]u8 = undefined;
        var url_esc: [1024]u8 = undefined;
        const name_len = escapeJsonString(name, &name_esc);
        const value_len = escapeJsonString(value, &value_esc);
        const url_len = escapeJsonString(url, &url_esc);
        var params_buf: [4096]u8 = undefined;
        const params = std.fmt.bufPrint(
            &params_buf,
            "{{\"name\":\"{s}\",\"value\":\"{s}\",\"url\":\"{s}\"}}",
            .{
                name_esc[0..name_len],
                value_esc[0..value_len],
                url_esc[0..url_len],
            },
        ) catch return error.OutOfMemory;
        const response = try self.sendCommand("Network.setCookie", params);
        defer self.allocator.free(response);
    }

    fn recvMessage(self: *CdpClient) ![]u8 {
        return self.recvWsTextAlloc();
    }

    /// Send a WebSocket text frame
    /// SOURCE: RFC 6455, Section 5.2 — Base framing protocol
    /// SOURCE: RFC 6455, Section 5.3 — Client-to-server masking
    fn sendWsText(self: *CdpClient, payload: []const u8) !void {
        // Build WebSocket frame header
        var header_buf: [14]u8 = undefined;
        var header_len: usize = 0;

        // Byte 0: FIN=1, RSV=000, opcode=0001 (text)
        // SOURCE: RFC 6455, Section 5.2 — first byte format
        header_buf[0] = WS_FIN_BIT | WS_OPCODE_TEXT;

        // Byte 1+: MASK=1 (client must mask), payload length
        // SOURCE: RFC 6455, Section 5.3 — client-to-server frames MUST be masked
        if (payload.len <= 125) {
            header_buf[1] = WS_MASK_BIT | @as(u8, @intCast(payload.len));
            header_len = 2;
        } else if (payload.len <= 65535) {
            header_buf[1] = WS_MASK_BIT | 126;
            const payload_len_u16: u16 = @intCast(payload.len);
            header_buf[2] = @intCast(payload_len_u16 >> 8);
            header_buf[3] = @intCast(payload_len_u16 & 0xFF);
            header_len = 4;
        } else {
            header_buf[1] = WS_MASK_BIT | 127;
            const len_be = std.mem.nativeToBig(u64, @as(u64, @intCast(payload.len)));
            header_buf[2..10].* = @bitCast(len_be);
            header_len = 10;
        }

        // Masking key: 4 random bytes (using address as pseudo-random for localhost CDP)
        // SOURCE: RFC 6455, Section 5.3 — 32-bit masking key
        const mask_key: [4]u8 = .{ 0xAB, 0xCD, 0xEF, 0x01 };
        header_buf[header_len..][0..4].* = mask_key;
        header_len += 4;

        // Write header
        try writeAll(self.fd, &header_buf, header_len);

        // Write masked payload
        // SOURCE: RFC 6455, Section 5.3 — j = i MOD 4, transformed = payload XOR mask_key[j]
        var masked_buf: [MAX_CDP_BUF]u8 = undefined;
        const write_len = @min(payload.len, masked_buf.len);
        for (payload[0..write_len], 0..) |byte, i| {
            masked_buf[i] = byte ^ mask_key[i % 4];
        }
        try writeAll(self.fd, &masked_buf, write_len);
    }

    /// Receive a WebSocket text frame and return the payload
    /// SOURCE: RFC 6455, Section 5.2 — Base framing protocol (server→client, no mask)
    fn recvWsTextAlloc(self: *CdpClient) ![]u8 {
        // Read frame header (at least 2 bytes)
        var header: [2]u8 = undefined;
        _ = try recvExact(self.fd, &header);

        // Parse opcode and FIN bit
        const opcode = header[0] & 0x0F;
        const fin = (header[0] & WS_FIN_BIT) != 0;

        // Parse payload length
        // SOURCE: RFC 6455, Section 5.2 — payload length encoding
        var payload_len: usize = header[1] & 0x7F;
        if (payload_len == 126) {
            var ext_len: [2]u8 = undefined;
            _ = try recvExact(self.fd, &ext_len);
            payload_len = (@as(usize, ext_len[0]) << 8) | @as(usize, ext_len[1]);
        } else if (payload_len == 127) {
            var ext_len: [8]u8 = undefined;
            _ = try recvExact(self.fd, &ext_len);
            payload_len = 0;
            for (ext_len) |b| payload_len = (payload_len << 8) | b;
        }

        // Server frames are NOT masked (MASK bit should be 0)
        // SOURCE: RFC 6455, Section 5.3 — server-to-client frames are NOT masked

        const payload = try self.allocator.alloc(u8, payload_len);
        errdefer self.allocator.free(payload);
        _ = try recvExact(self.fd, payload);

        // Handle close frame
        if (opcode == WS_OPCODE_CLOSE) return error.WsFrameError;

        // If not FIN, read continuation frames (simplified: just return what we have)
        _ = fin;
        return payload;
    }

    /// Send a raw WebSocket frame (for close frame etc.)
    fn sendWsFrame(self: *CdpClient, data: []const u8) !void {
        try writeAll(self.fd, data.ptr, data.len);
    }

    // -----------------------------------------------------------------------
    // HTTP helper: GET /json to find target tab
    // -----------------------------------------------------------------------

    const TabInfo = struct {
        ws_url: []u8,
    };

    /// Find the target tab by URL prefix via CDP HTTP endpoint
    /// SOURCE: Chrome DevTools Protocol — GET /json returns array of tab objects
    fn findTargetTab(allocator: std.mem.Allocator, url_prefix: []const u8) !TabInfo {
        // Resolve localhost via getaddrinfo — handles both IPv4 and IPv6
        // SOURCE: man 3 getaddrinfo — protocol-independent name resolution
        var hints: std.c.addrinfo = .{
            .flags = .{ .NUMERICSERV = true },
            .family = std.posix.AF.UNSPEC, // allow both IPv4 and IPv6
            .socktype = std.posix.SOCK.STREAM,
            .protocol = 0,
            .addrlen = 0,
            .canonname = null,
            .addr = null,
            .next = null,
        };
        var port_buf: [8]u8 = undefined;
        const port_len = std.fmt.bufPrint(&port_buf, "{d}\x00", .{CDP_PORT}) catch return error.OutOfMemory;
        const port_z: [:0]u8 = port_buf[0 .. port_len.len - 1 :0];

        var result: ?*std.c.addrinfo = null;
        const gai_rc = std.c.getaddrinfo("localhost", port_z.ptr, &hints, &result);
        if (@intFromEnum(gai_rc) != 0) return error.ResolveFailed;
        defer std.c.freeaddrinfo(result.?);

        const ai = result orelse return error.ResolveFailed;

        // Iterate through getaddrinfo results — Chrome CDP may listen on IPv4 only
        // SOURCE: man 3 getaddrinfo — result is a linked list; try each until one connects
        var current_ai: ?*std.c.addrinfo = ai;
        var connected_fd: i32 = -1;
        while (current_ai) |cai| : (current_ai = cai.next) {
            if (cai.addr == null) continue;

            std.debug.print("[CDP] Trying family={d}, addrlen={d}...\n", .{ cai.family, cai.addrlen });

            const rc_socket = linux.socket(@bitCast(cai.family), @bitCast(cai.socktype), @bitCast(cai.protocol));
            if (@as(isize, @bitCast(rc_socket)) < 0) continue;
            const try_fd: i32 = @intCast(rc_socket);

            const rc_connect = linux.connect(try_fd, cai.addr.?, cai.addrlen);
            if (@as(isize, @bitCast(rc_connect)) < 0) {
                _ = std.c.close(try_fd);
                std.debug.print("[CDP] connect failed family={d} (isize={d})\n", .{ cai.family, @as(isize, @bitCast(rc_connect)) });
                continue;
            }

            connected_fd = try_fd;
            std.debug.print("[CDP] HTTP connected to CDP (family={d})\n", .{cai.family});
            break;
        }

        if (connected_fd < 0) return error.ConnectFailed;
        const fd: i32 = connected_fd;
        defer _ = std.c.close(fd);

        // Send HTTP GET /json
        const request = "GET /json HTTP/1.1\r\nHost: localhost:9222\r\nConnection: close\r\n\r\n";
        try writeAll(fd, request.ptr, request.len);

        // Set socket receive timeout (3 seconds)
        // SOURCE: man 7 socket — SO_RCVTIMEO sets receive timeout
        const timeout = std.os.linux.timeval{
            .sec = 3,
            .usec = 0,
        };
        _ = std.os.linux.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, @ptrCast(&timeout), @sizeOf(std.os.linux.timeval));

        // Read response — Connection: close means server will close after sending
        var resp_buf: [MAX_CDP_BUF]u8 = undefined;
        var total: usize = 0;
        while (total < resp_buf.len - 1) {
            const n = std.posix.read(fd, resp_buf[total..]) catch |err| {
                std.debug.print("[CDP] read error at {d} bytes: {}\n", .{ total, err });
                break;
            };
            if (n == 0) {
                std.debug.print("[CDP] read returned 0 (connection closed) at {d} bytes\n", .{total});
                break;
            }
            total += n;
        }

        std.debug.print("[CDP] Total HTTP response: {d} bytes\n", .{total});
        if (total == 0) return error.ParseFailed;

        // Find body (after \r\n\r\n)
        const body_start = mem.indexOf(u8, resp_buf[0..total], "\r\n\r\n") orelse return error.ParseFailed;
        const body = resp_buf[body_start + 4 .. total];

        std.debug.print("[CDP] /json response: {d} bytes, body: {d} bytes\n", .{ total, body.len });
        const body_preview = @min(body.len, 1500);
        std.debug.print("[CDP] Body preview: {s}\n", .{body[0..body_preview]});

        // Parse JSON array of tab objects
        // Look for "webSocketDebuggerUrl" and "url" fields
        // Minimal JSON parsing: find the tab with matching URL prefix
        // NOTE: CDP JSON includes spaces after colons: "url": "https://..."
        // We search for the key with space flexibility
        const ws_key = "\"webSocketDebuggerUrl\": \"";
        const url_key = "\"url\": \"";

        var idx: usize = 0;
        while (idx < body.len) {
            // Find next url field
            const url_idx = mem.indexOfPos(u8, body, idx, url_key) orelse break;
            const url_val_start = url_idx + url_key.len;
            const url_val_end = mem.indexOfScalarPos(u8, body, url_val_start, '"') orelse break;
            const tab_url = body[url_val_start..url_val_end];

            std.debug.print("[CDP] Found tab URL: {s} (looking for prefix: {s})\n", .{ tab_url, url_prefix });

            // Check if this tab matches our target URL prefix
            if (mem.startsWith(u8, tab_url, url_prefix)) {
                // Find the corresponding webSocketDebuggerUrl in the same object
                // Search backwards from url_idx to find the start of this JSON object
                const obj_start = mem.indexOfPos(u8, body, url_idx, "{") orelse idx;
                const obj_end = mem.indexOfScalarPos(u8, body, url_idx, '}') orelse break;

                const ws_idx = mem.indexOfPos(u8, body, obj_start, ws_key) orelse {
                    idx = obj_end + 1;
                    continue;
                };
                const ws_val_start = obj_start + ws_idx + ws_key.len;
                const ws_val_end = mem.indexOfScalarPos(u8, body, ws_val_start, '"') orelse break;
                const ws_url = body[ws_val_start..ws_val_end];

                return .{
                    .ws_url = try allocator.dupe(u8, ws_url),
                };
            }

            idx = url_val_end + 1;
        }

        return error.NoTarget;
    }
};

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Write all bytes to fd, handling partial writes
/// SOURCE: man 2 write — may write fewer bytes than requested
fn writeAll(fd: i32, data: [*]const u8, len: usize) !void {
    var written: usize = 0;
    while (written < len) {
        // Use linux.write syscall directly — returns usize
        // SOURCE: man 2 write — on error returns -1 (as usize: maxInt(usize))
        const rc = linux.write(fd, data + written, len - written);
        if (rc == std.math.maxInt(usize)) {
            const err = std.posix.errno(rc);
            std.debug.print("[CDP] writeAll: write failed (errno={})\n", .{err});
            return error.WriteFailed;
        }
        const n: usize = @intCast(rc);
        if (n == 0) return error.WriteFailed;
        written += n;
    }
}

/// Read exactly N bytes from a file descriptor
fn recvExact(fd: i32, buf: []u8) ![]u8 {
    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch |err| {
            std.debug.print("[CDP] recvExact: read failed after {d}/{d} bytes: {}\n", .{ total, buf.len, err });
            return error.ReadFailed;
        };
        if (n == 0) {
            std.debug.print("[CDP] recvExact: EOF after {d}/{d} bytes\n", .{ total, buf.len });
            return error.ReadFailed;
        }
        total += n;
    }
    return buf;
}

fn currentTimestampNs() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
}

fn currentUnixMs() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    return (@as(i64, @intCast(ts.sec)) * 1000) + @divTrunc(@as(i64, @intCast(ts.nsec)), std.time.ns_per_ms);
}

fn parseFetchRequestPaused(
    allocator: std.mem.Allocator,
    message: []const u8,
) !PausedRequestCapture {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, message, .{}) catch return error.ParseFailed;
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.ParseFailed;
    const method_value = root.object.get("method") orelse return error.ParseFailed;
    if (method_value != .string or !mem.eql(u8, method_value.string, "Fetch.requestPaused")) {
        return error.ParseFailed;
    }

    const params_value = root.object.get("params") orelse return error.ParseFailed;
    if (params_value != .object) return error.ParseFailed;
    if (params_value.object.get("responseStatusCode") != null) return error.ParseFailed;

    const request_id_value = params_value.object.get("requestId") orelse return error.ParseFailed;
    if (request_id_value != .string) return error.ParseFailed;

    const request_value = params_value.object.get("request") orelse return error.ParseFailed;
    if (request_value != .object) return error.ParseFailed;

    const url_value = request_value.object.get("url") orelse return error.ParseFailed;
    const req_method_value = request_value.object.get("method") orelse return error.ParseFailed;
    const headers_value = request_value.object.get("headers") orelse return error.ParseFailed;
    if (url_value != .string or req_method_value != .string or headers_value != .object) return error.ParseFailed;

    var headers = try allocator.alloc(browser_bundle.HeaderPair, headers_value.object.count());
    errdefer allocator.free(headers);
    var header_iter = headers_value.object.iterator();
    var header_count: usize = 0;
    while (header_iter.next()) |entry| {
        if (entry.value_ptr.* != .string) return error.ParseFailed;
        headers[header_count] = .{
            .name = try allocator.dupe(u8, entry.key_ptr.*),
            .value = try allocator.dupe(u8, entry.value_ptr.*.string),
        };
        header_count += 1;
    }

    const post_data = if (request_value.object.get("postData")) |pd| blk: {
        if (pd != .string) return error.ParseFailed;
        break :blk try allocator.dupe(u8, pd.string);
    } else try allocator.dupe(u8, "");

    return .{
        .request_id = try allocator.dupe(u8, request_id_value.string),
        .bundle = .{
            .url = try allocator.dupe(u8, url_value.string),
            .method = try allocator.dupe(u8, req_method_value.string),
            .post_data = post_data,
            .headers = headers[0..header_count],
        },
    };
}

/// Parse IPv4 address string (e.g., "127.0.0.1") into network-byte-order u32
fn parseIpv4Addr(str: []const u8) !u32 {
    var parts = mem.splitSequence(u8, str, ".");
    var result: u32 = 0;
    var i: usize = 0;
    while (parts.next()) |part| {
        if (i >= 4) return error.ParseFailed;
        const octet = std.fmt.parseInt(u8, part, 10) catch return error.ParseFailed;
        result = (result << 8) | @as(u32, octet);
        i += 1;
    }
    if (i != 4) return error.ParseFailed;
    return result; // Already in big-endian (network byte order)
}

/// Escape double quotes and backslashes in a string for JSON embedding
fn escapeJsonString(input: []const u8, output: []u8) usize {
    var out_idx: usize = 0;
    for (input) |ch| {
        if (out_idx >= output.len - 2) break;
        if (ch == '\\') {
            output[out_idx] = '\\';
            output[out_idx + 1] = '\\';
            out_idx += 2;
        } else if (ch == '"') {
            output[out_idx] = '\\';
            output[out_idx + 1] = '"';
            out_idx += 2;
        } else if (ch == '\n') {
            output[out_idx] = '\\';
            output[out_idx + 1] = 'n';
            out_idx += 2;
        } else if (ch == '\r') {
            output[out_idx] = '\\';
            output[out_idx + 1] = 'r';
            out_idx += 2;
        } else {
            output[out_idx] = ch;
            out_idx += 1;
        }
    }
    return out_idx;
}

fn readBrowserSessionBridgeScript(buf: []u8) ![]u8 {
    const fd = std.posix.openat(std.posix.AT.FDCWD, "src/browser_session_bridge.js", .{ .ACCMODE = .RDONLY }, 0) catch
        return error.ReadFailed;
    defer _ = std.c.close(fd);

    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch return error.ReadFailed;
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

fn sanitizeTraceLabel(label: []const u8, buf: []u8) []const u8 {
    var len: usize = 0;
    for (label) |ch| {
        if (len >= buf.len) break;
        buf[len] = if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_') ch else '_';
        len += 1;
    }
    if (len == 0) {
        buf[0] = 'x';
        return buf[0..1];
    }
    return buf[0..len];
}

// ---------------------------------------------------------------------------
// Harvested Data Structures
// ---------------------------------------------------------------------------

const PausedRequestCapture = struct {
    request_id: []u8,
    bundle: browser_bundle.RequestBundle,

    fn deinit(self: *const PausedRequestCapture, allocator: std.mem.Allocator) void {
        allocator.free(self.request_id);
        var bundle = self.bundle;
        bundle.deinit(allocator);
    }
};

const BrowserUiState = struct {
    url: []const u8,
    title: []const u8,
    octocaptcha_length: usize,
    email_length: usize,
    password_length: usize,
    login_length: usize,
    submit_hidden: ?bool,
    submit_disabled: ?bool,
    load_button_hidden: ?bool,
    load_button_disabled: ?bool,
    has_captcha_frame: bool,
    has_verify_completed: bool,
    has_account_verif_text: bool,
    has_cookie_banner: bool,
    iframe_src: ?[]const u8,
    text_snippet: []const u8,
};

// ---------------------------------------------------------------------------
// Browser Audit Result — structured observability for every bridge action
// SOURCE: PRD "Full Real-Time Browser Observability System", ticket 446647de
// ---------------------------------------------------------------------------

/// Enum of all bridge action kinds for type-safe audit logging
pub const BrowserActionKind = enum {
    signup_start,
    signup_submit,
    verify_submit,
    dismiss_blockers,
    evaluate,
};

/// Structured audit result returned by every bridge helper function.
/// Replaces bare `bool` / `void` returns with full provenance:
/// what was attempted, whether it succeeded, element state before/after,
/// screenshot path, and precise timestamp.
pub const BrowserAuditResult = struct {
    ok: bool = false,
    selector: ?[]const u8 = null,
    element_found: bool = false,
    action_kind: BrowserActionKind = .evaluate,
    chars_written: usize = 0,
    state_after: ?[]const u8 = null,
    screenshot_path: ?[]const u8 = null,
    timestamp_ms: u64 = 0,
    err_msg: ?[]const u8 = null,

    /// Serialize this audit result to the browser-actions.ndjson file.
    /// Must be called by the bridge after the result is fully constructed.
    pub fn logToActions(self: *const BrowserAuditResult, bridge: *BrowserBridge) BridgeError!void {
        const trace_dir = bridge.diagnostics_dir orelse return;

        var path_buf: [1024]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/browser-actions.ndjson", .{trace_dir}) catch return error.OutOfMemory;
        const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .APPEND = true,
            .CLOEXEC = true,
        }, 0o644) catch return error.WriteFailed;
        defer _ = std.c.close(fd);

        // Build JSON line manually to avoid type coercion issues
        var line_buf = std.array_list.Managed(u8).init(bridge.allocator);
        defer line_buf.deinit();

        var tmp: [64]u8 = undefined;
        try line_buf.appendSlice("{\"timestamp_ms\":");
        try line_buf.appendSlice(std.fmt.bufPrint(&tmp, "{d}", .{self.timestamp_ms}) catch return error.OutOfMemory);
        try line_buf.appendSlice(",\"action\":\"");
        try line_buf.appendSlice(@tagName(self.action_kind));
        try line_buf.appendSlice("\",\"ok\":");
        try line_buf.appendSlice(if (self.ok) "true" else "false");
        try line_buf.appendSlice(",\"selector\":\"");
        if (self.selector) |s| {
            var esc: [512]u8 = undefined;
            const elen = escapeJsonString(s, &esc);
            try line_buf.appendSlice(esc[0..elen]);
        }
        try line_buf.appendSlice("\",\"element_found\":");
        try line_buf.appendSlice(if (self.element_found) "true" else "false");
        try line_buf.appendSlice(",\"chars_written\":");
        try line_buf.appendSlice(std.fmt.bufPrint(&tmp, "{d}", .{self.chars_written}) catch return error.OutOfMemory);
        try line_buf.appendSlice(",\"state_after\":\"");
        if (self.state_after) |s| {
            var esc: [512]u8 = undefined;
            const elen = escapeJsonString(s, &esc);
            try line_buf.appendSlice(esc[0..elen]);
        }
        try line_buf.appendSlice("\",\"screenshot_path\":\"");
        if (self.screenshot_path) |s| {
            try line_buf.appendSlice(s);
        }
        try line_buf.appendSlice("\",\"error\":");
        if (self.err_msg) |e| {
            var esc: [512]u8 = undefined;
            const elen = escapeJsonString(e, &esc);
            try line_buf.appendSlice("\"");
            try line_buf.appendSlice(esc[0..elen]);
            try line_buf.appendSlice("\"");
        } else {
            try line_buf.appendSlice("null");
        }
        try line_buf.appendSlice("}\n");

        try writeAll(fd, line_buf.items.ptr, line_buf.items.len);
    }

    /// Construct an error result from a Zig error
    pub fn fromError(err: anytype, kind: BrowserActionKind, ts: u64) BrowserAuditResult {
        return .{
            .ok = false,
            .action_kind = kind,
            .timestamp_ms = ts,
            .err_msg = @errorName(err),
        };
    }
};
comptime {
    // BrowserAuditResult is NOT packed (contains slices and optionals).
    // Size check for sanity: should be reasonable on 64-bit.
    std.debug.assert(@sizeOf(BrowserAuditResult) <= 128);
}

const RuntimeEvaluateStringEnvelope = struct {
    result: struct {
        result: struct {
            type: []const u8,
            value: []const u8,
        },
    },
};

const TopLevelMessageIdEnvelope = struct {
    id: ?u32 = null,
};

/// Captured Arkose token data from Chrome stdout
/// SOURCE: harvest.js GHOST_TOKEN: prefix format
pub const HarvestedToken = struct {
    token: [4096]u8 = [_]u8{0} ** 4096,
    token_len: usize = 0,
    url: [512]u8 = [_]u8{0} ** 512,
    url_len: usize = 0,
    method: [16]u8 = [_]u8{0} ** 16,
    method_len: usize = 0,
    timestamp: u64 = 0,

    pub fn isValid(self: *const HarvestedToken) bool {
        return self.token_len > 0 and self.token_len >= 100;
    }
};

/// Captured identity/cookie data from Chrome stdout
/// SOURCE: harvest.js GHOST_IDENTITY: prefix format
pub const HarvestedIdentity = struct {
    _octo: [512]u8 = [_]u8{0} ** 512,
    _octo_len: usize = 0,
    logged_in: [512]u8 = [_]u8{0} ** 512,
    logged_in_len: usize = 0,
    session: [512]u8 = [_]u8{0} ** 512,
    session_len: usize = 0,
    timestamp: u64 = 0,

    pub fn isValid(self: *const HarvestedIdentity) bool {
        return self._octo_len > 0 or self.logged_in_len > 0 or self.session_len > 0;
    }
};

/// Complete harvest result (token + identity)
pub const HarvestResult = struct {
    token: HarvestedToken = .{},
    identity: HarvestedIdentity = .{},
    token_captured: bool = false,
    identity_captured: bool = false,

    pub fn isComplete(self: *const HarvestResult) bool {
        return self.token_captured and self.identity_captured;
    }
};

// ---------------------------------------------------------------------------
// Browser Bridge — Main struct (CDP-based)
// ---------------------------------------------------------------------------

/// Manages CDP-based token harvesting from Chrome via Runtime.evaluate
///
/// Lifecycle:
///   1. init() — Connect to Chrome's CDP WebSocket for the signup tab
///   2. harvest() — Inject harvest.js via Runtime.evaluate, poll window.__ghost_* globals
///   3. deinit() — Close CDP WebSocket
pub const BrowserBridge = struct {
    allocator: mem.Allocator,
    cdp: CdpClient,
    result: HarvestResult = .{},
    start_time_ns: i64 = 0,
    diagnostics_dir: ?[]u8 = null,
    last_diag_fingerprint: u64 = 0,
    last_diag_log_ns: i64 = 0,
    screenshot_seq: usize = 0,
    latest_screenshot_name: ?[]u8 = null,

    /// Initialize bridge by connecting to Chrome's CDP WebSocket
    ///
    /// Connects to the tab whose URL starts with target_url_prefix.
    /// SOURCE: CDP spec — GET /json returns tab list with wsDebuggerUrl
    pub fn init(
        allocator: mem.Allocator,
        target_url_prefix: []const u8,
    ) BridgeError!BrowserBridge {
        var ts: std.posix.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        const now_ns = @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));

        // Wait for Chrome to start and load the target page
        // Retry connecting to CDP every 500ms for up to 10 seconds
        var cdp: CdpClient = undefined;
        var connected = false;
        var attempts: u32 = 0;
        while (!connected and attempts < 20) {
            cdp = CdpClient.connect(allocator, target_url_prefix) catch {
                attempts += 1;
                // Sleep 500ms between retries
                // SOURCE: man 2 nanosleep — suspends execution for specified interval
                const sleep_req = std.os.linux.timespec{ .sec = 0, .nsec = 500 * std.time.ns_per_ms };
                _ = std.os.linux.nanosleep(&sleep_req, null);
                continue;
            };
            connected = true;
        }

        if (!connected) {
            std.debug.print("[BRIDGE] Failed to connect to CDP after {d} attempts\n", .{attempts});
            return BridgeError.ConnectFailed;
        }

        var bridge_script_buf: [MAX_BRIDGE_SCRIPT_SIZE]u8 = undefined;
        const bridge_script = readBrowserSessionBridgeScript(&bridge_script_buf) catch return BridgeError.ReadFailed;
        try cdp.addScriptOnNewDocument(bridge_script);
        try cdp.reloadPage();

        return BrowserBridge{
            .allocator = allocator,
            .cdp = cdp,
            .start_time_ns = now_ns,
        };
    }

    pub fn enableDiagnostics(self: *BrowserBridge, trace_dir: []const u8) BridgeError!void {
        if (self.diagnostics_dir) |existing| self.allocator.free(existing);
        if (self.latest_screenshot_name) |existing| {
            self.allocator.free(existing);
            self.latest_screenshot_name = null;
        }
        self.diagnostics_dir = try self.allocator.dupe(u8, trace_dir);
        self.last_diag_fingerprint = 0;
        self.last_diag_log_ns = 0;
        self.screenshot_seq = 0;
        try self.emitDiagnosticState("bridge-enabled", true);
    }

    /// Inject harvest.js and poll for harvested token/identity data
    ///
    /// Steps:
    ///   1. Read harvest.js source file
    ///   2. Inject via CDP Runtime.evaluate
    ///   3. Poll window.__ghost_token and window.__ghost_identity globals
    ///   4. Parse JSON results into HarvestResult
    pub fn harvest(self: *BrowserBridge) BridgeError!HarvestResult {
        // Step 1: Read harvest.js source
        var harvest_buf: [MAX_HARVEST_SIZE]u8 = undefined;
        const harvest_js = readHarvestJs(&harvest_buf) catch |err| {
            std.debug.print("[BRIDGE] Failed to read harvest.js: {}\n", .{err});
            return BridgeError.ReadFailed;
        };

        // Step 2: Inject harvest.js via CDP Runtime.evaluate
        std.debug.print("[BRIDGE] Injecting harvest.js ({d} bytes) via CDP...\n", .{harvest_js.len});
        const inject_result = self.cdp.evaluate(harvest_js) catch |err| {
            std.debug.print("[BRIDGE] Failed to inject harvest.js: {}\n", .{err});
            return BridgeError.CdpError;
        };
        defer self.allocator.free(inject_result);
        std.debug.print("[BRIDGE] harvest.js injected successfully\n", .{});

        // Step 3: Poll window.__ghost_token and window.__ghost_identity
        while (!self.result.isComplete()) {
            if (self.hasTimedOut()) {
                return BridgeError.Timeout;
            }

            // Poll for token if not yet captured
            if (!self.result.token_captured) {
                const token_expr = "JSON.stringify(window.__ghost_token || null)";
                const token_resp = self.cdp.evaluate(token_expr) catch {
                    // Sleep and retry
                    const sleep_req = std.os.linux.timespec{ .sec = 0, .nsec = 500 * std.time.ns_per_ms };
                    _ = std.os.linux.nanosleep(&sleep_req, null);
                    continue;
                };
                defer self.allocator.free(token_resp);
                self.parseCdpValue(token_resp, "token") catch {};
            }

            // Poll for identity if not yet captured
            if (!self.result.identity_captured) {
                const identity_expr = "JSON.stringify(window.__ghost_identity || null)";
                const identity_resp = self.cdp.evaluate(identity_expr) catch {
                    const sleep_req = std.os.linux.timespec{ .sec = 0, .nsec = 500 * std.time.ns_per_ms };
                    _ = std.os.linux.nanosleep(&sleep_req, null);
                    continue;
                };
                defer self.allocator.free(identity_resp);
                self.parseCdpValue(identity_resp, "identity") catch {};
            }

            // Sleep between polls
            const sleep_req = std.os.linux.timespec{ .sec = 0, .nsec = 500 * std.time.ns_per_ms };
            _ = std.os.linux.nanosleep(&sleep_req, null);
        }

        return self.result;
    }

    pub fn captureSignupBundle(
        self: *BrowserBridge,
        username: []const u8,
        email: []const u8,
        password: []const u8,
        country: []const u8,
    ) BridgeError!browser_bundle.SignupBundle {
        try self.waitForTruthyExpression(
            "document.readyState === 'complete' && !!document.querySelector('form[action=\"/signup?social=false\"]')",
            REQUEST_CAPTURE_TIMEOUT_MS,
        );
        try self.cdp.enableFetchInterception("*github.com/signup?social=false*");
        defer self.cdp.disableFetchInterception() catch {};

        _ = try self.startSignupChallenge(username, email, password, country);
        std.debug.print("[BRIDGE] Waiting for browser-owned final signup request after visible Create account trigger...\n", .{});

        const paused = try self.waitForPausedRequest("/signup?social=false", REQUEST_CAPTURE_TIMEOUT_MS);
        defer self.allocator.free(paused.request_id);
        try self.cdp.failPausedRequest(paused.request_id);

        std.debug.print("[BRIDGE] Signup bundle captured: url={s}, method={s}, body={d} bytes\n", .{
            paused.bundle.url,
            paused.bundle.method,
            paused.bundle.post_data.len,
        });
        if (paused.bundle.headerValue("cookie")) |cookie| {
            std.debug.print("[BRIDGE] Signup bundle cookie header: {d} bytes\n", .{cookie.len});
        }

        return .{ .request = paused.bundle };
    }

    pub fn captureVerifyBundle(self: *BrowserBridge, verification_code: []const u8) BridgeError!browser_bundle.VerifyBundle {
        try self.waitForTruthyExpression(
            "location.pathname.includes('/account_verifications') && !!document.querySelector('form')",
            REQUEST_CAPTURE_TIMEOUT_MS,
        );
        try self.cdp.enableFetchInterception("*account_verifications*");
        defer self.cdp.disableFetchInterception() catch {};

        _ = try self.triggerVerificationSubmit(verification_code);

        const paused = try self.waitForPausedRequest("/account_verifications", REQUEST_CAPTURE_TIMEOUT_MS);
        defer self.allocator.free(paused.request_id);
        try self.cdp.failPausedRequest(paused.request_id);

        std.debug.print("[BRIDGE] Verify bundle captured: url={s}, method={s}, body={d} bytes\n", .{
            paused.bundle.url,
            paused.bundle.method,
            paused.bundle.post_data.len,
        });

        return .{ .request = paused.bundle };
    }

    pub fn navigateToAccountVerifications(self: *BrowserBridge) BridgeError!void {
        try self.cdp.navigatePage("https://github.com/account_verifications");
        try self.waitForTruthyExpression(
            "location.pathname.includes('/account_verifications')",
            REQUEST_CAPTURE_TIMEOUT_MS,
        );
    }

    pub fn syncGitHubCookies(
        self: *BrowserBridge,
        user_session: ?[]const u8,
        host_user_session: ?[]const u8,
        gh_sess: ?[]const u8,
        octo: ?[]const u8,
    ) BridgeError!void {
        if (user_session) |value| try self.cdp.setCookie("user_session", value, "https://github.com/");
        if (host_user_session) |value| try self.cdp.setCookie("__Host-user_session_same_site", value, "https://github.com/");
        if (gh_sess) |value| try self.cdp.setCookie("_gh_sess", value, "https://github.com/");
        if (octo) |value| try self.cdp.setCookie("_octo", value, "https://github.com/");
    }

    fn startSignupChallenge(
        self: *BrowserBridge,
        username: []const u8,
        email: []const u8,
        password: []const u8,
        country: []const u8,
    ) BridgeError!BrowserAuditResult {
        const ts = @as(u64, @intCast(currentUnixMs()));
        const selector = "form[action=\"/signup?social=false\"]";
        var user_esc: [512]u8 = undefined;
        var email_esc: [1024]u8 = undefined;
        var pass_esc: [1024]u8 = undefined;
        var country_esc: [128]u8 = undefined;
        const user_len = escapeJsonString(username, &user_esc);
        const email_len = escapeJsonString(email, &email_esc);
        const pass_len = escapeJsonString(password, &pass_esc);
        const country_len = escapeJsonString(country, &country_esc);
        const total_chars = user_len + email_len + pass_len + country_len;
        var expr_buf: [4096]u8 = undefined;
        const expression = std.fmt.bufPrint(
            &expr_buf,
            "window.__ghostBridge.startSignupChallenge({{\"username\":\"{s}\",\"email\":\"{s}\",\"password\":\"{s}\",\"country\":\"{s}\"}})",
            .{
                user_esc[0..user_len],
                email_esc[0..email_len],
                pass_esc[0..pass_len],
                country_esc[0..country_len],
            },
        ) catch return error.OutOfMemory;
        const response = try self.cdp.evaluate(expression);
        defer self.allocator.free(response);

        // Determine success from response
        const ok = extractRuntimeEvaluateStringValue(self.allocator, response) catch null;

        // Get screenshot name BEFORE capture so we can include it in the audit result
        var screenshot_name_buf: [32]u8 = undefined;
        const trace_dir = self.diagnostics_dir;
        if (trace_dir != null) {
            screenshot_name_buf = self.nextScreenshotName("signup-start");
        }
        const screenshot_path_slice: []const u8 = screenshot_name_buf[0..mem.indexOfScalar(u8, &screenshot_name_buf, 0) orelse 0];

        const result: BrowserAuditResult = if (ok) |val| blk: {
            defer self.allocator.free(val);
            break :blk .{
                .ok = true,
                .selector = selector,
                .element_found = true,
                .action_kind = .signup_start,
                .chars_written = total_chars,
                .state_after = "dispatched",
                .screenshot_path = if (trace_dir != null and screenshot_path_slice.len > 0) try self.allocator.dupe(u8, screenshot_path_slice) else null,
                .timestamp_ms = ts,
                .err_msg = null,
            };
        } else .{
            .ok = false,
            .selector = selector,
            .element_found = false,
            .action_kind = .signup_start,
            .chars_written = total_chars,
            .state_after = "failed",
            .screenshot_path = null,
            .timestamp_ms = ts,
            .err_msg = "no_response",
        };

        // Capture screenshot for audit trail
        if (trace_dir) |tdir| {
            self.captureScreenshot(tdir, "signup-start") catch {};
        }

        try result.logToActions(self);
        return result;
    }

    fn finishSignupSubmit(self: *BrowserBridge) BridgeError!BrowserAuditResult {
        const ts = @as(u64, @intCast(currentUnixMs()));
        const selector = "button.js-octocaptcha-form-submit, button[data-verify-submit-button]";
        const response = try self.cdp.evaluate("window.__ghostBridge.finishSignupSubmit()");
        defer self.allocator.free(response);

        const ok = extractRuntimeEvaluateStringValue(self.allocator, response) catch null;

        var ss_buf1: [32]u8 = undefined;
        const trace_dir1 = self.diagnostics_dir;
        if (trace_dir1 != null) ss_buf1 = self.nextScreenshotName("signup-submit");
        const ss_slice1: []const u8 = ss_buf1[0..mem.indexOfScalar(u8, &ss_buf1, 0) orelse 0];

        const result: BrowserAuditResult = if (ok) |val| blk: {
            defer self.allocator.free(val);
            break :blk .{
                .ok = true,
                .selector = selector,
                .element_found = true,
                .action_kind = .signup_submit,
                .chars_written = 0,
                .state_after = "submitted",
                .screenshot_path = if (trace_dir1 != null and ss_slice1.len > 0) try self.allocator.dupe(u8, ss_slice1) else null,
                .timestamp_ms = ts,
                .err_msg = null,
            };
        } else .{
            .ok = false,
            .selector = selector,
            .element_found = false,
            .action_kind = .signup_submit,
            .chars_written = 0,
            .state_after = "failed",
            .screenshot_path = null,
            .timestamp_ms = ts,
            .err_msg = "no_response",
        };

        if (trace_dir1) |tdir| {
            self.captureScreenshot(tdir, "signup-submit") catch {};
        }

        try result.logToActions(self);
        return result;
    }

    fn triggerVerificationSubmit(self: *BrowserBridge, verification_code: []const u8) BridgeError!BrowserAuditResult {
        const ts = @as(u64, @intCast(currentUnixMs()));
        const selector = "input[name=\"verification_code\"], [data-verify-code-input]";
        var code_esc: [128]u8 = undefined;
        const code_len = escapeJsonString(verification_code, &code_esc);
        var expr_buf: [1024]u8 = undefined;
        const expression = std.fmt.bufPrint(
            &expr_buf,
            "window.__ghostBridge.submitVerification({{\"code\":\"{s}\"}})",
            .{code_esc[0..code_len]},
        ) catch return error.OutOfMemory;
        const response = try self.cdp.evaluate(expression);
        defer self.allocator.free(response);

        const ok = extractRuntimeEvaluateStringValue(self.allocator, response) catch null;

        var ss_buf2: [32]u8 = undefined;
        const trace_dir2 = self.diagnostics_dir;
        if (trace_dir2 != null) ss_buf2 = self.nextScreenshotName("verify-submit");
        const ss_slice2: []const u8 = ss_buf2[0..mem.indexOfScalar(u8, &ss_buf2, 0) orelse 0];

        const result: BrowserAuditResult = if (ok) |val| blk: {
            defer self.allocator.free(val);
            break :blk .{
                .ok = true,
                .selector = selector,
                .element_found = true,
                .action_kind = .verify_submit,
                .chars_written = code_len,
                .state_after = "submitted",
                .screenshot_path = if (trace_dir2 != null and ss_slice2.len > 0) try self.allocator.dupe(u8, ss_slice2) else null,
                .timestamp_ms = ts,
                .err_msg = null,
            };
        } else .{
            .ok = false,
            .selector = selector,
            .element_found = false,
            .action_kind = .verify_submit,
            .chars_written = code_len,
            .state_after = "failed",
            .screenshot_path = null,
            .timestamp_ms = ts,
            .err_msg = "no_response",
        };

        if (trace_dir2) |tdir| {
            self.captureScreenshot(tdir, "verify-submit") catch {};
        }

        try result.logToActions(self);
        return result;
    }

    fn dismissPageBlockers(self: *BrowserBridge) BridgeError!BrowserAuditResult {
        const ts = @as(u64, @intCast(currentUnixMs()));
        const response = try self.cdp.evaluate("JSON.stringify(window.__ghostBridge.dismissPageBlockers())");
        defer self.allocator.free(response);

        // dismiss-blockers is best-effort; even a response means it ran
        const ok = extractRuntimeEvaluateStringValue(self.allocator, response) catch null;
        const result: BrowserAuditResult = if (ok) |val| blk: {
            defer self.allocator.free(val);
            break :blk .{
                .ok = true,
                .selector = "button[class*=\"dismiss\"], button[aria-label*=\"close\"], [class*=\"cookie-banner\"]",
                .element_found = true,
                .action_kind = .dismiss_blockers,
                .chars_written = 0,
                .state_after = "dismissed",
                .screenshot_path = null,
                .timestamp_ms = ts,
                .err_msg = null,
            };
        } else .{
            .ok = false,
            .selector = "button[class*=\"dismiss\"], button[aria-label*=\"close\"], [class*=\"cookie-banner\"]",
            .element_found = false,
            .action_kind = .dismiss_blockers,
            .chars_written = 0,
            .state_after = "failed",
            .screenshot_path = null,
            .timestamp_ms = ts,
            .err_msg = "no_response",
        };

        try result.logToActions(self);
        return result;
    }

    /// Log a network event to browser-network.ndjson
    /// SOURCE: PRD "Full Real-Time Browser Observability System", ticket a273db8e
    fn logNetworkEvent(
        self: *BrowserBridge,
        event_type: []const u8,
        url: []const u8,
        method: []const u8,
        has_post_data: bool,
        post_data_length: usize,
        phase_label: []const u8,
    ) BridgeError!void {
        const trace_dir = self.diagnostics_dir orelse return;

        var path_buf: [1024]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/browser-network.ndjson", .{trace_dir}) catch return error.OutOfMemory;
        const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .APPEND = true,
            .CLOEXEC = true,
        }, 0o644) catch return error.WriteFailed;
        defer _ = std.c.close(fd);

        var line_buf = std.array_list.Managed(u8).init(self.allocator);
        defer line_buf.deinit();

        var tmp: [64]u8 = undefined;
        try line_buf.appendSlice("{\"timestamp_ms\":");
        try line_buf.appendSlice(std.fmt.bufPrint(&tmp, "{d}", .{currentUnixMs()}) catch return error.OutOfMemory);
        try line_buf.appendSlice(",\"event_type\":\"");
        try line_buf.appendSlice(event_type);
        try line_buf.appendSlice("\",\"url\":\"");
        // URL-escape the URL (minimal: just escape quotes and backslashes)
        {
            var i: usize = 0;
            while (i < url.len) : (i += 1) {
                if (url[i] == '"') {
                    try line_buf.appendSlice("\\\"");
                } else if (url[i] == '\\') {
                    try line_buf.appendSlice("\\\\");
                } else {
                    try line_buf.appendSlice(url[i .. i + 1]);
                }
            }
        }
        try line_buf.appendSlice("\",\"method\":\"");
        try line_buf.appendSlice(method);
        try line_buf.appendSlice("\",\"has_post_data\":");
        try line_buf.appendSlice(if (has_post_data) "true" else "false");
        try line_buf.appendSlice(",\"post_data_length\":");
        try line_buf.appendSlice(std.fmt.bufPrint(&tmp, "{d}", .{post_data_length}) catch return error.OutOfMemory);
        try line_buf.appendSlice(",\"phase_label\":\"");
        try line_buf.appendSlice(phase_label);
        try line_buf.appendSlice("\"}\n");

        try writeAll(fd, line_buf.items.ptr, line_buf.items.len);
    }

    fn waitForPausedRequest(self: *BrowserBridge, url_substring: []const u8, timeout_ms: u64) BridgeError!PausedRequestCapture {
        const start_ns = currentTimestampNs();
        while (@as(u64, @intCast(@divTrunc(currentTimestampNs() - start_ns, std.time.ns_per_ms))) < timeout_ms) {
            _ = self.dismissPageBlockers() catch {};
            self.emitDiagnosticState("request-wait", false) catch {};
            const message = self.cdp.recvMessage() catch |err| switch (err) {
                error.ReadFailed => continue,
                else => return err,
            };
            defer self.allocator.free(message);
            const paused = parseFetchRequestPaused(self.allocator, message) catch |err| switch (err) {
                error.ParseFailed => continue,
                else => return err,
            };
            if (mem.indexOf(u8, paused.bundle.url, url_substring) != null) {
                // Log matched network event to browser-network.ndjson
                const phase_label = if (mem.indexOf(u8, url_substring, "signup") != null)
                    "signup-capture"
                else if (mem.indexOf(u8, url_substring, "account_verifications") != null)
                    "verify-capture"
                else
                    "unknown";
                try self.logNetworkEvent(
                    "request_paused",
                    paused.bundle.url,
                    paused.bundle.method,
                    paused.bundle.post_data.len > 0,
                    paused.bundle.post_data.len,
                    phase_label,
                );
                return paused;
            }
            paused.deinit(self.allocator);
        }
        self.logSignupBrowserState() catch {};
        return BridgeError.Timeout;
    }

    fn waitForTruthyExpression(self: *BrowserBridge, expression: []const u8, timeout_ms: u64) BridgeError!void {
        const start_ns = currentTimestampNs();
        while (@as(u64, @intCast(@divTrunc(currentTimestampNs() - start_ns, std.time.ns_per_ms))) < timeout_ms) {
            try self.emitDiagnosticState("wait-loop", false);
            const response = self.cdp.evaluate(expression) catch {
                const sleep_req = std.os.linux.timespec{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
                _ = std.os.linux.nanosleep(&sleep_req, null);
                continue;
            };
            defer self.allocator.free(response);
            if (mem.indexOf(u8, response, "\"value\":true") != null) return;

            const sleep_req = std.os.linux.timespec{ .sec = 0, .nsec = 100 * std.time.ns_per_ms };
            _ = std.os.linux.nanosleep(&sleep_req, null);
        }
        self.logSignupBrowserState() catch {};
        return BridgeError.Timeout;
    }

    fn logSignupBrowserState(self: *BrowserBridge) BridgeError!void {
        try self.emitDiagnosticState("timeout", true);
    }

    fn emitDiagnosticState(self: *BrowserBridge, label: []const u8, force_screenshot: bool) BridgeError!void {
        const trace_dir = self.diagnostics_dir orelse return;
        const now_ns = currentTimestampNs();
        if (!force_screenshot and self.last_diag_log_ns != 0 and now_ns - self.last_diag_log_ns < std.time.ns_per_s) {
            return;
        }

        const state = try self.observeUiState();
        defer self.freeUiState(state);
        const fingerprint = self.fingerprintUiState(state);
        const changed = fingerprint != self.last_diag_fingerprint;
        self.last_diag_fingerprint = fingerprint;
        self.last_diag_log_ns = now_ns;
        const timestamp_ms = currentUnixMs();

        std.debug.print(
            "[BRIDGE][{s}][{d}] url={s} title={s} token_len={d} email_len={d} password_len={d} login_len={d} load_hidden={any} load_disabled={any} submit_hidden={any} submit_disabled={any} captcha_frame={} verify_completed={} account_verif={} cookie_banner={} iframe={s}\n",
            .{
                label,
                timestamp_ms,
                state.url,
                state.title,
                state.octocaptcha_length,
                state.email_length,
                state.password_length,
                state.login_length,
                state.load_button_hidden,
                state.load_button_disabled,
                state.submit_hidden,
                state.submit_disabled,
                state.has_captcha_frame,
                state.has_verify_completed,
                state.has_account_verif_text,
                state.has_cookie_banner,
                state.iframe_src orelse "",
            },
        );

        try self.appendDiagnosticLine(trace_dir, label, timestamp_ms, state);
        if (force_screenshot or changed) {
            try self.captureScreenshot(trace_dir, label);
        }
        try self.writeLiveView(trace_dir, label, timestamp_ms, state);
    }

    fn observeUiState(self: *BrowserBridge) BridgeError!BrowserUiState {
        const expression =
            "JSON.stringify((() => { const token = document.querySelector('input[name=\"octocaptcha-token\"]'); const submit = document.querySelector('button.js-octocaptcha-form-submit'); const load = document.querySelector('button.js-octocaptcha-load-captcha'); const email = document.querySelector('input[name=\"user[email]\"]'); const password = document.querySelector('input[name=\"user[password]\"]'); const login = document.querySelector('input[name=\"user[login]\"]'); const captcha = document.querySelector('iframe[src*=\"octocaptcha\"], iframe[src*=\"arkose\"], iframe[title*=\"captcha\"]'); const text = document.body.innerText || ''; const buttons = Array.from(document.querySelectorAll('button,input[type=\"button\"],input[type=\"submit\"]')).map((el) => (el.textContent || el.value || el.getAttribute('aria-label') || '').trim()).filter(Boolean); return { url: location.href, title: document.title || '', octocaptcha_length: token?.value?.length || 0, email_length: email?.value?.length || 0, password_length: password?.value?.length || 0, login_length: login?.value?.length || 0, submit_hidden: submit ? !!submit.hidden : null, submit_disabled: submit ? !!submit.disabled : null, load_button_hidden: load ? !!load.hidden : null, load_button_disabled: load ? !!load.disabled : null, has_captcha_frame: !!captcha, has_verify_completed: /verify completed|verification completed/i.test(text), has_account_verif_text: /account verification|verify your account|enter code|verification code/i.test(text), has_cookie_banner: /how to manage cookie preferences|manage cookies|privacy statement/i.test(text) || buttons.some((value) => /accept all cookies|accept all|manage cookies|reject/i.test(value)), iframe_src: captcha?.src || null, text_snippet: text.slice(0, 240) }; })())";
        const response = try self.cdp.evaluate(expression);
        defer self.allocator.free(response);

        var parsed = parseBrowserUiStateFromEvaluateResponse(self.allocator, response) catch return error.ParseFailed;
        defer parsed.deinit();
        return .{
            .url = try self.allocator.dupe(u8, parsed.value.url),
            .title = try self.allocator.dupe(u8, parsed.value.title),
            .octocaptcha_length = parsed.value.octocaptcha_length,
            .email_length = parsed.value.email_length,
            .password_length = parsed.value.password_length,
            .login_length = parsed.value.login_length,
            .submit_hidden = parsed.value.submit_hidden,
            .submit_disabled = parsed.value.submit_disabled,
            .load_button_hidden = parsed.value.load_button_hidden,
            .load_button_disabled = parsed.value.load_button_disabled,
            .has_captcha_frame = parsed.value.has_captcha_frame,
            .has_verify_completed = parsed.value.has_verify_completed,
            .has_account_verif_text = parsed.value.has_account_verif_text,
            .has_cookie_banner = parsed.value.has_cookie_banner,
            .iframe_src = if (parsed.value.iframe_src) |src| try self.allocator.dupe(u8, src) else null,
            .text_snippet = try self.allocator.dupe(u8, parsed.value.text_snippet),
        };
    }

    fn fingerprintUiState(self: *BrowserBridge, state: BrowserUiState) u64 {
        _ = self;
        return std.hash.Wyhash.hash(0, state.url) ^
            std.hash.Wyhash.hash(1, state.title) ^
            std.hash.Wyhash.hash(2, state.text_snippet) ^
            @as(u64, state.octocaptcha_length);
    }

    fn freeUiState(self: *BrowserBridge, state: BrowserUiState) void {
        self.allocator.free(state.url);
        self.allocator.free(state.title);
        if (state.iframe_src) |src| self.allocator.free(src);
        self.allocator.free(state.text_snippet);
    }

    fn appendDiagnosticLine(self: *BrowserBridge, trace_dir: []const u8, label: []const u8, timestamp_ms: i64, state: BrowserUiState) BridgeError!void {
        var path_buf: [1024]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/browser-state.ndjson", .{trace_dir}) catch return error.OutOfMemory;
        const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .APPEND = true,
            .CLOEXEC = true,
        }, 0o644) catch return error.WriteFailed;
        defer _ = std.c.close(fd);

        var line_buf = std.array_list.Managed(u8).init(self.allocator);
        defer line_buf.deinit();
        var label_esc: [128]u8 = undefined;
        var url_esc: [2048]u8 = undefined;
        var title_esc: [512]u8 = undefined;
        var iframe_esc: [2048]u8 = undefined;
        var text_esc: [1024]u8 = undefined;
        const label_len = escapeJsonString(label, &label_esc);
        const url_len = escapeJsonString(state.url, &url_esc);
        const title_len = escapeJsonString(state.title, &title_esc);
        const iframe_len = escapeJsonString(state.iframe_src orelse "", &iframe_esc);
        const text_len = escapeJsonString(state.text_snippet, &text_esc);
        const line = try std.fmt.allocPrint(
            self.allocator,
            "{{\"label\":\"{s}\",\"timestamp_ms\":{d},\"url\":\"{s}\",\"title\":\"{s}\",\"octocaptcha_length\":{d},\"email_length\":{d},\"password_length\":{d},\"login_length\":{d},\"submit_hidden\":{any},\"submit_disabled\":{any},\"load_button_hidden\":{any},\"load_button_disabled\":{any},\"has_captcha_frame\":{},\"has_verify_completed\":{},\"has_account_verif_text\":{},\"has_cookie_banner\":{},\"iframe_src\":\"{s}\",\"text_snippet\":\"{s}\"}}\n",
            .{
                label_esc[0..label_len],
                timestamp_ms,
                url_esc[0..url_len],
                title_esc[0..title_len],
                state.octocaptcha_length,
                state.email_length,
                state.password_length,
                state.login_length,
                state.submit_hidden,
                state.submit_disabled,
                state.load_button_hidden,
                state.load_button_disabled,
                state.has_captcha_frame,
                state.has_verify_completed,
                state.has_account_verif_text,
                state.has_cookie_banner,
                iframe_esc[0..iframe_len],
                text_esc[0..text_len],
            },
        );
        defer self.allocator.free(line);
        try line_buf.appendSlice(line);
        try writeAll(fd, line_buf.items.ptr, line_buf.items.len);
    }

    /// Return the next screenshot file name (relative to trace dir) without actually capturing.
    /// Useful for including the screenshot path in audit results before capture.
    fn nextScreenshotName(self: *const BrowserBridge, label: []const u8) [32]u8 {
        var safe_label_buf: [64]u8 = undefined;
        const safe_label = sanitizeTraceLabel(label, &safe_label_buf);
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "shot-{d:0>4}-{s}.png", .{
            self.screenshot_seq,
            safe_label,
        }) catch "shot-unknown.png";
        var result: [32]u8 = [_]u8{0} ** 32;
        @memcpy(result[0..name.len], name);
        return result;
    }

    fn captureScreenshot(self: *BrowserBridge, trace_dir: []const u8, label: []const u8) BridgeError!void {
        const response = try self.cdp.sendCommand("Page.captureScreenshot", "{\"format\":\"png\"}");
        defer self.allocator.free(response);

        const data_marker = "\"data\":\"";
        const data_idx = mem.indexOf(u8, response, data_marker) orelse return error.ParseFailed;
        const data_start = data_idx + data_marker.len;
        const data_end = mem.indexOfScalarPos(u8, response, data_start, '"') orelse return error.ParseFailed;
        const b64 = response[data_start..data_end];

        const decoder = std.base64.standard.Decoder;
        const decoded_len = decoder.calcSizeForSlice(b64) catch return error.ParseFailed;
        const png = try self.allocator.alloc(u8, decoded_len);
        defer self.allocator.free(png);
        _ = decoder.decode(png, b64) catch return error.ParseFailed;

        var safe_label_buf: [64]u8 = undefined;
        const safe_label = sanitizeTraceLabel(label, &safe_label_buf);
        var path_buf: [1024]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/shot-{d:0>4}-{s}.png", .{
            trace_dir,
            self.screenshot_seq,
            safe_label,
        }) catch return error.OutOfMemory;
        self.screenshot_seq += 1;
        if (self.latest_screenshot_name) |existing| self.allocator.free(existing);
        self.latest_screenshot_name = self.allocator.dupe(u8, path[path.len - (safe_label.len + 14)..]) catch null;

        const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
        }, 0o644) catch return error.WriteFailed;
        defer _ = std.c.close(fd);
        try writeAll(fd, png.ptr, png.len);
    }

    fn writeLiveView(self: *BrowserBridge, trace_dir: []const u8, label: []const u8, timestamp_ms: i64, state: BrowserUiState) BridgeError!void {
        var path_buf: [1024]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/live-view.html", .{trace_dir}) catch return error.OutOfMemory;
        const screenshot_name = self.latest_screenshot_name orelse "";
        var text_esc: [1024]u8 = undefined;
        const text_len = escapeJsonString(state.text_snippet, &text_esc);
        const screenshot_html = if (screenshot_name.len > 0)
            try std.fmt.allocPrint(self.allocator, "<h2>Latest Screenshot</h2><img src=\"{s}\" alt=\"latest screenshot\">", .{screenshot_name})
        else
            try self.allocator.dupe(u8, "");
        defer self.allocator.free(screenshot_html);
        const html = try std.fmt.allocPrint(
            self.allocator,
            "<!doctype html><html><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"1\"><title>Ghost Browser Live View</title><style>body{{font-family:monospace;background:#111;color:#eee;margin:24px}}img{{max-width:100%;border:1px solid #333}}pre{{white-space:pre-wrap}}a{{color:#9cf}}</style></head><body><h1>Ghost Browser Live View</h1><p>label={s} timestamp_ms={d}</p><p><a href=\"browser.mp4\">video</a> | <a href=\"browser-state.ndjson\">state log</a> | <a href=\"browser-actions.ndjson\">action log</a></p><pre>url={s}\ntitle={s}\noctocaptcha_length={d}\nemail_length={d}\npassword_length={d}\nlogin_length={d}\nload_hidden={any}\nload_disabled={any}\nsubmit_hidden={any}\nsubmit_disabled={any}\ncaptcha_frame={}\nverify_completed={}\naccount_verif={}\ncookie_banner={}\niframe={s}\n\n{s}</pre>{s}</body></html>",
            .{
                label,
                timestamp_ms,
                state.url,
                state.title,
                state.octocaptcha_length,
                state.email_length,
                state.password_length,
                state.login_length,
                state.load_button_hidden,
                state.load_button_disabled,
                state.submit_hidden,
                state.submit_disabled,
                state.has_captcha_frame,
                state.has_verify_completed,
                state.has_account_verif_text,
                state.has_cookie_banner,
                state.iframe_src orelse "",
                text_esc[0..text_len],
                screenshot_html,
            },
        );
        defer self.allocator.free(html);

        const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .TRUNC = true,
            .CLOEXEC = true,
        }, 0o644) catch return error.WriteFailed;
        defer _ = std.c.close(fd);
        try writeAll(fd, html.ptr, html.len);
    }

    fn logBridgeAction(self: *BrowserBridge, kind: []const u8, response: []const u8) BridgeError!void {
        const trace_dir = self.diagnostics_dir orelse return;

        var path_buf: [1024]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/browser-actions.ndjson", .{trace_dir}) catch return error.OutOfMemory;
        const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{
            .ACCMODE = .WRONLY,
            .CREAT = true,
            .APPEND = true,
            .CLOEXEC = true,
        }, 0o644) catch return error.WriteFailed;
        defer _ = std.c.close(fd);

        var kind_esc: [128]u8 = undefined;
        const kind_len = escapeJsonString(kind, &kind_esc);
        const line = if (extractRuntimeEvaluateStringValue(self.allocator, response)) |value| blk: {
            defer self.allocator.free(value);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"kind\":\"{s}\",\"timestamp_ms\":{d},\"payload\":{s}}}\n",
                .{
                    kind_esc[0..kind_len],
                    currentUnixMs(),
                    value,
                },
            );
        } else |_| blk: {
            var raw_esc: [4096]u8 = undefined;
            const raw_len = escapeJsonString(response, &raw_esc);
            break :blk try std.fmt.allocPrint(
                self.allocator,
                "{{\"kind\":\"{s}\",\"timestamp_ms\":{d},\"raw_response\":\"{s}\"}}\n",
                .{
                    kind_esc[0..kind_len],
                    currentUnixMs(),
                    raw_esc[0..raw_len],
                },
            );
        };
        defer self.allocator.free(line);
        try writeAll(fd, line.ptr, line.len);
    }

    /// Parse CDP Runtime.evaluate response value
    /// CDP response format: {"id":N,"result":{"result":{"type":"string","value":"..."}}}
    fn parseCdpValue(self: *BrowserBridge, response: []const u8, field: []const u8) !void {
        const value = try extractRuntimeEvaluateStringValue(self.allocator, response);
        defer self.allocator.free(value);

        // "null" means the global is not set yet
        if (mem.eql(u8, value, "null")) return;

        if (mem.eql(u8, field, "token")) {
            try self.parseTokenLine(value);
        } else if (mem.eql(u8, field, "identity")) {
            try self.parseIdentityLine(value);
        }
    }

    /// Parse token JSON into HarvestedToken struct
    fn parseTokenLine(self: *BrowserBridge, json_str: []const u8) BridgeError!void {
        var parsed = std.json.parseFromSlice(
            struct {
                token: []const u8,
                url: []const u8,
                method: []const u8,
                timestamp: u64,
            },
            self.allocator,
            json_str,
            .{},
        ) catch |err| {
            std.debug.print("[BRIDGE] Failed to parse token JSON: {}\n", .{err});
            return BridgeError.ParseFailed;
        };
        defer parsed.deinit();

        const data = parsed.value;

        const token_copy = @min(data.token.len, self.result.token.token.len);
        @memcpy(self.result.token.token[0..token_copy], data.token[0..token_copy]);
        self.result.token.token_len = token_copy;

        const url_copy = @min(data.url.len, self.result.token.url.len);
        @memcpy(self.result.token.url[0..url_copy], data.url[0..url_copy]);
        self.result.token.url_len = url_copy;

        const method_copy = @min(data.method.len, self.result.token.method.len);
        @memcpy(self.result.token.method[0..method_copy], data.method[0..method_copy]);
        self.result.token.method_len = method_copy;

        self.result.token.timestamp = data.timestamp;
        self.result.token_captured = true;

        std.debug.print("[BRIDGE] Captured token: {d} bytes from {s}\n", .{
            token_copy,
            data.url,
        });
    }

    /// Parse identity JSON into HarvestedIdentity struct
    fn parseIdentityLine(self: *BrowserBridge, json_str: []const u8) BridgeError!void {
        var parsed = std.json.parseFromSlice(
            struct {
                _octo: ?[]const u8,
                logged_in: ?[]const u8,
                timestamp: u64,
            },
            self.allocator,
            json_str,
            .{},
        ) catch |err| {
            std.debug.print("[BRIDGE] Failed to parse identity JSON: {}\n", .{err});
            return BridgeError.ParseFailed;
        };
        defer parsed.deinit();

        const data = parsed.value;

        if (data._octo) |octo| {
            const octo_copy = @min(octo.len, self.result.identity._octo.len);
            @memcpy(self.result.identity._octo[0..octo_copy], octo[0..octo_copy]);
            self.result.identity._octo_len = octo_copy;
        }

        if (data.logged_in) |li| {
            const li_copy = @min(li.len, self.result.identity.logged_in.len);
            @memcpy(self.result.identity.logged_in[0..li_copy], li[0..li_copy]);
            self.result.identity.logged_in_len = li_copy;
        }

        self.result.identity.timestamp = data.timestamp;
        self.result.identity_captured = true;

        std.debug.print("[BRIDGE] Captured identity: _octo={d}B, logged_in={d}B\n", .{
            self.result.identity._octo_len,
            self.result.identity.logged_in_len,
        });
    }

    /// Check if extraction timeout has expired
    fn hasTimedOut(self: *const BrowserBridge) bool {
        var ts: std.posix.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        const now_ns = @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
        const elapsed_ns = now_ns - self.start_time_ns;
        const elapsed_ms = @divTrunc(elapsed_ns, std.time.ns_per_ms);
        return elapsed_ms >= EXTRACTION_TIMEOUT_MS;
    }

    /// Clean up — close CDP WebSocket
    pub fn deinit(self: *BrowserBridge) void {
        if (self.latest_screenshot_name) |name| {
            self.allocator.free(name);
            self.latest_screenshot_name = null;
        }
        if (self.diagnostics_dir) |dir| {
            self.allocator.free(dir);
            self.diagnostics_dir = null;
        }
        self.cdp.close();
    }

    /// Verify that all required trace artifacts exist after a run.
    /// SOURCE: PRD "Full Real-Time Browser Observability System", ticket 0b0380bf
    pub fn verifyArtifacts(self: *BrowserBridge) void {
        const trace_dir = self.diagnostics_dir orelse {
            std.debug.print("[ARTIFACTS] ⚠️ No diagnostics directory — skipping verification\n", .{});
            return;
        };

        const required_files = [_][]const u8{
            "browser-state.ndjson",
            "browser-actions.ndjson",
            "browser-network.ndjson",
            "live-view.html",
        };

        var all_ok = true;
        var stats_buf: [256]u8 = undefined;

        for (required_files) |fname| {
            var path_buf: [1024]u8 = undefined;
            const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ trace_dir, fname }) catch continue;

            const stat = std.posix.stat(path, &stats_buf);
            if (stat != 0) {
                std.debug.print("[ARTIFACTS] ❌ Missing: {s}\n", .{fname});
                all_ok = false;
            } else {
                const size = std.mem.nativeToLittle(u64, @bitCast(stats_buf[48..56].*));
                std.debug.print("[ARTIFACTS] ✅ {s}: {d} bytes\n", .{ fname, size });
            }
        }

        // Check for screenshots
        var screenshot_count: usize = 0;
        const dir = std.posix.openat(std.posix.AT.FDCWD, trace_dir, .{ .ACCMODE = .RDONLY }, 0) catch {
            std.debug.print("[ARTIFACTS] ❌ Cannot open trace directory\n", .{});
            return;
        };
        defer _ = std.c.close(dir);

        var linux_dirent_buf: [1024]u8 = undefined;
        while (true) {
            const n = std.posix.getdents64(dir, &linux_dirent_buf) catch break;
            if (n == 0) break;
            var offset: usize = 0;
            while (offset < n) {
                const dirent_ptr = linux_dirent_buf[offset..];
                if (dirent_ptr.len < 19) break; // minimum d_reclen
                const d_reclen = std.mem.nativeToLittle(u16, @bitCast(dirent_ptr[16..18].*));
                if (d_reclen < 19) break;
                const name_start = 19;
                if (name_start >= d_reclen) break;
                const name_end = mem.indexOfScalarPos(u8, dirent_ptr, name_start, 0) orelse break;
                const entry_name = dirent_ptr[name_start..name_end];
                if (mem.startsWith(u8, entry_name, "shot-") and mem.endsWith(u8, entry_name, ".png")) {
                    screenshot_count += 1;
                }
                offset += d_reclen;
            }
        }

        if (screenshot_count == 0) {
            std.debug.print("[ARTIFACTS] ⚠️ No screenshots captured\n", .{});
        } else {
            std.debug.print("[ARTIFACTS] ✅ screenshots: {d} files\n", .{screenshot_count});
        }

        if (all_ok and screenshot_count > 0) {
            std.debug.print("[ARTIFACTS] ✅ All required artifacts present\n", .{});
        } else if (!all_ok) {
            std.debug.print("[ARTIFACTS] ❌ Some artifacts missing — check trace directory: {s}\n", .{trace_dir});
        }
    }
};

// ---------------------------------------------------------------------------
// File I/O helper
// ---------------------------------------------------------------------------

/// Read harvest.js source file from disk
fn readHarvestJs(buf: []u8) ![]u8 {
    // Read harvest.js using low-level syscalls
    // SOURCE: man 2 openat — open file relative to cwd
    // SOURCE: man 2 read — read from file descriptor
    const fd = std.posix.openat(std.posix.AT.FDCWD, "src/harvest.js", .{ .ACCMODE = .RDONLY }, 0) catch
        return error.ReadFailed;
    defer _ = std.c.close(fd);

    var total: usize = 0;
    while (total < buf.len) {
        const n = std.posix.read(fd, buf[total..]) catch return error.ReadFailed;
        if (n == 0) break;
        total += n;
    }
    return buf[0..total];
}

fn extractRuntimeEvaluateStringValue(allocator: std.mem.Allocator, response: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(RuntimeEvaluateStringEnvelope, allocator, response, .{
        .ignore_unknown_fields = true,
    }) catch return error.ParseFailed;
    defer parsed.deinit();

    const inner = parsed.value.result.result;
    if (!mem.eql(u8, inner.type, "string")) return error.ParseFailed;
    return allocator.dupe(u8, inner.value);
}

fn extractTopLevelMessageId(allocator: std.mem.Allocator, response: []const u8) ?u32 {
    var parsed = std.json.parseFromSlice(TopLevelMessageIdEnvelope, allocator, response, .{
        .ignore_unknown_fields = true,
    }) catch return null;
    defer parsed.deinit();
    return parsed.value.id;
}

fn parseBrowserUiStateFromEvaluateResponse(
    allocator: std.mem.Allocator,
    response: []const u8,
) !std.json.Parsed(BrowserUiState) {
    const value = try extractRuntimeEvaluateStringValue(allocator, response);
    defer allocator.free(value);
    return std.json.parseFromSlice(BrowserUiState, allocator, value, .{
        .allocate = .alloc_always,
    }) catch error.ParseFailed;
}

/// Unescape basic JSON string escapes (\\, \", \n, \r, \t)
fn unescapeJsonString(input: []const u8, output: []u8) []u8 {
    var out_idx: usize = 0;
    var i: usize = 0;
    while (i < input.len and out_idx < output.len - 1) {
        if (input[i] == '\\' and i + 1 < input.len) {
            const next = input[i + 1];
            if (next == '\\') {
                output[out_idx] = '\\';
                out_idx += 1;
                i += 2;
            } else if (next == '"') {
                output[out_idx] = '"';
                out_idx += 1;
                i += 2;
            } else if (next == 'n') {
                output[out_idx] = '\n';
                out_idx += 1;
                i += 2;
            } else if (next == 'r') {
                output[out_idx] = '\r';
                out_idx += 1;
                i += 2;
            } else if (next == 't') {
                output[out_idx] = '\t';
                out_idx += 1;
                i += 2;
            } else {
                output[out_idx] = input[i];
                out_idx += 1;
                i += 1;
            }
        } else {
            output[out_idx] = input[i];
            out_idx += 1;
            i += 1;
        }
    }
    return output[0..out_idx];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseTokenLine: extracts token from valid JSON" {
    const allocator = std.testing.allocator;
    // Can't init BrowserBridge without Chrome running, so test parseTokenLine directly
    var bridge = BrowserBridge{
        .allocator = allocator,
        .cdp = undefined,
        .result = .{},
        .start_time_ns = 0,
    };

    const json = "{\"token\":\"test_token_value_123\",\"url\":\"https://example.com\",\"method\":\"POST\",\"timestamp\":1234567890}";
    try bridge.parseTokenLine(json);

    try std.testing.expect(bridge.result.token_captured);
    try std.testing.expectEqualStrings("test_token_value_123", bridge.result.token.token[0..bridge.result.token.token_len]);
    try std.testing.expectEqualStrings("https://example.com", bridge.result.token.url[0..bridge.result.token.url_len]);
    try std.testing.expectEqualStrings("POST", bridge.result.token.method[0..bridge.result.token.method_len]);
}

test "parseIdentityLine: extracts cookies from valid JSON" {
    const allocator = std.testing.allocator;
    var bridge = BrowserBridge{
        .allocator = allocator,
        .cdp = undefined,
        .result = .{},
        .start_time_ns = 0,
    };

    const json = "{\"_octo\":\"octo_value\",\"logged_in\":\"yes\",\"timestamp\":1234567890}";
    try bridge.parseIdentityLine(json);

    try std.testing.expect(bridge.result.identity_captured);
    try std.testing.expectEqualStrings("octo_value", bridge.result.identity._octo[0..bridge.result.identity._octo_len]);
    try std.testing.expectEqualStrings("yes", bridge.result.identity.logged_in[0..bridge.result.identity.logged_in_len]);
}

test "escapeJsonString: escapes special characters" {
    var output: [256]u8 = undefined;
    const input = "hello \"world\" and \\path\\ and\nnewline";
    const len = escapeJsonString(input, &output);
    const result = output[0..len];
    try std.testing.expect(mem.indexOf(u8, result, "\\\"") != null);
    try std.testing.expect(mem.indexOf(u8, result, "\\\\") != null);
    try std.testing.expect(mem.indexOf(u8, result, "\\n") != null);
}

test "unescapeJsonString: unescapes JSON strings" {
    var output: [256]u8 = undefined;
    const input = "hello \\\"world\\\" and \\\\path\\\\ and\\nnewline";
    const result = unescapeJsonString(input, &output);
    try std.testing.expect(mem.indexOf(u8, result, "\"") != null);
    try std.testing.expect(mem.indexOf(u8, result, "\\") != null);
    try std.testing.expect(mem.indexOf(u8, result, "\n") != null);
}

test "extractRuntimeEvaluateStringValue: preserves escaped JSON payload from CDP Runtime.evaluate" {
    const allocator = std.testing.allocator;
    const response =
        "{\"id\":7,\"result\":{\"result\":{\"type\":\"string\",\"value\":\"{\\\"url\\\":\\\"https://github.com/signup\\\",\\\"title\\\":\\\"Sign up for GitHub · GitHub\\\",\\\"octocaptcha_length\\\":0,\\\"email_length\\\":12,\\\"password_length\\\":20,\\\"login_length\\\":8,\\\"submit_hidden\\\":true,\\\"submit_disabled\\\":true,\\\"load_button_hidden\\\":false,\\\"load_button_disabled\\\":false,\\\"has_captcha_frame\\\":false,\\\"has_verify_completed\\\":false,\\\"has_account_verif_text\\\":true,\\\"has_cookie_banner\\\":false,\\\"iframe_src\\\":null,\\\"text_snippet\\\":\\\"Verify your account\\\"}\"}}}";

    const value = try extractRuntimeEvaluateStringValue(allocator, response);
    defer allocator.free(value);

    try std.testing.expectEqualStrings(
        "{\"url\":\"https://github.com/signup\",\"title\":\"Sign up for GitHub · GitHub\",\"octocaptcha_length\":0,\"email_length\":12,\"password_length\":20,\"login_length\":8,\"submit_hidden\":true,\"submit_disabled\":true,\"load_button_hidden\":false,\"load_button_disabled\":false,\"has_captcha_frame\":false,\"has_verify_completed\":false,\"has_account_verif_text\":true,\"has_cookie_banner\":false,\"iframe_src\":null,\"text_snippet\":\"Verify your account\"}",
        value,
    );
}

test "parseBrowserUiStateFromEvaluateResponse: decodes escaped BrowserUiState payload" {
    const allocator = std.testing.allocator;
    const response =
        "{\"id\":7,\"result\":{\"result\":{\"type\":\"string\",\"value\":\"{\\\"url\\\":\\\"https://github.com/signup\\\",\\\"title\\\":\\\"Sign up for GitHub · GitHub\\\",\\\"octocaptcha_length\\\":0,\\\"email_length\\\":12,\\\"password_length\\\":20,\\\"login_length\\\":8,\\\"submit_hidden\\\":true,\\\"submit_disabled\\\":true,\\\"load_button_hidden\\\":false,\\\"load_button_disabled\\\":false,\\\"has_captcha_frame\\\":true,\\\"has_verify_completed\\\":false,\\\"has_account_verif_text\\\":true,\\\"has_cookie_banner\\\":true,\\\"iframe_src\\\":\\\"https://octocaptcha.com/frame\\\",\\\"text_snippet\\\":\\\"Verify your account\\\"}\"}}}";

    var state = try parseBrowserUiStateFromEvaluateResponse(allocator, response);
    defer state.deinit();

    try std.testing.expectEqualStrings("https://github.com/signup", state.value.url);
    try std.testing.expectEqualStrings("Sign up for GitHub · GitHub", state.value.title);
    try std.testing.expectEqual(@as(usize, 0), state.value.octocaptcha_length);
    try std.testing.expectEqual(@as(usize, 12), state.value.email_length);
    try std.testing.expectEqual(@as(usize, 20), state.value.password_length);
    try std.testing.expectEqual(@as(usize, 8), state.value.login_length);
    try std.testing.expectEqual(true, state.value.has_captcha_frame);
    try std.testing.expectEqual(true, state.value.has_cookie_banner);
    try std.testing.expectEqualStrings("https://octocaptcha.com/frame", state.value.iframe_src.?);
}

test "parseIpv4Addr: parses 127.0.0.1" {
    const addr = try parseIpv4Addr("127.0.0.1");
    // Should be 0x7F000001 in big-endian (network byte order)
    try std.testing.expectEqual(@as(u32, 0x7F000001), addr);
}

test "sendWsText: 16-bit payload length is encoded in network byte order" {
    var fds: [2]i32 = undefined;
    // SOURCE: man 2 socketpair — creates a connected pair of sockets for local IPC.
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
    if (rc == std.math.maxInt(usize)) return error.SocketFailed;
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    var payload: [126]u8 = undefined;
    @memset(&payload, 'A');

    var client = CdpClient{
        .fd = fds[0],
        .allocator = std.testing.allocator,
        .msg_id = 0,
    };
    try client.sendWsText(&payload);

    var frame: [2 + 2 + 4 + payload.len]u8 = undefined;
    _ = try recvExact(fds[1], &frame);

    try std.testing.expectEqual(@as(u8, WS_FIN_BIT | WS_OPCODE_TEXT), frame[0]);
    try std.testing.expectEqual(@as(u8, WS_MASK_BIT | 126), frame[1]);
    try std.testing.expectEqual(@as(u8, 0x00), frame[2]);
    try std.testing.expectEqual(@as(u8, 0x7E), frame[3]);
}

test "recvWsTextAlloc: supports server text frames larger than MAX_CDP_BUF" {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
    if (rc == std.math.maxInt(usize)) return error.SocketFailed;
    defer _ = linux.close(fds[0]);
    defer _ = linux.close(fds[1]);

    const allocator = std.testing.allocator;
    const payload_len = MAX_CDP_BUF + 1024;
    const payload = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload);
    @memset(payload, 'Z');

    var header: [10]u8 = undefined;
    header[0] = WS_FIN_BIT | WS_OPCODE_TEXT;
    header[1] = 127;
    const len_be = std.mem.nativeToBig(u64, @as(u64, payload_len));
    header[2..10].* = @bitCast(len_be);
    try writeAll(fds[1], &header, header.len);
    try writeAll(fds[1], payload.ptr, payload.len);

    var client = CdpClient{
        .fd = fds[0],
        .allocator = allocator,
        .msg_id = 0,
    };

    const received = try client.recvWsTextAlloc();
    defer allocator.free(received);

    try std.testing.expectEqual(payload_len, received.len);
    try std.testing.expectEqual(@as(u8, 'Z'), received[0]);
    try std.testing.expectEqual(@as(u8, 'Z'), received[received.len - 1]);
}

test "sendCommand: ignores event messages with nested id before matching top-level response id" {
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
    };

    const event_message =
        "{\"method\":\"Runtime.executionContextCreated\",\"params\":{\"context\":{\"id\":1,\"origin\":\"https://github.com\"}}}";
    const reply_message =
        "{\"id\":1,\"result\":{\"result\":{\"type\":\"string\",\"value\":\"ok\"}}}";

    var event_header: [2]u8 = .{ WS_FIN_BIT | WS_OPCODE_TEXT, @intCast(event_message.len) };
    var reply_header: [2]u8 = .{ WS_FIN_BIT | WS_OPCODE_TEXT, @intCast(reply_message.len) };
    try writeAll(fds[1], &event_header, event_header.len);
    try writeAll(fds[1], event_message.ptr, event_message.len);
    try writeAll(fds[1], &reply_header, reply_header.len);
    try writeAll(fds[1], reply_message.ptr, reply_message.len);

    const response = try client.sendCommand("Runtime.evaluate", "{\"expression\":\"1\"}");
    defer allocator.free(response);

    try std.testing.expectEqualStrings(reply_message, response);
}

test "parseFetchRequestPaused: extracts ordered headers and postData" {
    const allocator = std.testing.allocator;
    const message =
        \\{"method":"Fetch.requestPaused","params":{"requestId":"req-1","request":{"url":"https://github.com/signup?social=false","method":"POST","headers":{"user-agent":"UA","sec-fetch-mode":"navigate","cookie":"_gh_sess=abc"},"postData":"authenticity_token=abc&octocaptcha-token=xyz"}}}
    ;

    var paused = try parseFetchRequestPaused(allocator, message);
    defer paused.deinit(allocator);

    try std.testing.expectEqualStrings("req-1", paused.request_id);
    try std.testing.expectEqualStrings("https://github.com/signup?social=false", paused.bundle.url);
    try std.testing.expectEqualStrings("POST", paused.bundle.method);
    try std.testing.expectEqualStrings("authenticity_token=abc&octocaptcha-token=xyz", paused.bundle.post_data);
    try std.testing.expectEqual(@as(usize, 3), paused.bundle.headers.len);
    try std.testing.expectEqualStrings("user-agent", paused.bundle.headers[0].name);
    try std.testing.expectEqualStrings("sec-fetch-mode", paused.bundle.headers[1].name);
    try std.testing.expectEqualStrings("cookie", paused.bundle.headers[2].name);
}
