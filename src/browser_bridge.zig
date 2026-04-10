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

/// Poll timeout for CDP WebSocket checking (100ms)
/// SOURCE: man 2 poll — timeout in milliseconds
pub const POLL_TIMEOUT_MS: i32 = 100;

/// Maximum buffer size for CDP responses
pub const MAX_CDP_BUF: usize = 65536;

/// Maximum buffer size for harvest.js source file
pub const MAX_HARVEST_SIZE: usize = 65536;

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
        var recv_buf: [MAX_CDP_BUF]u8 = undefined;
        while (true) {
            const response = try self.recvWsText(&recv_buf);
            // Check if this response matches our message id
            const id_marker = "\"id\":";
            const id_idx = mem.indexOf(u8, response, id_marker) orelse continue;
            const id_start = id_idx + id_marker.len;
            const id_end = mem.indexOfAnyPos(u8, response, id_start, ",}") orelse continue;
            const id_str = response[id_start..id_end];
            const resp_id = std.fmt.parseInt(u32, id_str, 10) catch continue;
            if (resp_id == self.msg_id) {
                return self.allocator.dupe(u8, response);
            }
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
        ) catch return error.OutOfMemory;

        const response = try self.sendCommand("Runtime.evaluate", params);
        return response;
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
            const len_be = std.mem.nativeToBig(u16, @as(u16, @intCast(payload.len)));
            header_buf[2] = @intCast(len_be >> 8);
            header_buf[3] = @intCast(len_be & 0xFF);
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
    fn recvWsText(self: *CdpClient, buf: []u8) ![]u8 {
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

        // Read payload
        if (payload_len > buf.len) return error.WsFrameError;
        const payload = buf[0..payload_len];
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
        const body_preview = @min(body.len, 500);
        std.debug.print("[CDP] Body preview: {s}\n", .{body[0..body_preview]});

        // Parse JSON array of tab objects
        // Look for "webSocketDebuggerUrl" and "url" fields
        // Minimal JSON parsing: find the tab with matching URL prefix
        const ws_key = "\"webSocketDebuggerUrl\":\"";
        const url_key = "\"url\":\"";

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
        const n = std.posix.read(fd, buf[total..]) catch return error.ReadFailed;
        if (n == 0) return error.ReadFailed;
        total += n;
    }
    return buf;
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

// ---------------------------------------------------------------------------
// Harvested Data Structures
// ---------------------------------------------------------------------------

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

        return BrowserBridge{
            .allocator = allocator,
            .cdp = cdp,
            .start_time_ns = now_ns,
        };
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

    /// Parse CDP Runtime.evaluate response value
    /// CDP response format: {"id":N,"result":{"result":{"type":"string","value":"..."}}}
    fn parseCdpValue(self: *BrowserBridge, response: []const u8, field: []const u8) !void {
        // Extract the "value" field from CDP response
        const value_marker = "\"value\":\"";
        const val_idx = mem.indexOf(u8, response, value_marker) orelse return;
        const val_start = val_idx + value_marker.len;
        const val_end = mem.indexOfScalarPos(u8, response, val_start, '"') orelse return;
        const value_str = response[val_start..val_end];

        // "null" means the global is not set yet
        if (mem.eql(u8, value_str, "null")) return;

        // Unescape basic JSON escapes in the value
        var unescaped_buf: [MAX_CDP_BUF]u8 = undefined;
        const unescaped = unescapeJsonString(value_str, &unescaped_buf);

        if (mem.eql(u8, field, "token")) {
            try self.parseTokenLine(unescaped);
        } else if (mem.eql(u8, field, "identity")) {
            try self.parseIdentityLine(unescaped);
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
        self.cdp.close();
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

test "parseIpv4Addr: parses 127.0.0.1" {
    const addr = try parseIpv4Addr("127.0.0.1");
    // Should be 0x7F000001 in big-endian (network byte order)
    try std.testing.expectEqual(@as(u32, 0x7F000001), addr);
}
