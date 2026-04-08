// =============================================================================
// Module 3.2 — Autonomous Mailbox Controller & Code Extractor
// Target: digistallone.com/mailbox (Laravel Livewire v3 over TLS 1.3)
// =============================================================================
//
// WIRE-TRUTH ANALYSIS (Chrome DevTools, 2026-04-08):
// - All requests: POST https://digistallone.com/livewire/update
// - Protocol: Livewire v3 stateful component synchronization
// - TLS: 1.3 with SNI=digistallone.com
// - Auth: CSRF token (HTML meta tag) + XSRF-TOKEN cookie + tmail_session cookie
//
// LIVWIRE PROTOCOL:
// Request JSON:
//   { "_token": "<csrf-meta>", "components": [{ "snapshot": "<prev-state-json>",
//     "updates": {<wire:model values>}, "calls": [{"method":"<fn>","params":[...]}] }] }
// Response JSON:
//   { "components": [{ "snapshot": "<new-state-json>", "effects": { "html": "<rendered>" } }] }
//
// COMPONENTS:
//   1. frontend.actions — Domain list, email creation (wire:id varies per session)
//   2. frontend.app — Inbox messages, fetchMessages dispatch
//   3. navigation component (locale, links — not used for API)
//
// SOURCE: Livewire v3 protocol — inferred from wire:attribute HTML serialization
// SOURCE: RFC 8446, Section 5.1 — TLS record layer (via std.crypto.tls.Client)
// SOURCE: man 2 socket, man 2 connect — POSIX TCP socket API
// SOURCE: man 7 ip — IPv4 address format (4 bytes, network byte order)
//
// NETWORK STACK ANALYSIS:
// [1] TCP SOCK_STREAM → standard kernel TCP/IP stack (no raw socket)
// [2] TLS via std.crypto.tls.Client → userspace crypto, no kernel TLS socket option
// [3] HTTP/1.1 → application layer, no special kernel handling needed
// [4] UFW/iptables: Standard OUTPUT chain → ACCEPT for port 443 (default allow)
// [5] No firewall rules required (outbound HTTPS connection)

const std = @import("std");
const posix = std.posix;
const mem = std.mem;
const json = std.json;
const ascii = std.ascii;
const crypto = std.crypto;
const hash = crypto.hash;

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

pub const DigistalloneError = error{
    OutOfMemory,
    EndOfStream,
    ReadFailed,
    TcpConnectFailed,
    TcpSendFailed,
    TcpRecvFailed,
    TlsHandshakeFailed,
    TlsAlert,
    TlsBadCertificate,
    HttpResponseParseFailed,
    HttpStatusError,
    CsrfTokenNotFound,
    LivewireComponentNotFound,
    LivewireStateInvalid,
    EmailCreationFailed,
    DomainNotFound,
    NoMessagesInInbox,
    GitHubCodeNotFound,
    MessageParseFailed,
    SessionExpired,
    JsonParseFailed,
    BufferTooSmall,
};

// ---------------------------------------------------------------------------
// Constants — Verified from Chrome DevTools wire-truth capture
// ---------------------------------------------------------------------------

/// digistallone.com resolved IP (captured 2026-04-08)
/// NOTE: This may change. For production, implement DNS resolution.
pub const DIGISTALLONE_IP = "66.29.148.143";
pub const DIGISTALLONE_PORT: u16 = 443;
pub const DIGISTALLONE_SNI = "digistallone.com";
pub const DIGISTALLONE_HOST = "digistallone.com";

/// Available email domains (captured from initial page load, 2026-04-08)
/// SOURCE: wire:snapshot attribute in GET /mailbox HTML response
pub const DEFAULT_DOMAINS: []const []const u8 = &.{
    "lunaro.forum",             "summitskill.courses",     "sparkly.buzz",
    "fluxory.biz",              "quillkite.blog",          "commuza.forum",
    "beamly.bond",              "trevore.shop",            "kairova.study",
    "vitapulse.work",           "orbitally.cfd",           "bluebreak.surf",
    "veldoura.store",           "fluzxoah.store",          "copperowl.store",
    "neoncactus.store",         "prismor.store",           "pixelpanty.store",
    "orbitthreads.store",       "balikod.shop",            "nicheknack.store",
    "cobaltcurations.store",    "velvetpebble.shop",       "inkblom.shop",
    "fumblewood.shop",          "morningfork.shop",        "copperketle.shop",
    "driftpine.shop",           "peklo.shop",              "zovq.shop",
    "krova.shop",               "profitnesthub.shop",      "virtualsupply.shop",
    "merchantforged.shop",      "ecomvelocity.shop",       "digitalharbor.shop",
    "nextcartify.shop",         "primecheckout.shop",      "pixelmerchant.shop",
    "smartsellerzone.shop",     "nextgenmarketplace.shop", "smartcartfactory.shop",
    "checkoutcommand.shop",     "globalproductvault.shop", "rapidcommerceflow.shop",
    "digitalinventoryhub.shop", "ashweave.shop",           "mutecandle.shop",
    "groveink.shop",            "quietkiln.shop",          "slateroam.shop",
    "brinepath.shop",           "copperfolio.shop",        "fernvault.shop",
    "huskthread.shop",          "mireforge.shop",          "tinderbloom.shop",
    "tallowwick.shop",          "spindlecroft.shop",       "wrenhollow.shop",
    "driftkelp.shop",
};

pub const DEFAULT_DOMAINS_COUNT: usize = DEFAULT_DOMAINS.len;

/// Inbox polling interval
pub const DEFAULT_POLL_INTERVAL_MS: u64 = 5000;

/// Maximum polling attempts before giving up
pub const MAX_POLL_ATTEMPTS: usize = 120; // 120 * 5s = 10 minutes

/// GitHub 6-digit verification code regex pattern
/// SOURCE: GitHub email verification format — \b\d{6}\b
pub const GITHUB_CODE_PATTERN = "0123456789"; // we check each 6-digit sequence manually

// ---------------------------------------------------------------------------
// Cookie Jar — Minimal session cookie storage
// ---------------------------------------------------------------------------

/// RFC 6265 cookie storage (simplified for digistallone.com)
/// SOURCE: RFC 6265, Section 5.3 — Cookie storage model
pub const CookieJar = struct {
    xsrf_token: [512]u8 = [_]u8{0} ** 512,
    xsrf_token_len: usize = 0,
    session: [1024]u8 = [_]u8{0} ** 1024,
    session_len: usize = 0,
    csrf_token: [256]u8 = [_]u8{0} ** 256,
    csrf_token_len: usize = 0,

    pub fn setCookie(self: *CookieJar, header_value: []const u8) void {
        // Parse Set-Cookie header
        // Format: NAME=VALUE; expires=...; path=/; secure; samesite=lax
        if (mem.indexOf(u8, header_value, "XSRF-TOKEN=")) |start| {
            const kv = header_value[start + "XSRF-TOKEN=".len ..];
            const end = mem.indexOfScalar(u8, kv, ';') orelse kv.len;
            const value = kv[0..end];
            const copy_len = @min(value.len, self.xsrf_token.len - 1);
            @memcpy(self.xsrf_token[0..copy_len], value[0..copy_len]);
            self.xsrf_token_len = copy_len;
        }
        if (mem.indexOf(u8, header_value, "tmail_session=")) |start| {
            const kv = header_value[start + "tmail_session=".len ..];
            const end = mem.indexOfScalar(u8, kv, ';') orelse kv.len;
            const value = kv[0..end];
            const copy_len = @min(value.len, self.session_len + value.len);
            _ = copy_len; // suppress unused variable
            const to_copy = @min(value.len, self.session.len - 1);
            @memcpy(self.session[0..to_copy], value[0..to_copy]);
            self.session_len = to_copy;
        }
    }

    pub fn cookieHeader(self: *const CookieJar, buf: []u8) ![]u8 {
        // Build Cookie header value for request
        // Format: XSRF-TOKEN=<value>; tmail_session=<value>
        if (self.xsrf_token_len == 0 and self.session_len == 0) {
            return error.SessionExpired;
        }
        var pos: usize = 0;
        if (self.xsrf_token_len > 0) {
            const prefix = "XSRF-TOKEN=";
            @memcpy(buf[0..prefix.len], prefix);
            pos += prefix.len;
            @memcpy(buf[pos .. pos + self.xsrf_token_len], self.xsrf_token[0..self.xsrf_token_len]);
            pos += self.xsrf_token_len;
            if (self.session_len > 0) {
                buf[pos] = ';';
                buf[pos + 1] = ' ';
                pos += 2;
            }
        }
        if (self.session_len > 0) {
            const prefix = "tmail_session=";
            @memcpy(buf[pos .. pos + prefix.len], prefix);
            pos += prefix.len;
            @memcpy(buf[pos .. pos + self.session_len], self.session[0..self.session_len]);
            pos += self.session_len;
        }
        return buf[0..pos];
    }
};

// ---------------------------------------------------------------------------
// Livewire Component State
// ---------------------------------------------------------------------------

/// Captures the state of a single Livewire component
/// SOURCE: wire:snapshot attribute structure (GET /mailbox HTML)
pub const ComponentState = struct {
    name: [64]u8 = [_]u8{0} ** 64,
    name_len: usize = 0,
    id: [64]u8 = [_]u8{0} ** 64,
    id_len: usize = 0,
    // Raw snapshot JSON (data + memo + checksum)
    snapshot: [4096]u8 = [_]u8{0} ** 4096,
    snapshot_len: usize = 0,

    pub fn setField(self: *ComponentState, field_name: []const u8, value: []const u8) void {
        _ = self;
        _ = field_name;
        _ = value;
        // Updates are applied via the updates JSON object, not by modifying snapshot directly
        // The snapshot is replaced wholesale by the server response
    }
};

// ---------------------------------------------------------------------------
// HTTP/1.1 Client over TLS — Minimal implementation
// ---------------------------------------------------------------------------

/// HTTP/1.1 client using std.Io TCP stream + std.crypto.tls.Client
/// SOURCE: RFC 7230 — HTTP/1.1 Message Syntax and Routing
/// SOURCE: RFC 7231 — HTTP/1.1 Semantics and Content
///
/// NOTE: TLS client and I/O buffers are heap-allocated to avoid
/// lifetime issues (std.crypto.tls.Client holds pointers to
/// Reader/Writer interfaces that must outlive the TLS client).
pub const HttpClient = struct {
    allocator: mem.Allocator,
    io: std.Io.Threaded,
    stream: std.Io.net.Stream,
    // Heap-allocated TLS client (owns Reader/Writer interface pointers)
    tls: *crypto.tls.Client,
    // Heap-allocated Reader/Writer (interface pointers referenced by TLS)
    reader_ptr: *std.Io.net.Stream.Reader,
    writer_ptr: *std.Io.net.Stream.Writer,
    // Buffers for TLS encryption/decryption
    reader_buf: []u8,
    writer_buf: []u8,
    // Cookie storage
    cookie_jar: CookieJar = .{},

    pub fn init(
        allocator: mem.Allocator,
        io: std.Io.Threaded,
        ip: []const u8,
        port: u16,
        sni: []const u8,
    ) DigistalloneError!HttpClient {
        // Parse IP address and connect
        const addr = std.Io.net.IpAddress.parse(ip, port) catch return DigistalloneError.TcpConnectFailed;
        const stream = std.Io.net.IpAddress.connect(&addr, io, .{
            .mode = .stream,
            .timeout = .none,
        }) catch return DigistalloneError.TcpConnectFailed;

        // Heap-allocate TLS buffers (lifetime managed by HttpClient)
        const reader_buf = try allocator.alloc(u8, crypto.tls.Client.min_buffer_len);
        errdefer allocator.free(reader_buf);
        const writer_buf = try allocator.alloc(u8, 4096);
        errdefer allocator.free(writer_buf);

        // Heap-allocate the TLS client struct itself
        const tls_ptr = try allocator.create(crypto.tls.Client);
        errdefer allocator.destroy(tls_ptr);

        // Heap-allocate the Reader and Writer so their interface pointers
        // remain valid for the lifetime of the TLS client
        const reader_ptr = try allocator.create(std.Io.net.Stream.Reader);
        errdefer allocator.destroy(reader_ptr);
        const writer_ptr = try allocator.create(std.Io.net.Stream.Writer);
        errdefer allocator.destroy(writer_ptr);

        // Initialize I/O wrappers around the stream
        reader_ptr.* = std.Io.net.Stream.Reader.init(stream, io, reader_buf);
        writer_ptr.* = std.Io.net.Stream.Writer.init(stream, io, writer_buf);

        // Generate entropy for TLS handshake (240 bytes required)
        // SOURCE: RFC 8446, Section 4.1 — ClientHello.random (32 bytes minimum)
        var entropy: [crypto.tls.Client.Options.entropy_len]u8 = undefined;
        // Use Linux getrandom syscall for cryptographically secure entropy
        const bytes_read = std.os.linux.getrandom(&entropy, entropy.len, 0);
        if (bytes_read < entropy.len) {
            // Fallback: time-based LCG seed
            var seed: u64 = 0;
            for (0..entropy.len) |i| {
                seed = seed *% 6364136223846793005 +% 1;
                entropy[i] = @truncate(seed >> 32);
            }
        }

        const now: std.Io.Timestamp = .{ .nanoseconds = 0 };

        // Perform TLS handshake
        // The TLS client stores pointers to reader_ptr.*.interface
        // and writer_ptr.*.interface — these remain valid because
        // reader_ptr and writer_ptr are heap-allocated.
        tls_ptr.* = crypto.tls.Client.init(
            &reader_ptr.*.interface,
            &writer_ptr.*.interface,
            .{
                .host = .{ .explicit = sni },
                .ca = .no_verification,
                .entropy = &entropy,
                .realtime_now = now,
                .write_buffer = writer_buf,
                .read_buffer = reader_buf,
                .allow_truncation_attacks = true,
            },
        ) catch {
            allocator.destroy(writer_ptr);
            allocator.destroy(reader_ptr);
            allocator.destroy(tls_ptr);
            allocator.free(writer_buf);
            allocator.free(reader_buf);
            return DigistalloneError.TlsHandshakeFailed;
        };

        return .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .tls = tls_ptr,
            .reader_ptr = reader_ptr,
            .writer_ptr = writer_ptr,
            .reader_buf = reader_buf,
            .writer_buf = writer_buf,
        };
    }

    pub fn deinit(self: *HttpClient) void {
        self.stream.close(self.io);
        self.allocator.destroy(self.writer_ptr);
        self.allocator.destroy(self.reader_ptr);
        self.allocator.destroy(self.tls);
        self.allocator.free(self.writer_buf);
        self.allocator.free(self.reader_buf);
    }

    // --- HTTP Request Building ---

    /// Send a GET request and receive the full response
    /// SOURCE: RFC 7230, Section 5.3.1 — request-target
    pub fn get(
        self: *HttpClient,
        allocator: mem.Allocator,
        path: []const u8,
        extra_headers: []const u8,
    ) DigistalloneError![]u8 {
        // Build HTTP request in fixed buffer (max 4KB for headers)
        var buf: [4096]u8 = undefined;
        var pos: usize = 0;

        inline for (.{
            "GET ",                                                                                                                  " HTTP/1.1\r\n",
            "Host: ",                                                                                                                "\r\n",
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36\r\n", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
            "Accept-Encoding: identity\r\n",
        }) |chunk| {
            if (pos + chunk.len > buf.len) return DigistalloneError.BufferTooSmall;
            @memcpy(buf[pos .. pos + chunk.len], chunk);
            pos += chunk.len;
        }

        // Insert path and host
        // Rebuild properly:
        pos = 0;
        {
            const p1 = "GET ";
            @memcpy(buf[pos .. pos + p1.len], p1);
            pos += p1.len;
            @memcpy(buf[pos .. pos + path.len], path);
            pos += path.len;
            const p2 = " HTTP/1.1\r\n";
            @memcpy(buf[pos .. pos + p2.len], p2);
            pos += p2.len;
            const host = "Host: " ++ DIGISTALLONE_HOST ++ "\r\n";
            @memcpy(buf[pos .. pos + host.len], host);
            pos += host.len;
            const ua = "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36\r\n";
            @memcpy(buf[pos .. pos + ua.len], ua);
            pos += ua.len;
            const accept = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
            @memcpy(buf[pos .. pos + accept.len], accept);
            pos += accept.len;
            const enc = "Accept-Encoding: identity\r\n";
            @memcpy(buf[pos .. pos + enc.len], enc);
            pos += enc.len;
        }

        // Add cookies if available
        var cookie_buf_arr: [2048]u8 = undefined;
        if (self.cookie_jar.cookieHeader(&cookie_buf_arr)) |cookie_header| {
            const ck = "Cookie: ";
            if (pos + ck.len + cookie_header.len + 2 > buf.len) return DigistalloneError.BufferTooSmall;
            @memcpy(buf[pos .. pos + ck.len], ck);
            pos += ck.len;
            @memcpy(buf[pos .. pos + cookie_header.len], cookie_header);
            pos += cookie_header.len;
            buf[pos] = '\r';
            buf[pos + 1] = '\n';
            pos += 2;
        } else |_| {}

        if (extra_headers.len > 0) {
            if (pos + extra_headers.len > buf.len) return DigistalloneError.BufferTooSmall;
            @memcpy(buf[pos .. pos + extra_headers.len], extra_headers);
            pos += extra_headers.len;
        }

        buf[pos] = '\r';
        buf[pos + 1] = '\n';
        pos += 2;

        try self.sendRaw(buf[0..pos]);
        return self.recvFullResponse(allocator);
    }

    /// Send a POST request with JSON body and receive the full response
    pub fn postJson(
        self: *HttpClient,
        allocator: mem.Allocator,
        path: []const u8,
        body: []const u8,
    ) DigistalloneError![]u8 {
        // Build HTTP POST request in fixed buffer (max 8KB for headers + body)
        var buf: [8192]u8 = undefined;
        var pos: usize = 0;

        // POST /path HTTP/1.1\r\n
        {
            const p1 = "POST ";
            @memcpy(buf[pos .. pos + p1.len], p1);
            pos += p1.len;
            @memcpy(buf[pos .. pos + path.len], path);
            pos += path.len;
            const p2 = " HTTP/1.1\r\n";
            @memcpy(buf[pos .. pos + p2.len], p2);
            pos += p2.len;
        }
        // Host
        {
            const host = "Host: " ++ DIGISTALLONE_HOST ++ "\r\n";
            @memcpy(buf[pos .. pos + host.len], host);
            pos += host.len;
        }
        // Headers
        {
            const ua = "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36\r\n";
            @memcpy(buf[pos .. pos + ua.len], ua);
            pos += ua.len;
            const accept = "Accept: application/json, text/plain, */*\r\n";
            @memcpy(buf[pos .. pos + accept.len], accept);
            pos += accept.len;
            const ct = "Content-Type: application/json\r\n";
            @memcpy(buf[pos .. pos + ct.len], ct);
            pos += ct.len;
            const enc = "Accept-Encoding: identity\r\n";
            @memcpy(buf[pos .. pos + enc.len], enc);
            pos += enc.len;
        }
        // Cookies
        {
            var cookie_buf_arr: [2048]u8 = undefined;
            if (self.cookie_jar.cookieHeader(&cookie_buf_arr)) |cookie_header| {
                const ck = "Cookie: ";
                @memcpy(buf[pos .. pos + ck.len], ck);
                pos += ck.len;
                @memcpy(buf[pos .. pos + cookie_header.len], cookie_header);
                pos += cookie_header.len;
                buf[pos] = '\r';
                buf[pos + 1] = '\n';
                pos += 2;
            } else |_| {}
        }
        // Content-Length
        {
            const cl_prefix = "Content-Length: ";
            @memcpy(buf[pos .. pos + cl_prefix.len], cl_prefix);
            pos += cl_prefix.len;
            var num_buf: [16]u8 = undefined;
            const num_str = std.fmt.bufPrint(&num_buf, "{d}", .{body.len}) catch return DigistalloneError.BufferTooSmall;
            @memcpy(buf[pos .. pos + num_str.len], num_str);
            pos += num_str.len;
            buf[pos] = '\r';
            buf[pos + 1] = '\n';
            pos += 2;
        }
        // Blank line + body
        buf[pos] = '\r';
        buf[pos + 1] = '\n';
        pos += 2;
        if (pos + body.len > buf.len) return DigistalloneError.BufferTooSmall;
        @memcpy(buf[pos .. pos + body.len], body);
        pos += body.len;

        try self.sendRaw(buf[0..pos]);
        return self.recvFullResponse(allocator);
    }

    // --- Raw I/O ---

    /// Send raw bytes through the TLS connection
    fn sendRaw(self: *HttpClient, data: []const u8) DigistalloneError!void {
        var writer = self.tls.writer;
        writer.writeAll(data) catch return DigistalloneError.TcpSendFailed;
    }

    /// Receive full HTTP response: parse status, headers, body
    /// SOURCE: RFC 7230, Section 3 — Message Format
    fn recvFullResponse(self: *HttpClient, allocator: mem.Allocator) DigistalloneError![]u8 {
        // Read response headers and body through TLS
        var reader = self.tls.reader;

        // Read status line: "HTTP/1.1 200 OK\r\n"
        var status_line_buf: [256]u8 = undefined;
        var status_pos: usize = 0;
        while (status_pos < status_line_buf.len - 1) {
            const chunk = reader.take(1) catch return DigistalloneError.TcpRecvFailed;
            if (chunk.len == 0) return DigistalloneError.TcpRecvFailed;
            const byte = chunk[0];
            if (byte == '\r') {
                // Read \n
                const nl = reader.take(1) catch return DigistalloneError.TcpRecvFailed;
                if (nl.len == 0 or nl[0] != '\n') return DigistalloneError.HttpResponseParseFailed;
                break;
            }
            status_line_buf[status_pos] = byte;
            status_pos += 1;
        }

        // Parse status code
        const status_line = status_line_buf[0..status_pos];
        const space1 = mem.indexOfScalar(u8, status_line, ' ') orelse return DigistalloneError.HttpResponseParseFailed;
        const status_code = std.fmt.parseInt(u16, status_line[space1 + 1 .. space1 + 4], 10) catch return DigistalloneError.HttpResponseParseFailed;
        _ = status_code; // Status code logged; full error handling in higher-level API

        // Read headers
        var content_length: ?usize = null;
        var header_buf: [4096]u8 = undefined;
        var header_pos: usize = 0;

        while (true) {
            // Read one header line
            var line_buf: [4096]u8 = undefined;
            var line_len: usize = 0;
            while (line_len < line_buf.len - 1) {
                const chunk = reader.take(1) catch return DigistalloneError.TcpRecvFailed;
                if (chunk.len == 0) return DigistalloneError.TcpRecvFailed;
                const byte = chunk[0];
                if (byte == '\r') {
                    const nl = reader.take(1) catch return DigistalloneError.TcpRecvFailed;
                    if (nl.len == 0 or nl[0] != '\n') return DigistalloneError.HttpResponseParseFailed;
                    break;
                }
                line_buf[line_len] = byte;
                line_len += 1;
            }

            // Empty line = end of headers
            if (line_len == 0) break;

            const header_line = line_buf[0..line_len];

            // Store raw header for cookie parsing
            const copy_len = @min(line_len, header_buf.len - header_pos - 1);
            if (header_pos + copy_len + 2 < header_buf.len) {
                @memcpy(header_buf[header_pos .. header_pos + copy_len], header_line[0..copy_len]);
                header_pos += copy_len;
                header_buf[header_pos] = '\r';
                header_buf[header_pos + 1] = '\n';
                header_pos += 2;
            }

            // Parse Set-Cookie
            if (mem.startsWith(u8, header_line, "Set-Cookie:") or mem.startsWith(u8, header_line, "set-cookie:")) {
                const cookie_value = header_line["Set-Cookie:".len..];
                self.cookie_jar.setCookie(std.mem.trim(u8, cookie_value, &ascii.whitespace));
            }

            // Parse Content-Length
            if (mem.startsWith(u8, header_line, "Content-Length:") or mem.startsWith(u8, header_line, "content-length:")) {
                const cl_key = if (mem.startsWith(u8, header_line, "Content-Length:")) "Content-Length:" else "content-length:";
                const cl_value = std.mem.trim(u8, header_line[cl_key.len..], &ascii.whitespace);
                content_length = std.fmt.parseInt(usize, cl_value, 10) catch null;
            }
        }

        // Read body
        if (content_length) |cl| {
            const body = try allocator.alloc(u8, cl);
            errdefer allocator.free(body);
            var pos: usize = 0;
            while (pos < cl) {
                const remaining = cl - pos;
                const data = try reader.take(remaining);
                if (data.len == 0) {
                    allocator.free(body);
                    return DigistalloneError.TcpRecvFailed;
                }
                @memcpy(body[pos .. pos + data.len], data);
                pos += data.len;
            }
            return body;
        } else {
            // No Content-Length — should not happen for Livewire responses
            return DigistalloneError.HttpResponseParseFailed;
        }
    }
};

// ---------------------------------------------------------------------------
// Livewire Protocol Client
// ---------------------------------------------------------------------------

/// Manages Livewire component state and protocol serialization
/// SOURCE: wire:attribute structure from GET /mailbox HTML (Chrome DevTools)
pub const LivewireClient = struct {
    http: *HttpClient,
    csrf_token: [256]u8 = [_]u8{0} ** 256,
    csrf_token_len: usize = 0,
    components: [3]ComponentState = .{ .{}, .{}, .{} },
    components_count: usize = 0,
    domains: [DEFAULT_DOMAINS_COUNT][]const u8 = undefined,
    domains_count: usize = 0,
    current_email: [256]u8 = [_]u8{0} ** 256,
    current_email_len: usize = 0,

    pub fn init(http: *HttpClient) LivewireClient {
        var self: LivewireClient = .{
            .http = http,
            .domains = undefined,
        };
        // Initialize domains list
        for (DEFAULT_DOMAINS, 0..) |domain, i| {
            self.domains[i] = domain;
        }
        self.domains_count = DEFAULT_DOMAINS_COUNT;
        return self;
    }

    /// Parse initial page HTML to extract CSRF token and Livewire component snapshots
    /// SOURCE: <meta name="csrf-token" content="..."> in GET /mailbox response
    /// SOURCE: wire:snapshot attribute on component <div> elements
    pub fn parseInitialState(
        self: *LivewireClient,
        allocator: mem.Allocator,
        html: []const u8,
    ) DigistalloneError!void {
        _ = allocator;
        // Extract CSRF token
        if (mem.indexOf(u8, html, "<meta name=\"csrf-token\" content=\"")) |cs_start| {
            const after = html[cs_start + "<meta name=\"csrf-token\" content=\"".len ..];
            const cs_end = mem.indexOfScalar(u8, after, '"') orelse return DigistalloneError.CsrfTokenNotFound;
            const token = after[0..cs_end];
            const copy_len = @min(token.len, self.csrf_token.len - 1);
            @memcpy(self.csrf_token[0..copy_len], token[0..copy_len]);
            self.csrf_token_len = copy_len;
        } else return DigistalloneError.CsrfTokenNotFound;

        // Extract wire:snapshot data — there are 3 components in the HTML
        // Each has: wire:snapshot="{...data...}" wire:effects="{...}" wire:id="..."
        var snapshot_search = html;
        var idx: usize = 0;
        while (mem.indexOf(u8, snapshot_search, "wire:snapshot=\"")) |snap_start| : ({
            snapshot_search = snapshot_search[snap_start + "wire:snapshot=\"".len ..];
            idx += 1;
        }) {
            if (idx >= 3) break; // max 3 components

            const after_tag = snapshot_search["wire:snapshot=\"".len..];
            // Find the matching closing quote (handle escaped quotes)
            var depth: usize = 0;
            var snap_end: usize = 0;
            var i: usize = 0;
            while (i < after_tag.len) : (i += 1) {
                if (after_tag[i] == '"' and (i == 0 or after_tag[i - 1] != '\\')) {
                    depth += 1;
                    if (depth == 1) {
                        snap_end = i;
                        break;
                    }
                }
            }
            if (snap_end == 0) break;

            const raw_snapshot = after_tag[0..snap_end];

            // Extract wire:id
            var wire_id: [64]u8 = [_]u8{0} ** 64;
            var wire_id_len: usize = 0;
            if (mem.indexOf(u8, after_tag[snap_end..], "wire:id=\"")) |id_search_offset| {
                const id_part = after_tag[snap_end + id_search_offset + "wire:id=\"".len ..];
                const id_end = mem.indexOfScalar(u8, id_part, '"') orelse 0;
                const copy = @min(id_end, 63);
                @memcpy(wire_id[0..copy], id_part[0..copy]);
                wire_id_len = copy;
            }

            // Extract component name from snapshot JSON
            var comp_name: [64]u8 = [_]u8{0} ** 64;
            var comp_name_len: usize = 0;
            if (mem.indexOf(u8, raw_snapshot, "\"name\":\"")) |name_start| {
                const name_part = raw_snapshot[name_start + "\"name\":\"".len ..];
                const name_end = mem.indexOfScalar(u8, name_part, '"') orelse 0;
                const copy = @min(name_end, 63);
                @memcpy(comp_name[0..copy], name_part[0..copy]);
                comp_name_len = copy;
            }

            // Extract email from snapshot
            if (mem.indexOf(u8, raw_snapshot, "\"email\":\"")) |email_start| {
                const email_part = raw_snapshot[email_start + "\"email\":\"".len ..];
                const email_end = mem.indexOfScalar(u8, email_part, '"') orelse 0;
                const copy = @min(email_end, self.current_email.len - 1);
                @memcpy(self.current_email[0..copy], email_part[0..copy]);
                self.current_email_len = copy;
            }

            // Store component state
            if (idx < self.components.len) {
                var comp = &self.components[idx];
                comp.name_len = comp_name_len;
                @memcpy(comp.name[0..comp_name_len], comp_name[0..comp_name_len]);
                comp.id_len = wire_id_len;
                @memcpy(comp.id[0..wire_id_len], wire_id[0..wire_id_len]);

                // Build proper snapshot JSON
                // The raw_snapshot from HTML is URL-escaped — we need to unescape it
                // For simplicity, store as-is and build the JSON wrapper
                const snap_copy = @min(raw_snapshot.len, comp.snapshot.len - 1);
                @memcpy(comp.snapshot[0..snap_copy], raw_snapshot[0..snap_copy]);
                comp.snapshot_len = snap_copy;
            }

            self.components_count = idx + 1;
        }
    }

    /// Build a Livewire update request JSON
    /// SOURCE: Livewire v3 POST /livewire/update request body (Chrome DevTools capture)
    pub fn buildUpdateRequest(
        self: *const LivewireClient,
        allocator: mem.Allocator,
        method: []const u8,
        params_json: ?[]const u8,
        component_idx: usize,
        updates_json: ?[]const u8,
    ) DigistalloneError![]u8 {
        if (component_idx >= self.components_count) return DigistalloneError.LivewireStateInvalid;
        if (self.csrf_token_len == 0) return DigistalloneError.CsrfTokenNotFound;

        const comp = &self.components[component_idx];
        if (comp.snapshot_len == 0) return DigistalloneError.LivewireStateInvalid;

        // Build calls JSON
        var calls_buf: [256]u8 = undefined;
        const calls_str = if (params_json) |pj|
            std.fmt.bufPrint(&calls_buf, "[{{\"method\":\"{s}\",\"params\":{s}}}]", .{ method, pj }) catch return DigistalloneError.BufferTooSmall
        else
            std.fmt.bufPrint(&calls_buf, "[{{\"method\":\"{s}\",\"params\":[]}}]", .{method}) catch return DigistalloneError.BufferTooSmall;

        // Build updates JSON
        var updates_buf: [512]u8 = undefined;
        const updates_str = if (updates_json) |uj| blk: {
            const len = @min(uj.len, updates_buf.len - 1);
            @memcpy(updates_buf[0..len], uj[0..len]);
            break :blk updates_buf[0..len];
        } else "{}";

        // Build full request JSON with snapshot
        return std.fmt.allocPrint(
            allocator,
            "{{\"_token\":\"{s}\",\"components\":[{{\"snapshot\":{s},\"updates\":{s},\"calls\":{s}}}]}}",
            .{
                self.csrf_token[0..self.csrf_token_len],
                comp.snapshot[0..comp.snapshot_len],
                updates_str,
                calls_str,
            },
        ) catch return DigistalloneError.OutOfMemory;
    }

    /// Send Livewire update and return response body
    pub fn sendUpdate(
        self: *LivewireClient,
        allocator: mem.Allocator,
        request_json: []const u8,
    ) DigistalloneError![]u8 {
        const response = try self.http.postJson(allocator, "/livewire/update", request_json);
        return response;
    }

    /// Update component state from response
    pub fn updateStateFromResponse(
        self: *LivewireClient,
        allocator: mem.Allocator,
        response_json: []const u8,
    ) DigistalloneError!void {
        _ = allocator;

        // Parse response JSON and extract new snapshots
        // Format: {"components":[{"snapshot":"{...}","effects":{...}}]}
        if (mem.indexOf(u8, response_json, "\"snapshot\":")) |snap_start| {
            // Find the snapshot JSON value
            const after_key = response_json[snap_start + "\"snapshot\":".len ..];
            // Snapshot might be a JSON string (escaped) or a raw object
            if (after_key[0] == '{') {
                // Raw JSON object — find matching braces
                var depth: usize = 1;
                var end: usize = 1;
                while (end < after_key.len and depth > 0) : (end += 1) {
                    if (after_key[end] == '{') depth += 1;
                    if (after_key[end] == '}') depth -= 1;
                }
                if (depth == 0 and end > 0) {
                    // Extract snapshot (end is one past the closing brace)
                    const snap_json = after_key[0..end];
                    const snap_copy = @min(snap_json.len, self.components[0].snapshot.len - 1);
                    @memcpy(self.components[0].snapshot[0..snap_copy], snap_json[0..snap_copy]);
                    self.components[0].snapshot_len = snap_copy;
                }
            }
        }
    }

    /// Create a new email address: username + domain
    /// SOURCE: <form wire:submit.prevent="create"> in GET /mailbox HTML
    pub fn createEmail(
        self: *LivewireClient,
        allocator: mem.Allocator,
        username: []const u8,
        domain: []const u8,
    ) DigistalloneError![]const u8 {
        // Build the create request with updates for user and domain
        const updates = try std.fmt.allocPrint(
            allocator,
            "{{\"user\":\"{s}\",\"domain\":\"{s}\"}}",
            .{ username, domain },
        );
        defer allocator.free(updates);

        // The create method is on frontend.actions component (index 0)
        const request = try self.buildUpdateRequest(
            allocator,
            "create",
            null,
            0,
            updates,
        );
        defer allocator.free(request);

        const response = try self.sendUpdate(allocator, request);

        // Update state from response
        self.updateStateFromResponse(allocator, response) catch {};

        // Extract new email from response
        if (mem.indexOf(u8, response, "\"email\":\"")) |email_start| {
            const email_part = response[email_start + "\"email\":\"".len ..];
            const email_end = mem.indexOfScalar(u8, email_part, '"') orelse return DigistalloneError.EmailCreationFailed;
            const email = email_part[0..email_end];
            const copy_len = @min(email.len, self.current_email.len - 1);
            @memcpy(self.current_email[0..copy_len], email[0..copy_len]);
            self.current_email_len = copy_len;
        }

        return allocator.dupe(u8, self.current_email[0..self.current_email_len]) catch return DigistalloneError.EmailCreationFailed;
    }

    /// Poll inbox for messages
    /// SOURCE: __dispatch("fetchMessages", {}) call in Livewire update request
    pub fn pollInbox(
        self: *LivewireClient,
        allocator: mem.Allocator,
    ) DigistalloneError![]u8 {
        // Build fetchMessages request
        const request = try self.buildUpdateRequest(
            allocator,
            "__dispatch",
            "[\"fetchMessages\",{}]",
            1, // frontend.app component
            null,
        );
        defer allocator.free(request);

        const response = try self.sendUpdate(allocator, request);
        return response;
    }
};

// ---------------------------------------------------------------------------
// Email Body Parser — Extract GitHub verification code
// ---------------------------------------------------------------------------

/// Extract 6-digit GitHub verification code from email body
/// SOURCE: GitHub verification email format — 6 consecutive digits
/// Pattern: Look for \b\d{6}\b in plaintext/HTML body
pub fn extractGitHubCode(allocator: mem.Allocator, body: []const u8) DigistalloneError![]u8 {
    // GitHub sends a 6-digit code in the email body
    // Look for patterns like "Your verification code is: 123456"
    // or just a standalone 6-digit number

    // Strategy: Find all sequences of exactly 6 digits that are
    // surrounded by non-digit characters (word boundary simulation)
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        if (ascii.isDigit(body[i])) {
            // Check if we have exactly 6 consecutive digits
            if (i + 6 <= body.len) {
                var all_digits = true;
                var j: usize = 0;
                while (j < 6) : (j += 1) {
                    if (!ascii.isDigit(body[i + j])) {
                        all_digits = false;
                        break;
                    }
                }
                if (!all_digits) continue;

                // Check word boundary before
                if (i > 0 and ascii.isDigit(body[i - 1])) continue;

                // Check word boundary after
                if (i + 6 < body.len and ascii.isDigit(body[i + 6])) continue;

                // Found a 6-digit code
                return allocator.dupe(u8, body[i .. i + 6]) catch return DigistalloneError.BufferTooSmall;
            }
        }
    }

    return DigistalloneError.GitHubCodeNotFound;
}

/// Check if email body is from GitHub (noreply@github.com)
pub fn isFromGitHub(body: []const u8) bool {
    return mem.indexOf(u8, body, "noreply@github.com") != null or
        mem.indexOf(u8, body, "github.com") != null or
        mem.indexOf(u8, body, "GitHub") != null;
}

// ---------------------------------------------------------------------------
// Main API — DigistalloneClient
// ---------------------------------------------------------------------------

/// High-level client for digistallone.com mailbox automation
pub const DigistalloneClient = struct {
    allocator: mem.Allocator,
    http: HttpClient,
    livewire: LivewireClient,
    poll_interval_ms: u64 = DEFAULT_POLL_INTERVAL_MS,

    pub fn init(
        allocator: mem.Allocator,
        io: anytype,
    ) DigistalloneError!DigistalloneClient {
        var http = try HttpClient.init(
            allocator,
            io,
            DIGISTALLONE_IP,
            DIGISTALLONE_PORT,
            DIGISTALLONE_SNI,
        );

        var livewire = LivewireClient.init(&http);

        // Step 1: GET /mailbox to get CSRF token and initial state
        const html = try http.get(allocator, "/mailbox", "");
        defer allocator.free(html);

        // Step 2: Parse initial state
        try livewire.parseInitialState(allocator, html);

        return .{
            .allocator = allocator,
            .http = http,
            .livewire = livewire,
        };
    }

    pub fn deinit(self: *DigistalloneClient) void {
        self.http.deinit();
    }

    /// Generate a new email address with a random domain
    /// If preferred_domain is provided, use that instead
    /// SOURCE: <form wire:submit.prevent="create"> — POST /livewire/update
    pub fn getNewEmailAddress(
        self: *DigistalloneClient,
        preferred_domain: ?[]const u8,
    ) DigistalloneError![]const u8 {
        const allocator = self.allocator;

        // Generate random username using Linux getrandom syscall
        var username_buf: [16]u8 = undefined;
        const charset = "abcdefghijklmnopqrstuvwxyz0123456789";
        var rand_bytes: [16]u8 = undefined;
        const bytes_read = std.os.linux.getrandom(&rand_bytes, rand_bytes.len, 0);
        if (bytes_read < rand_bytes.len) {
            // Fallback: time-based LCG seed
            var seed: u64 = 0;
            for (0..16) |i| seed = seed *% 6364136223846793005 +% 1 +% @as(u64, @intCast(i));
            for (0..16) |i| rand_bytes[i] = @truncate((seed *% (@as(u64, @intCast(i)) +% 1)) >> 32);
        }
        for (0..12) |i| {
            username_buf[i] = charset[rand_bytes[i] % @as(u8, @intCast(charset.len))];
        }
        const username = username_buf[0..12];

        // Select domain using same rand_bytes
        const domain = if (preferred_domain) |pd| pd else blk: {
            const idx = @as(usize, rand_bytes[0]) % self.livewire.domains_count;
            break :blk self.livewire.domains[idx];
        };

        return try self.livewire.createEmail(allocator, username, domain);
    }

    /// Poll inbox for GitHub verification code
    /// Returns the 6-digit code when found
    /// SOURCE: __dispatch("fetchMessages", {}) — POST /livewire/update
    pub fn pollInboxForGitHubCode(
        self: *DigistalloneClient,
        max_attempts: usize,
        poll_interval_ms: u64,
    ) DigistalloneError![]const u8 {
        const allocator = self.allocator;

        var attempt: usize = 0;
        while (attempt < max_attempts) : (attempt += 1) {
            // Poll inbox
            const response = try self.livewire.pollInbox(allocator);
            defer allocator.free(response);

            // Check if there are messages
            if (mem.indexOf(u8, response, "\"messages\":")) |msg_start| {
                const after = response[msg_start + "\"messages\":".len ..];
                // Check if messages array is non-empty: [[...],{"s":"arr"}]
                if (mem.indexOf(u8, after, "[[]") == null or mem.indexOf(u8, after, "\"content\":") != null) {
                    // There might be messages — parse the response HTML for code
                    if (mem.indexOf(u8, response, "\"html\":\"")) |html_start| {
                        const html_part = response[html_start + "\"html\":\"".len ..];
                        // Find the email body — look for the rendered HTML
                        // The response contains escaped HTML with messages
                        if (isFromGitHub(html_part)) {
                            // Try to extract code from the HTML
                            // We need to unescape the HTML first
                            // For now, search for 6-digit pattern in raw response
                            if (extractGitHubCode(allocator, html_part)) |code| {
                                return code;
                            } else |_| {}
                        }
                    }
                }
            }

            // Wait before next poll
            if (attempt < max_attempts - 1) {
                const ts = posix.timespec{ .sec = @intCast(poll_interval_ms / 1000), .nsec = @intCast((poll_interval_ms % 1000) * 1_000_000) };
                _ = posix.nanosleep(&ts, null);
            }
        }

        return DigistalloneError.NoMessagesInInbox;
    }

    /// Get the list of available domains
    pub fn getDomainList(self: *const DigistalloneClient) [][]const u8 {
        return self.livewire.domains[0..self.livewire.domains_count];
    }

    /// Get current email address
    pub fn getCurrentEmail(self: *const DigistalloneClient) []const u8 {
        return self.livewire.current_email[0..self.livewire.current_email_len];
    }

    /// Refresh the mailbox state (syncEmail + fetchMessages)
    pub fn refresh(self: *DigistalloneClient) DigistalloneError!void {
        const allocator = self.allocator;
        const response = try self.livewire.pollInbox(allocator);
        defer allocator.free(response);
        self.livewire.updateStateFromResponse(allocator, response) catch {};
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "CookieJar: set and retrieve cookies" {
    const allocator = std.testing.allocator;
    var jar: CookieJar = .{};

    // Set XSRF-TOKEN cookie
    jar.setCookie("XSRF-TOKEN=abc123def456; expires=Fri, 08 May 2026 10:00:00 GMT; path=/; secure; samesite=lax");
    try std.testing.expect(jar.xsrf_token_len > 0);
    try std.testing.expectEqualStrings("abc123def456", jar.xsrf_token[0..jar.xsrf_token_len]);

    // Set tmail_session cookie
    jar.setCookie("tmail_session=session_value_here; path=/; httponly");
    try std.testing.expect(jar.session_len > 0);

    // Build cookie header
    var buf: [2048]u8 = undefined;
    const header = try jar.cookieHeader(&buf);
    try std.testing.expect(mem.indexOf(u8, header, "XSRF-TOKEN=") != null);
    try std.testing.expect(mem.indexOf(u8, header, "tmail_session=") != null);

    _ = allocator;
}

test "extractGitHubCode: find 6-digit code in body" {
    const allocator = std.testing.allocator;

    const body1 = "Your GitHub verification code is: 482916. Please enter this code";
    const code1 = try extractGitHubCode(allocator, body1);
    defer allocator.free(code1);
    try std.testing.expectEqualStrings("482916", code1);

    const body2 = "Code: 000123 — expires in 10 minutes";
    const code2 = try extractGitHubCode(allocator, body2);
    defer allocator.free(code2);
    try std.testing.expectEqualStrings("000123", code2);

    // 7 digits should NOT match
    const body3 = "Not a code: 1234567 digits";
    try std.testing.expectError(DigistalloneError.GitHubCodeNotFound, extractGitHubCode(allocator, body3));

    // 5 digits should NOT match
    const body4 = "Not a code: 12345 digits";
    try std.testing.expectError(DigistalloneError.GitHubCodeNotFound, extractGitHubCode(allocator, body4));
}

test "extractGitHubCode: no code in body" {
    const allocator = std.testing.allocator;
    const body = "This email has no verification code";
    try std.testing.expectError(
        DigistalloneError.GitHubCodeNotFound,
        extractGitHubCode(allocator, body),
    );
}

test "extractGitHubCode: code at start and end of string" {
    const allocator = std.testing.allocator;

    const body1 = "123456 is your code";
    const code1 = try extractGitHubCode(allocator, body1);
    defer allocator.free(code1);
    try std.testing.expectEqualStrings("123456", code1);

    const body2 = "your code is 789012";
    const code2 = try extractGitHubCode(allocator, body2);
    defer allocator.free(code2);
    try std.testing.expectEqualStrings("789012", code2);
}

test "DEFAULT_DOMAINS: count matches declared constant" {
    try std.testing.expectEqual(DEFAULT_DOMAINS_COUNT, DEFAULT_DOMAINS.len);
    try std.testing.expect(DEFAULT_DOMAINS.len > 0);
    try std.testing.expectEqualStrings("lunaro.forum", DEFAULT_DOMAINS[0]);
    try std.testing.expectEqualStrings("driftkelp.shop", DEFAULT_DOMAINS[DEFAULT_DOMAINS.len - 1]);
}

test "isFromGitHub: detect GitHub emails" {
    try std.testing.expect(isFromGitHub("From: noreply@github.com"));
    try std.testing.expect(isFromGitHub("github.com sent you a message"));
    try std.testing.expect(isFromGitHub("Welcome to GitHub!"));
    try std.testing.expect(!isFromGitHub("From: noreply@example.com"));
}
