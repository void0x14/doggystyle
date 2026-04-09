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
/// NOTE: Runtime client path now prefers hostname resolution via std.Io.net.HostName.connect.
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

// SOURCE: GET /mailbox HTML source — Livewire component snapshots are serialized into
// the wire:snapshot attribute using HTML entities such as &quot; for JSON quotes.
fn decodeHtmlAttributeInto(dst: []u8, src: []const u8) DigistalloneError!usize {
    var src_idx: usize = 0;
    var dst_idx: usize = 0;

    while (src_idx < src.len) {
        if (dst_idx >= dst.len) return DigistalloneError.BufferTooSmall;

        if (src[src_idx] == '&') {
            if (mem.startsWith(u8, src[src_idx..], "&quot;")) {
                dst[dst_idx] = '"';
                src_idx += "&quot;".len;
            } else if (mem.startsWith(u8, src[src_idx..], "&#039;")) {
                dst[dst_idx] = '\'';
                src_idx += "&#039;".len;
            } else if (mem.startsWith(u8, src[src_idx..], "&amp;")) {
                dst[dst_idx] = '&';
                src_idx += "&amp;".len;
            } else if (mem.startsWith(u8, src[src_idx..], "&lt;")) {
                dst[dst_idx] = '<';
                src_idx += "&lt;".len;
            } else if (mem.startsWith(u8, src[src_idx..], "&gt;")) {
                dst[dst_idx] = '>';
                src_idx += "&gt;".len;
            } else {
                dst[dst_idx] = src[src_idx];
                src_idx += 1;
            }
        } else {
            dst[dst_idx] = src[src_idx];
            src_idx += 1;
        }
        dst_idx += 1;
    }

    return dst_idx;
}

// SOURCE: GET /mailbox inline bootstrap script — DOMContentLoaded sets
// `const email = '<current mailbox>'` before dispatching syncEmail/fetchMessages.
fn extractBootstrapEmail(html: []const u8) ?[]const u8 {
    const prefix = "const email = '";
    const start = mem.indexOf(u8, html, prefix) orelse return null;
    const after = html[start + prefix.len ..];
    const end = mem.indexOfScalar(u8, after, '\'') orelse return null;
    return after[0..end];
}

/// Get current monotonic timestamp in nanoseconds.
/// SOURCE: man 2 clock_gettime — CLOCK_MONOTONIC for measuring elapsed time
fn currentTimestampNs() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
}

// ---------------------------------------------------------------------------
// HTTP/1.1 Client over TLS
// ---------------------------------------------------------------------------

/// HTTP/1.1 client using std.Io network streams + std.crypto.tls.Client
/// SOURCE: RFC 7230 — HTTP/1.1 Message Syntax and Routing
/// SOURCE: RFC 7231 — HTTP/1.1 Semantics and Content
/// SOURCE: RFC 8446, Section 5.1 — TLS record layer

pub const HttpClient = struct {
    allocator: mem.Allocator,
    io_impl: *std.Io.Threaded,
    io: std.Io,
    stream: std.Io.net.Stream,
    tls: *crypto.tls.Client,
    reader_ptr: *std.Io.net.Stream.Reader,
    writer_ptr: *std.Io.net.Stream.Writer,
    read_buf: []u8,
    write_buf: []u8,
    cookie_jar: CookieJar = .{},
    /// Last activity timestamp (nanoseconds since epoch).
    /// Used to detect stale connections (server Keep-Alive timeout).
    last_activity_ns: i64 = 0,
    /// Stored connection parameters for reconnection
    target: [256]u8 = [_]u8{0} ** 256,
    target_len: usize = 0,
    port: u16 = 0,
    sni: [256]u8 = [_]u8{0} ** 256,
    sni_len: usize = 0,

    // SOURCE: vendor/zig-std/std/Io/net.zig — std.Io.net.IpAddress.parse/connect
    // SOURCE: vendor/zig-std/std/Io/net/HostName.zig — std.Io.net.HostName.init/connect
    fn connectTcpTarget(io: std.Io, target: []const u8, port: u16) DigistalloneError!std.Io.net.Stream {
        if (std.Io.net.IpAddress.parse(target, port)) |addr| {
            return std.Io.net.IpAddress.connect(&addr, io, .{
                .mode = .stream,
                .protocol = .tcp,
                .timeout = .none,
            }) catch return DigistalloneError.TcpConnectFailed;
        } else |_| {}

        const host = std.Io.net.HostName.init(target) catch return DigistalloneError.TcpConnectFailed;
        return std.Io.net.HostName.connect(host, io, port, .{
            .mode = .stream,
            .protocol = .tcp,
            .timeout = .none,
        }) catch return DigistalloneError.TcpConnectFailed;
    }

    // SOURCE: vendor/zig-std/std/Io/Threaded.zig — Threaded.init/io provide the default POSIX networking backend
    // SOURCE: vendor/zig-std/std/Io/net/HostName.zig — HostName.connect resolves DNS before opening TCP stream
    // SOURCE: vendor/zig-std/std/Io/net.zig — Stream.Reader.init / Stream.Writer.init satisfy std.crypto.tls.Client I/O contracts
    // SOURCE: vendor/zig-std/std/crypto/tls/Client.zig — Client.init expects stable Reader/Writer interfaces for TLS records
    pub fn init(
        allocator: mem.Allocator,
        target: []const u8,
        port: u16,
        sni: []const u8,
    ) DigistalloneError!HttpClient {
        const io_impl = try allocator.create(std.Io.Threaded);
        errdefer allocator.destroy(io_impl);
        io_impl.* = std.Io.Threaded.init(std.heap.smp_allocator, .{});
        errdefer io_impl.deinit();
        const io = io_impl.io();

        const stream = try connectTcpTarget(io, target, port);
        errdefer stream.close(io);

        // Heap-allocate TLS buffers
        const read_buf = try allocator.alloc(u8, crypto.tls.Client.min_buffer_len);
        errdefer allocator.free(read_buf);
        const write_buf = try allocator.alloc(u8, crypto.tls.Client.min_buffer_len);
        errdefer allocator.free(write_buf);

        // Heap-allocate the TLS client struct
        const tls_ptr = try allocator.create(crypto.tls.Client);
        errdefer allocator.destroy(tls_ptr);

        const reader_ptr = try allocator.create(std.Io.net.Stream.Reader);
        errdefer allocator.destroy(reader_ptr);
        const writer_ptr = try allocator.create(std.Io.net.Stream.Writer);
        errdefer allocator.destroy(writer_ptr);
        reader_ptr.* = std.Io.net.Stream.Reader.init(stream, io, read_buf);
        writer_ptr.* = std.Io.net.Stream.Writer.init(stream, io, write_buf);

        // Generate entropy for TLS handshake
        var entropy: [crypto.tls.Client.Options.entropy_len]u8 = undefined;
        const gr_rc = std.os.linux.getrandom(&entropy, entropy.len, 0);
        if (gr_rc < entropy.len) {
            var seed: u64 = 0;
            for (0..entropy.len) |i| {
                seed = seed *% 6364136223846793005 +% 1;
                entropy[i] = @truncate(seed >> 32);
            }
        }

        const now: std.Io.Timestamp = .{ .nanoseconds = 0 };

        tls_ptr.* = crypto.tls.Client.init(
            &reader_ptr.interface,
            &writer_ptr.interface,
            .{
                .host = .{ .explicit = sni },
                .ca = .no_verification,
                .entropy = &entropy,
                .realtime_now = now,
                .write_buffer = write_buf,
                .read_buffer = read_buf,
                .allow_truncation_attacks = true,
            },
        ) catch {
            allocator.destroy(writer_ptr);
            allocator.destroy(reader_ptr);
            allocator.destroy(tls_ptr);
            allocator.free(write_buf);
            allocator.free(read_buf);
            stream.close(io);
            io_impl.deinit();
            allocator.destroy(io_impl);
            return DigistalloneError.TlsHandshakeFailed;
        };

        // Store connection parameters for reconnection
        var stored_target: [256]u8 = [_]u8{0} ** 256;
        const target_copy = @min(target.len, stored_target.len);
        @memcpy(stored_target[0..target_copy], target[0..target_copy]);
        var stored_sni: [256]u8 = [_]u8{0} ** 256;
        const sni_copy = @min(sni.len, stored_sni.len);
        @memcpy(stored_sni[0..sni_copy], sni[0..sni_copy]);
        const now_ns = currentTimestampNs();

        return .{
            .allocator = allocator,
            .io_impl = io_impl,
            .io = io,
            .stream = stream,
            .tls = tls_ptr,
            .reader_ptr = reader_ptr,
            .writer_ptr = writer_ptr,
            .read_buf = read_buf,
            .write_buf = write_buf,
            .cookie_jar = .{},
            .last_activity_ns = now_ns,
            .target = stored_target,
            .target_len = target_copy,
            .port = port,
            .sni = stored_sni,
            .sni_len = sni_copy,
        };
    }

    pub fn deinit(self: *HttpClient) void {
        self.stream.close(self.io);
        self.allocator.destroy(self.writer_ptr);
        self.allocator.destroy(self.reader_ptr);
        self.allocator.destroy(self.tls);
        self.allocator.free(self.write_buf);
        self.allocator.free(self.read_buf);
        self.io_impl.deinit();
        self.allocator.destroy(self.io_impl);
    }

    /// Check if the connection has been idle too long (server likely closed it).
    /// LiteSpeed Keep-Alive timeout is typically 5 seconds.
    /// We use a conservative 3-second threshold.
    /// SOURCE: LiteSpeed documentation — default keepalive_timeout = 5s
    pub fn isStale(self: *const HttpClient, max_idle_ms: u64) bool {
        const now_ns = currentTimestampNs();
        const elapsed_ms: i64 = @divTrunc(now_ns - self.last_activity_ns, std.time.ns_per_ms);
        return elapsed_ms > max_idle_ms;
    }

    /// Record activity — call after every send/recv operation
    pub fn recordActivity(self: *HttpClient) void {
        self.last_activity_ns = currentTimestampNs();
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
            const ua = "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36\r\n";
            @memcpy(buf[pos .. pos + ua.len], ua);
            pos += ua.len;
            const accept = "Accept: application/json, text/plain, */*\r\n";
            @memcpy(buf[pos .. pos + accept.len], accept);
            pos += accept.len;
            const ct = "Content-Type: application/json\r\n";
            @memcpy(buf[pos .. pos + ct.len], ct);
            pos += ct.len;
            // SOURCE: Wire-truth capture 2026-04-09 — browser sends these for Laravel CSRF validation
            const origin_hdr = "Origin: https://" ++ DIGISTALLONE_HOST ++ "\r\n";
            @memcpy(buf[pos .. pos + origin_hdr.len], origin_hdr);
            pos += origin_hdr.len;
            const referer_hdr = "Referer: https://" ++ DIGISTALLONE_HOST ++ "/mailbox\r\n";
            @memcpy(buf[pos .. pos + referer_hdr.len], referer_hdr);
            pos += referer_hdr.len;
            // SOURCE: Wire-truth — browser sends empty x-livewire header (Livewire v3 signature)
            const livewire_hdr = "x-livewire: \r\n";
            @memcpy(buf[pos .. pos + livewire_hdr.len], livewire_hdr);
            pos += livewire_hdr.len;
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
        const writer = &self.tls.writer;
        writer.writeAll(data) catch return DigistalloneError.TcpSendFailed;
        writer.flush() catch return DigistalloneError.TcpSendFailed;
        self.writer_ptr.interface.flush() catch return DigistalloneError.TcpSendFailed;
        self.recordActivity();
    }

    /// Receive full HTTP response: parse status, headers, body
    /// SOURCE: RFC 7230, Section 3 — Message Format
    fn recvFullResponse(self: *HttpClient, allocator: mem.Allocator) DigistalloneError![]u8 {
        defer self.recordActivity();
        const reader = &self.tls.reader;

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
            if (ascii.startsWithIgnoreCase(header_line, "set-cookie:")) {
                const cookie_value = header_line["set-cookie:".len..];
                self.cookie_jar.setCookie(std.mem.trim(u8, cookie_value, &ascii.whitespace));
            }

            // Parse Content-Length
            if (ascii.startsWithIgnoreCase(header_line, "content-length:")) {
                const cl_value = std.mem.trim(u8, header_line["content-length:".len..], &ascii.whitespace);
                content_length = std.fmt.parseInt(usize, cl_value, 10) catch null;
            }
        }

        // Read body
        if (content_length) |cl| {
            const body = try allocator.alloc(u8, cl);
            errdefer allocator.free(body);
            var pos: usize = 0;
            while (pos < cl) {
                const available = reader.peekGreedy(1) catch return DigistalloneError.TcpRecvFailed;
                const chunk_len = @min(available.len, cl - pos);
                @memcpy(body[pos .. pos + chunk_len], available[0..chunk_len]);
                reader.toss(chunk_len);
                pos += chunk_len;
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
    csrf_token: [256]u8 = [_]u8{0} ** 256,
    csrf_token_len: usize = 0,
    components: [3]ComponentState = .{ .{}, .{}, .{} },
    components_count: usize = 0,
    domains: [DEFAULT_DOMAINS_COUNT][]const u8 = undefined,
    domains_count: usize = 0,
    current_email: [256]u8 = [_]u8{0} ** 256,
    current_email_len: usize = 0,

    pub fn init() LivewireClient {
        var self: LivewireClient = .{
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
        // Extract CSRF token
        if (mem.indexOf(u8, html, "<meta name=\"csrf-token\" content=\"")) |cs_start| {
            const after = html[cs_start + "<meta name=\"csrf-token\" content=\"".len ..];
            const cs_end = mem.indexOfScalar(u8, after, '"') orelse return DigistalloneError.CsrfTokenNotFound;
            const token = after[0..cs_end];
            const copy_len = @min(token.len, self.csrf_token.len - 1);
            @memcpy(self.csrf_token[0..copy_len], token[0..copy_len]);
            self.csrf_token_len = copy_len;
        } else return DigistalloneError.CsrfTokenNotFound;

        if (extractBootstrapEmail(html)) |bootstrap_email| {
            const copy_len = @min(bootstrap_email.len, self.current_email.len - 1);
            @memcpy(self.current_email[0..copy_len], bootstrap_email[0..copy_len]);
            self.current_email_len = copy_len;
        }

        // Extract wire:snapshot data — there are currently three components in GET /mailbox
        // and the attribute contents are HTML-entity encoded JSON strings.
        var search_start: usize = 0;
        while (self.components_count < self.components.len) {
            const snapshot_attr = "wire:snapshot=\"";
            const snap_rel = mem.indexOf(u8, html[search_start..], snapshot_attr) orelse break;
            const snap_start = search_start + snap_rel + snapshot_attr.len;
            const after_snapshot = html[snap_start..];
            const snap_end = mem.indexOfScalar(u8, after_snapshot, '"') orelse break;
            const raw_snapshot = after_snapshot[0..snap_end];

            const after_snapshot_attr = after_snapshot[snap_end..];
            const id_attr = "wire:id=\"";
            const id_rel = mem.indexOf(u8, after_snapshot_attr, id_attr) orelse break;
            const id_start = snap_start + snap_end + id_rel + id_attr.len;
            const id_after = html[id_start..];
            const id_end = mem.indexOfScalar(u8, id_after, '"') orelse break;
            const wire_id = id_after[0..id_end];

            var comp = &self.components[self.components_count];
            comp.id_len = @min(wire_id.len, comp.id.len);
            @memcpy(comp.id[0..comp.id_len], wire_id[0..comp.id_len]);

            comp.snapshot_len = try decodeHtmlAttributeInto(comp.snapshot[0 .. comp.snapshot.len - 1], raw_snapshot);
            const decoded_snapshot = comp.snapshot[0..comp.snapshot_len];

            var parsed_snapshot = std.json.parseFromSlice(std.json.Value, allocator, decoded_snapshot, .{}) catch {
                return DigistalloneError.JsonParseFailed;
            };
            defer parsed_snapshot.deinit();

            if (parsed_snapshot.value.object.get("memo")) |memo_value| {
                if (memo_value.object.get("name")) |name_value| {
                    const name = name_value.string;
                    comp.name_len = @min(name.len, comp.name.len);
                    @memcpy(comp.name[0..comp.name_len], name[0..comp.name_len]);
                }
            }

            if (self.current_email_len == 0) {
                if (parsed_snapshot.value.object.get("data")) |data_value| {
                    if (data_value.object.get("email")) |email_value| {
                        if (email_value != .null) {
                            const email = email_value.string;
                            const copy_len = @min(email.len, self.current_email.len - 1);
                            @memcpy(self.current_email[0..copy_len], email[0..copy_len]);
                            self.current_email_len = copy_len;
                        }
                    }
                }
            }

            self.components_count += 1;
            search_start = snap_start + snap_end;
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

        const params_str = params_json orelse "[]";

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
            "{{\"_token\":{f},\"components\":[{{\"snapshot\":{f},\"updates\":{s},\"calls\":[{{\"path\":\"\",\"method\":{f},\"params\":{s}}}]}}]}}",
            .{
                std.json.fmt(self.csrf_token[0..self.csrf_token_len], .{}),
                std.json.fmt(comp.snapshot[0..comp.snapshot_len], .{}),
                updates_str,
                std.json.fmt(method, .{}),
                params_str,
            },
        ) catch return DigistalloneError.OutOfMemory;
    }

    /// Send Livewire update and return response body
    pub fn sendUpdate(
        self: *LivewireClient,
        http: *HttpClient,
        allocator: mem.Allocator,
        request_json: []const u8,
    ) DigistalloneError![]u8 {
        _ = self;
        const response = try http.postJson(allocator, "/livewire/update", request_json);
        return response;
    }

    /// Update component states from response
    /// SOURCE: Wire-truth capture 2026-04-09 — response contains multiple components
    /// each with its own snapshot. Must update ALL components, not just [0].
    pub fn updateStateFromResponse(
        self: *LivewireClient,
        allocator: mem.Allocator,
        response_json: []const u8,
    ) DigistalloneError!void {
        _ = allocator;

        // Response format: {"components":[{"snapshot":"{...}","effects":{...}}, ...]}
        // Multiple components may be updated in a single response.
        // We walk through all snapshot occurrences and match them by component name.
        var search_start: usize = 0;
        while (mem.indexOf(u8, response_json[search_start..], "\"snapshot\":")) |snap_rel| {
            const snap_start = search_start + snap_rel + "\"snapshot\":".len;
            const after_key = response_json[snap_start..];

            // Snapshot is a JSON string (starts with '"') or object (starts with '{')
            if (after_key.len < 2) break;

            if (after_key[0] == '"') {
                // JSON-encoded string — find the closing unescaped quote
                var end: usize = 1;
                while (end < after_key.len) : (end += 1) {
                    if (after_key[end] == '"' and after_key[end - 1] != '\\') break;
                }
                if (end >= after_key.len) break;
                const snap_escaped = after_key[1..end]; // strip surrounding quotes

                // Extract component name from snapshot to find matching local component
                // The snapshot contains "memo":{"name":"frontend.app",...}
                var comp_name_buf: [64]u8 = undefined;
                var comp_name_len: usize = 0;
                if (mem.indexOf(u8, snap_escaped, "\"name\":\"")) |name_pos| {
                    const after_name_key = snap_escaped[name_pos + "\"name\":\"".len ..];
                    if (mem.indexOfScalar(u8, after_name_key, '"')) |name_end| {
                        const extracted = after_name_key[0..name_end];
                        comp_name_len = @min(extracted.len, comp_name_buf.len);
                        @memcpy(comp_name_buf[0..comp_name_len], extracted[0..comp_name_len]);
                    }
                }

                // Find matching component by name
                if (comp_name_len > 0) {
                    var ci: usize = 0;
                    while (ci < self.components_count) : (ci += 1) {
                        if (self.components[ci].name_len == comp_name_len and
                            mem.eql(u8, self.components[ci].name[0..comp_name_len], comp_name_buf[0..comp_name_len]))
                        {
                            const snap_copy = @min(snap_escaped.len, self.components[ci].snapshot.len - 1);
                            @memcpy(self.components[ci].snapshot[0..snap_copy], snap_escaped[0..snap_copy]);
                            self.components[ci].snapshot_len = snap_copy;
                            break;
                        }
                    }
                }

                search_start = snap_start + end + 1;
            } else if (after_key[0] == '{') {
                // Raw JSON object — find matching braces
                var depth: usize = 1;
                var end: usize = 1;
                while (end < after_key.len and depth > 0) : (end += 1) {
                    if (after_key[end] == '{') depth += 1;
                    if (after_key[end] == '}') depth -= 1;
                }
                if (depth == 0 and end > 0) {
                    const snap_json = after_key[0..end];
                    // Try to extract component name
                    var comp_name_buf: [64]u8 = undefined;
                    var comp_name_len: usize = 0;
                    if (mem.indexOf(u8, snap_json, "\"name\":\"")) |name_pos| {
                        const after_name_key = snap_json[name_pos + "\"name\":\"".len ..];
                        if (mem.indexOfScalar(u8, after_name_key, '"')) |name_end| {
                            const extracted = after_name_key[0..name_end];
                            comp_name_len = @min(extracted.len, comp_name_buf.len);
                            @memcpy(comp_name_buf[0..comp_name_len], extracted[0..comp_name_len]);
                        }
                    }

                    if (comp_name_len > 0) {
                        var ci: usize = 0;
                        while (ci < self.components_count) : (ci += 1) {
                            if (self.components[ci].name_len == comp_name_len and
                                mem.eql(u8, self.components[ci].name[0..comp_name_len], comp_name_buf[0..comp_name_len]))
                            {
                                const snap_copy = @min(snap_json.len, self.components[ci].snapshot.len - 1);
                                @memcpy(self.components[ci].snapshot[0..snap_copy], snap_json[0..snap_copy]);
                                self.components[ci].snapshot_len = snap_copy;
                                break;
                            }
                        }
                    }

                    search_start = snap_start + end;
                } else break;
            } else break;
        }
    }

    /// Create a new email address: username + domain
    /// SOURCE: <form wire:submit.prevent="create"> in GET /mailbox HTML
    pub fn createEmail(
        self: *LivewireClient,
        http: *HttpClient,
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

        const response = try self.sendUpdate(http, allocator, request);
        defer allocator.free(response);

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

    /// Find component index by name
    /// SOURCE: Wire-truth capture 2026-04-09 — 3 components in order:
    ///   [0] frontend.actions, [1] frontend.nav, [2] frontend.app
    fn findComponentByName(self: *const LivewireClient, name: []const u8) ?usize {
        var i: usize = 0;
        while (i < self.components_count) : (i += 1) {
            if (mem.eql(u8, self.components[i].name[0..self.components[i].name_len], name)) {
                return i;
            }
        }
        return null;
    }

    /// Poll inbox for messages
    /// SOURCE: __dispatch("fetchMessages", {}) call in Livewire update request
    /// SOURCE: Wire-truth capture 2026-04-09 — fetchMessages is on frontend.app (index 2)
    /// Component order: [0] frontend.actions, [1] frontend.nav, [2] frontend.app
    pub fn pollInbox(
        self: *LivewireClient,
        http: *HttpClient,
        allocator: mem.Allocator,
    ) DigistalloneError![]u8 {
        // Use frontend.app component (index 2, NOT 1 which is frontend.nav)
        const comp_idx = self.findComponentByName("frontend.app") orelse 2;

        // Build fetchMessages request
        const request = try self.buildUpdateRequest(
            allocator,
            "__dispatch",
            "[\"fetchMessages\",{}]",
            comp_idx,
            null,
        );
        defer allocator.free(request);

        const response = try self.sendUpdate(http, allocator, request);
        return response;
    }
};

// ---------------------------------------------------------------------------
// Email Body Parser — Extract GitHub verification code
// ---------------------------------------------------------------------------

/// Extract GitHub verification code from email body (6-10 consecutive digits)
/// SOURCE: GitHub verification email format — codes are 6-10 digit sequences
/// Pattern: First sequence of 6-10 consecutive digits bounded by non-digit chars
/// WIRE-TRUTH: Real email contained <span class="...">90818627</span> — 8 digits
pub fn extractGitHubCode(allocator: mem.Allocator, body: []const u8) DigistalloneError![]u8 {
    // GitHub sends variable-length numeric codes (observed: 6-10 digits)
    // Strategy: Find all maximal sequences of consecutive digits, accept 6-10 length

    var i: usize = 0;
    while (i < body.len) {
        // Skip non-digits
        if (!ascii.isDigit(body[i])) {
            i += 1;
            continue;
        }

        // Found a digit — measure the full consecutive digit run
        const run_start = i;
        while (i < body.len and ascii.isDigit(body[i])) : (i += 1) {}
        const run_len = i - run_start;

        // Accept if the run is between 6 and 10 digits inclusive
        if (run_len >= 6 and run_len <= 10) {
            return allocator.dupe(u8, body[run_start .. run_start + run_len]) catch
                return DigistalloneError.BufferTooSmall;
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

/// Unescape a JSON-encoded string into raw bytes.
/// Handles: \n, \r, \t, \", \\, \/, \uXXXX (for ASCII range)
/// SOURCE: RFC 8259, Section 7 — JSON string escaping rules
fn unescapeJsonString(dst: []u8, src: []const u8) DigistalloneError!usize {
    var si: usize = 0;
    var di: usize = 0;
    while (si < src.len) {
        if (di >= dst.len) return DigistalloneError.BufferTooSmall;
        if (src[si] == '\\' and si + 1 < src.len) {
            switch (src[si + 1]) {
                'n' => { dst[di] = '\n'; si += 2; },
                'r' => { dst[di] = '\r'; si += 2; },
                't' => { dst[di] = '\t'; si += 2; },
                '"' => { dst[di] = '"'; si += 2; },
                '\\' => { dst[di] = '\\'; si += 2; },
                '/' => { dst[di] = '/'; si += 2; },
                'u' => {
                    // \uXXXX — only handle ASCII range (U+0000..U+007F)
                    if (si + 5 > src.len) return DigistalloneError.BufferTooSmall;
                    const hex = src[si + 2 .. si + 6];
                    const codepoint = std.fmt.parseInt(u16, hex, 16) catch return DigistalloneError.JsonParseFailed;
                    if (codepoint < 0x80) {
                        dst[di] = @as(u8, @intCast(codepoint));
                    } else {
                        dst[di] = @as(u8, @intCast(codepoint & 0xFF));
                    }
                    si += 6;
                },
                else => { dst[di] = src[si]; si += 1; },
            }
        } else {
            dst[di] = src[si];
            si += 1;
        }
        di += 1;
    }
    return di;
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
    ) DigistalloneError!DigistalloneClient {
        var http = try HttpClient.init(
            allocator,
            DIGISTALLONE_HOST,
            DIGISTALLONE_PORT,
            DIGISTALLONE_SNI,
        );
        errdefer http.deinit();

        var livewire = LivewireClient.init();

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

    /// Refresh the HTTP connection if it has been idle too long.
    /// This prevents TcpRecvFailed from stale Keep-Alive connections.
    /// Also re-fetches /mailbox to get fresh CSRF tokens if needed.
    ///
    /// ROOT CAUSE FIX (2026-04-09):
    /// LiteSpeed Keep-Alive timeout is ~5 seconds. If the DigistalloneClient
    /// sits idle for longer (e.g., during GitHub signup which takes ~11s),
    /// the server silently closes the TCP connection. Next send/recv fails
    /// with TcpRecvFailed.
    ///
    /// SOURCE: LiteSpeed docs — default keepalive_timeout = 5s
    /// SOURCE: man 2 clock_gettime — CLOCK_MONOTONIC for idle detection
    pub fn ensureConnected(self: *DigistalloneClient) DigistalloneError!void {
        // LiteSpeed default Keep-Alive timeout: ~5 seconds
        // We use 3 seconds as a conservative threshold
        const KEEPALIVE_THRESHOLD_MS: u64 = 3000;

        if (self.http.isStale(KEEPALIVE_THRESHOLD_MS)) {
            std.debug.print("[DIGISTALLONE] Connection stale (>{d}ms idle), reconnecting...\n", .{KEEPALIVE_THRESHOLD_MS});

            // Close old connection completely
            self.http.deinit();

            // Re-create from scratch
            var new_http = try HttpClient.init(
                self.allocator,
                DIGISTALLONE_HOST,
                DIGISTALLONE_PORT,
                DIGISTALLONE_SNI,
            );

            // Re-fetch /mailbox to get fresh CSRF tokens
            const html = try new_http.get(self.allocator, "/mailbox", "");
            defer self.allocator.free(html);

            // Re-parse Livewire state with fresh tokens
            try self.livewire.parseInitialState(self.allocator, html);

            // Replace old http with new one
            self.http = new_http;

            std.debug.print("[DIGISTALLONE] Reconnected and refreshed CSRF tokens.\n", .{});
        }
    }

    /// Generate a new email address with a random domain
    /// If preferred_domain is provided, use that instead
    /// SOURCE: <form wire:submit.prevent="create"> — POST /livewire/update
    pub fn getNewEmailAddress(
        self: *DigistalloneClient,
        preferred_domain: ?[]const u8,
    ) DigistalloneError![]const u8 {
        const allocator = self.allocator;

        if (self.livewire.current_email_len > 0) {
            const current_email = self.livewire.current_email[0..self.livewire.current_email_len];
            if (preferred_domain) |domain| {
                if (mem.indexOfScalar(u8, current_email, '@')) |at_pos| {
                    if (mem.eql(u8, current_email[at_pos + 1 ..], domain)) {
                        return allocator.dupe(u8, current_email) catch return DigistalloneError.OutOfMemory;
                    }
                }
            } else {
                return allocator.dupe(u8, current_email) catch return DigistalloneError.OutOfMemory;
            }
        }

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

        return try self.livewire.createEmail(&self.http, allocator, username, domain);
    }

    /// Poll inbox for GitHub verification code
    /// Returns the 6-digit code when found
    /// SOURCE: __dispatch("fetchMessages", {}) — POST /livewire/update
    /// SOURCE: Wire-truth capture 2026-04-09 — response effects.html contains rendered message HTML
    ///
    /// KEEP-ALIVE FIX: Calls ensureConnected() before polling to prevent
    /// TcpRecvFailed from stale connections (LiteSpeed 5s Keep-Alive timeout).
    pub fn pollInboxForGitHubCode(
        self: *DigistalloneClient,
        max_attempts: usize,
        poll_interval_ms: u64,
    ) DigistalloneError![]const u8 {
        const allocator = self.allocator;

        // ROOT CAUSE FIX: Reconnect if the connection has been idle too long
        // (e.g., during GitHub signup which takes ~11s).
        try self.ensureConnected();

        var attempt: usize = 0;
        var last_html_snapshot: ?[]const u8 = null;
        while (attempt < max_attempts) : (attempt += 1) {
            // Poll inbox using frontend.app component
            const response = self.livewire.pollInbox(&self.http, allocator) catch |err| {
                if (err == DigistalloneError.TcpRecvFailed) {
                    // Connection was silently closed by server — full reconnect + retry
                    std.debug.print("[MAIL] TcpRecvFailed on poll, full reconnect...\n", .{});
                    try self.ensureConnected();
                    // Don't count this as a failed attempt — retry immediately
                    continue;
                }
                return err;
            };
            defer allocator.free(response);

            // Update all component snapshots from response (fresh snapshots for next poll)
            self.livewire.updateStateFromResponse(allocator, response) catch {};

            // Extract effects.html from the response
            // Wire-truth response structure:
            // {"components":[{"snapshot":"...","effects":{"html":"<rendered>","dispatches":[]}}]}
            // The "html" field contains JSON-escaped HTML (newlines as \n, quotes as \")
            if (mem.indexOf(u8, response, "\"html\":\"")) |html_start| {
                const after_html_key = response[html_start + "\"html\":\"".len ..];
                // Find the end of the JSON string value
                // Walk through escaped characters until unescaped closing quote
                var end: usize = 0;
                while (end < after_html_key.len) : (end += 1) {
                    if (after_html_key[end] == '"' and
                        (end == 0 or after_html_key[end - 1] != '\\'))
                    {
                        break;
                    }
                }
                if (end > 0 and end < after_html_key.len) {
                    const html_escaped = after_html_key[0..end];

                    // Unescape JSON string into a buffer
                    var html_buf: [65536]u8 = undefined;
                    const html_len = unescapeJsonString(&html_buf, html_escaped) catch html_escaped.len;
                    const html = html_buf[0..html_len];

                    // Save snapshot for failure dump
                    last_html_snapshot = html;

                    // Check if this looks like a GitHub email
                    if (isFromGitHub(html)) {
                        // Extract 6-10 digit verification code
                        if (extractGitHubCode(allocator, html)) |code| {
                            return code;
                        } else |_| {}
                    }

                    // Also try searching the raw escaped string as fallback (digits aren't escaped)
                    if (extractGitHubCode(allocator, html_escaped)) |code| {
                        return code;
                    } else |_| {}
                }
            }

            // Wait before next poll
            if (attempt < max_attempts - 1) {
                _ = self.http.io.sleep(std.Io.Duration.fromMilliseconds(@as(i64, @intCast(poll_interval_ms))), .awake) catch {};
            }
        }

        // NO SILENT FAILURE: Dump the last seen HTML snapshot for debugging
        if (last_html_snapshot) |snap| {
            std.debug.print("[MAIL] FAILED: No GitHub code found after {d} attempts. Last HTML snapshot:\n{s}\n", .{ max_attempts, snap });
        } else {
            std.debug.print("[MAIL] FAILED: No GitHub code found after {d} attempts. No HTML snapshot available (no messages?).\n", .{max_attempts});
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
        const response = try self.livewire.pollInbox(&self.http, allocator);
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

test "extractGitHubCode: find 6-10 digit codes in body" {
    const allocator = std.testing.allocator;

    // 6-digit code (classic format)
    const body1 = "Your GitHub verification code is: 482916. Please enter this code";
    const code1 = try extractGitHubCode(allocator, body1);
    defer allocator.free(code1);
    try std.testing.expectEqualStrings("482916", code1);

    // 8-digit code (WIRE-TRUTH: real email had 90818627)
    const body2 = "Your verification code is: 90818627. Enter it below";
    const code2 = try extractGitHubCode(allocator, body2);
    defer allocator.free(code2);
    try std.testing.expectEqualStrings("90818627", code2);

    // 10-digit code (upper bound)
    const body2b = "Code: 1234567890 — expires in 10 minutes";
    const code2b = try extractGitHubCode(allocator, body2b);
    defer allocator.free(code2b);
    try std.testing.expectEqualStrings("1234567890", code2b);

    // 5 digits should NOT match (too short)
    const body3 = "Not a code: 12345 digits";
    try std.testing.expectError(DigistalloneError.GitHubCodeNotFound, extractGitHubCode(allocator, body3));

    // 11 digits should NOT match (too long)
    const body4 = "Not a code: 12345678901 digits";
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

    // 8-digit code at end of string
    const body3 = "your code is 90818627";
    const code3 = try extractGitHubCode(allocator, body3);
    defer allocator.free(code3);
    try std.testing.expectEqualStrings("90818627", code3);
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

test "parseInitialState: decodes Livewire snapshots and bootstrap email" {
    const allocator = std.testing.allocator;
    const html =
        \\<meta name="csrf-token" content="csrf-123" />
        \\<div wire:snapshot="{&quot;data&quot;:{&quot;email&quot;:null},&quot;memo&quot;:{&quot;id&quot;:&quot;actions-id&quot;,&quot;name&quot;:&quot;frontend.actions&quot;},&quot;checksum&quot;:&quot;sum-actions&quot;}" wire:effects="{}" wire:id="actions-id"></div>
        \\<div wire:snapshot="{&quot;data&quot;:{&quot;email&quot;:null},&quot;memo&quot;:{&quot;id&quot;:&quot;app-id&quot;,&quot;name&quot;:&quot;frontend.app&quot;},&quot;checksum&quot;:&quot;sum-app&quot;}" wire:effects="{}" wire:id="app-id"></div>
        \\<script>
        \\document.addEventListener('DOMContentLoaded', () => {
        \\    const email = 'alpha@lunaro.forum';
        \\    Livewire.dispatch('syncEmail', { email });
        \\});
        \\</script>
    ;

    var livewire = LivewireClient.init();
    try livewire.parseInitialState(allocator, html);

    try std.testing.expectEqualStrings("csrf-123", livewire.csrf_token[0..livewire.csrf_token_len]);
    try std.testing.expectEqual(@as(usize, 2), livewire.components_count);
    try std.testing.expectEqualStrings("frontend.actions", livewire.components[0].name[0..livewire.components[0].name_len]);
    try std.testing.expectEqualStrings("actions-id", livewire.components[0].id[0..livewire.components[0].id_len]);
    try std.testing.expectEqualStrings("frontend.app", livewire.components[1].name[0..livewire.components[1].name_len]);
    try std.testing.expectEqualStrings("app-id", livewire.components[1].id[0..livewire.components[1].id_len]);
    try std.testing.expectEqualStrings("alpha@lunaro.forum", livewire.current_email[0..livewire.current_email_len]);
    try std.testing.expectEqualStrings(
        "{\"data\":{\"email\":null},\"memo\":{\"id\":\"actions-id\",\"name\":\"frontend.actions\"},\"checksum\":\"sum-actions\"}",
        livewire.components[0].snapshot[0..livewire.components[0].snapshot_len],
    );
}

test "buildUpdateRequest: matches Livewire client payload shape" {
    const allocator = std.testing.allocator;
    const html =
        \\<meta name="csrf-token" content="csrf-123" />
        \\<div wire:snapshot="{&quot;data&quot;:{&quot;email&quot;:null},&quot;memo&quot;:{&quot;id&quot;:&quot;actions-id&quot;,&quot;name&quot;:&quot;frontend.actions&quot;},&quot;checksum&quot;:&quot;sum-actions&quot;}" wire:effects="{}" wire:id="actions-id"></div>
    ;

    var livewire = LivewireClient.init();
    try livewire.parseInitialState(allocator, html);

    const request = try livewire.buildUpdateRequest(
        allocator,
        "create",
        null,
        0,
        "{\"user\":\"tester\",\"domain\":\"lunaro.forum\"}",
    );
    defer allocator.free(request);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, request, .{});
    defer parsed.deinit();

    const root = parsed.value.object;
    try std.testing.expectEqualStrings("csrf-123", root.get("_token").?.string);

    const component = root.get("components").?.array.items[0].object;
    try std.testing.expectEqualStrings(
        "{\"data\":{\"email\":null},\"memo\":{\"id\":\"actions-id\",\"name\":\"frontend.actions\"},\"checksum\":\"sum-actions\"}",
        component.get("snapshot").?.string,
    );
    try std.testing.expectEqualStrings("tester", component.get("updates").?.object.get("user").?.string);
    try std.testing.expectEqualStrings("lunaro.forum", component.get("updates").?.object.get("domain").?.string);

    const call = component.get("calls").?.array.items[0].object;
    try std.testing.expectEqualStrings("", call.get("path").?.string);
    try std.testing.expectEqualStrings("create", call.get("method").?.string);
    try std.testing.expectEqual(@as(usize, 0), call.get("params").?.array.items.len);
}
