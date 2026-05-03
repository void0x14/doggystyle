// =============================================================================
// Module — Arkose Audio Bypass Faz 1: Audio Downloader (İstihbarat)
// Target: Arkose Labs Audio CAPTCHA — rtag/audio endpoint
// =============================================================================
//
// WIRE-TRUTH ANALYSIS (LIVE TEST 2026-04-24):
// - Arkose Labs Audio CAPTCHA serves a SINGLE MP3 (~18-21s, 44100Hz mono)
// - Retrieved via rtag/audio?challenge=N endpoint (NOT fc/get_audio)
// - Single MP3 contains 3 speaker segments concatenated
// - Analysis splits the PCM into 3 equal parts for spectral flux comparison
// - BrowserBridge CDP Fetch.requestPaused intercepts the rtag/audio requests
//
// SOURCE: RFC 7231, Section 4.3.1 — HTTP GET semantics
// SOURCE: RFC 3986, Section 3.4 — URL query component
// SOURCE: RFC 9112, Section 6.3 — HTTP response body framing
// SOURCE: RFC 8446, Section 5.1 — TLS record layer (via std.crypto.tls.Client)
// SOURCE: Arkose Labs Audio API — rtag/audio?challenge=N endpoint (live capture 2026-04-24)

const std = @import("std");
const mem = std.mem;
const ascii = std.ascii;
const posix = std.posix;
const crypto = std.crypto;
const browser_bridge = @import("../browser_bridge.zig");
const audio_decrypt = @import("audio_decrypt.zig");

// ---------------------------------------------------------------------------
// Error Types
// ---------------------------------------------------------------------------

pub const AudioDownloaderError = error{
    OutOfMemory,
    ParseFailed,
    DnsFailed,
    TcpConnectFailed,
    TcpSendFailed,
    TcpRecvFailed,
    TlsHandshakeFailed,
    HttpResponseParseFailed,
    HttpStatusError,
    BufferTooSmall,
    DirectoryCreateFailed,
    FileWriteFailed,
    UrlCaptureTimeout,
    CdpEvalFailed,
    Base64DecodeFailed,
    GameTokenNotFound,
    FetchFailed,
    EncryptedJsonAudioPayload,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// SOURCE: Arkose Labs Audio API — single MP3 per challenge, split into 3 parts for analysis
pub const AUDIO_CLIP_COUNT: u8 = 1;

/// Maximum time to wait for each audio URL capture via CDP
pub const CAPTURE_TIMEOUT_MS: u64 = 60000;

/// Maximum HTTP response body size (10 MB)
const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024;

/// Buffer sizes
const HTTP_REQ_BUF_LEN: usize = 4096;
const MAX_HTTP_HEADER_LEN: usize = 4096;
const MAX_STATUS_LINE_LEN: usize = 256;
const MAX_CHUNK_LINE_LEN: usize = 4096;

/// Large base64 audio payloads need longer than the default CDP receive timeout.
const AUDIO_FETCH_EVALUATE_TIMEOUT_MS: u64 = 30000;
const AUDIO_FETCH_QUEUE_KEY = "__ghostAudioFetchQueue";

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

/// Shared return type for download operations (used by audio_bypass.zig too)
pub const FetchResult = struct {
    url: []u8,
    path: []u8,
    data: []u8,
};

comptime {
    std.debug.assert(@sizeOf(FetchResult) > 0);
}

// SOURCE: Arkose Labs Audio API — rtag/audio returns MP3 per challenge
pub const AudioClip = struct {
    index: u8,
    url: []const u8,
    data: []const u8,
    session_token: []const u8,
    pk: []const u8,
};

comptime {
    std.debug.assert(@sizeOf(AudioClip) > 0);
}

// SOURCE: Arkose Labs Audio API — 3 clips per challenge
pub const AudioDownloadResult = struct {
    clips: [3]AudioClip,
    session_token: []const u8,
    pk: []const u8,
    execution_time_ms: u64,
};

comptime {
    std.debug.assert(@sizeOf(AudioDownloadResult) > 0);
}

// ---------------------------------------------------------------------------
// URL parsing
// ---------------------------------------------------------------------------

const UrlParts = struct {
    host: []const u8,
    path: []const u8,
    port: u16,
};

// SOURCE: RFC 3986, Section 3.1 — URI scheme (https)
fn parseUrlParts(url: []const u8) AudioDownloaderError!UrlParts {
    if (!mem.startsWith(u8, url, "https://")) return error.ParseFailed;
    const after_scheme = url["https://".len..];
    const path_start = mem.indexOfScalar(u8, after_scheme, '/') orelse return error.ParseFailed;
    return .{
        .host = after_scheme[0..path_start],
        .path = after_scheme[path_start..],
        .port = 443,
    };
}

// ---------------------------------------------------------------------------
// extractSessionToken — URL'den session_token query parameter'ını çıkar
// SOURCE: RFC 3986, Section 3.4 — Query component
// ---------------------------------------------------------------------------
pub fn extractSessionToken(url: []const u8) AudioDownloaderError![]const u8 {
    const key = "session_token=";
    const start = mem.indexOf(u8, url, key) orelse return error.ParseFailed;
    const value_start = start + key.len;
    if (value_start >= url.len) return error.ParseFailed;
    const end = mem.indexOfScalarPos(u8, url, value_start, '&') orelse url.len;
    if (end <= value_start) return error.ParseFailed;
    return url[value_start..end];
}

// SOURCE: RFC 3986, Section 3.4 — Query component
fn extractQueryParam(url: []const u8, key: []const u8) AudioDownloaderError![]const u8 {
    const start = mem.indexOf(u8, url, key) orelse return error.ParseFailed;
    const value_start = start + key.len;
    if (value_start >= url.len) return error.ParseFailed;
    const end = mem.indexOfScalarPos(u8, url, value_start, '&') orelse url.len;
    if (end <= value_start) return error.ParseFailed;
    return url[value_start..end];
}

// ---------------------------------------------------------------------------
// saveAudioClipToDisk — Audio data'yı tmp/audio_clip_{index}.raw olarak kaydet
// SOURCE: POSIX filesystem API — open/write/close (man 2 open, man 2 write)
// ---------------------------------------------------------------------------
pub fn saveAudioClipToDisk(allocator: std.mem.Allocator, data: []const u8, index: u8) AudioDownloaderError![]u8 {
    // SOURCE: man 2 mkdir — creates directory (EEXIST if exists)
    {
        const mkdir_rc = std.os.linux.mkdirat(std.posix.AT.FDCWD, "tmp", 0o755);
        if (mkdir_rc != 0) {
            const err_val = -@as(i64, @bitCast(mkdir_rc));
            if (err_val != 17) return error.DirectoryCreateFailed; // EEXIST = 17 on Linux
        }
    }

    const path = try std.fmt.allocPrint(allocator, "tmp/audio_clip_{d}.raw", .{index});
    errdefer allocator.free(path);

    // SOURCE: man 2 open — O_WRONLY | O_CREAT | O_TRUNC
    const fd = posix.openat(posix.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    }, 0o644) catch return error.FileWriteFailed;
    defer _ = std.c.close(fd);

    var written: usize = 0;
    while (written < data.len) {
        // SOURCE: man 2 write — returns number of bytes written
        const rc = std.os.linux.write(fd, data.ptr + written, data.len - written);
        if (rc == std.math.maxInt(usize)) return error.FileWriteFailed;
        const n: usize = @intCast(rc);
        if (n == 0) return error.FileWriteFailed;
        written += n;
    }

    std.debug.print("[AUDIO] Saved clip {d}: {d} bytes → {s}\n", .{ index, data.len, path });
    return path;
}

// ---------------------------------------------------------------------------
// HTTP/1.1 response body reader helpers
// SOURCE: RFC 9112, Section 6.3 — Message body length determination
// ---------------------------------------------------------------------------

// SOURCE: RFC 9112, Section 2 — CRLF line delimiters
fn readHttpLine(reader: anytype, buf: []u8) AudioDownloaderError![]const u8 {
    var len: usize = 0;
    while (len < buf.len) {
        const chunk = reader.take(1) catch return error.TcpRecvFailed;
        if (chunk.len == 0) return error.TcpRecvFailed;
        if (chunk[0] == '\r') {
            const nl = reader.take(1) catch return error.TcpRecvFailed;
            if (nl.len == 0 or nl[0] != '\n') return error.HttpResponseParseFailed;
            return buf[0..len];
        }
        buf[len] = chunk[0];
        len += 1;
    }
    return error.HttpResponseParseFailed;
}

// SOURCE: RFC 9112, Section 6.3 — Content-Length body
fn readContentLengthBody(reader: anytype, allocator: std.mem.Allocator, content_length: usize) AudioDownloaderError![]u8 {
    const body = try allocator.alloc(u8, content_length);
    errdefer allocator.free(body);
    var pos: usize = 0;
    while (pos < content_length) {
        const available = reader.peekGreedy(1) catch return error.TcpRecvFailed;
        if (available.len == 0) return error.TcpRecvFailed;
        const to_copy = @min(available.len, content_length - pos);
        @memcpy(body[pos .. pos + to_copy], available[0..to_copy]);
        reader.toss(to_copy);
        pos += to_copy;
    }
    return body;
}

// SOURCE: RFC 9112, Section 7.1.3 — Chunked transfer-coding
fn readChunkedBody(reader: anytype, allocator: std.mem.Allocator) AudioDownloaderError![]u8 {
    var body = std.array_list.Managed(u8).init(allocator);
    errdefer body.deinit();
    var line_buf: [MAX_CHUNK_LINE_LEN]u8 = undefined;
    while (true) {
        const chunk_line = try readHttpLine(reader, &line_buf);
        const chunk_size = try parseChunkSize(chunk_line);
        if (chunk_size == 0) {
            while (true) {
                const trailer = try readHttpLine(reader, &line_buf);
                if (trailer.len == 0) break;
            }
            return body.toOwnedSlice();
        }
        var remaining = chunk_size;
        while (remaining > 0) {
            const available = reader.peekGreedy(1) catch return error.TcpRecvFailed;
            if (available.len == 0) return error.TcpRecvFailed;
            const to_copy = @min(available.len, remaining);
            try body.appendSlice(available[0..to_copy]);
            reader.toss(to_copy);
            remaining -= to_copy;
        }
        try consumeRequiredCrlf(reader);
    }
}

// SOURCE: RFC 9112, Section 6.3 — Connection close delimits body
fn readBodyUntilClose(reader: anytype, allocator: std.mem.Allocator) AudioDownloaderError![]u8 {
    var body = std.array_list.Managed(u8).init(allocator);
    errdefer body.deinit();
    while (true) {
        const available = reader.peekGreedy(1) catch return error.TcpRecvFailed;
        if (available.len == 0) break;
        try body.appendSlice(available);
        reader.toss(available.len);
    }
    return body.toOwnedSlice();
}

fn consumeRequiredCrlf(reader: anytype) AudioDownloaderError!void {
    const cr = reader.take(1) catch return error.TcpRecvFailed;
    if (cr.len == 0 or cr[0] != '\r') return error.HttpResponseParseFailed;
    const nl = reader.take(1) catch return error.TcpRecvFailed;
    if (nl.len == 0 or nl[0] != '\n') return error.HttpResponseParseFailed;
}

fn parseChunkSize(line: []const u8) AudioDownloaderError!usize {
    const ext_start = mem.indexOfScalar(u8, line, ';') orelse line.len;
    const chunk_size_text = mem.trim(u8, line[0..ext_start], &ascii.whitespace);
    if (chunk_size_text.len == 0) return error.HttpResponseParseFailed;
    return std.fmt.parseInt(usize, chunk_size_text, 16) catch return error.HttpResponseParseFailed;
}

fn hasFinalChunkedTransferCoding(value: []const u8) bool {
    var parts = mem.splitScalar(u8, value, ',');
    var last: []const u8 = "";
    while (parts.next()) |part| {
        last = mem.trim(u8, part, &ascii.whitespace);
    }
    return last.len > 0 and ascii.eqlIgnoreCase(last, "chunked");
}

// ---------------------------------------------------------------------------
// downloadAudioClip — Audio URL'inden raw octet-stream indir
// SOURCE: RFC 7231, Section 4.3.1 — GET semantics
// SOURCE: RFC 8446, Section 5.1 — TLS record layer
// SOURCE: RFC 9112, Section 6.3 — Response body framing
// ---------------------------------------------------------------------------
pub fn downloadAudioClip(allocator: std.mem.Allocator, url: []const u8) AudioDownloaderError![]u8 {
    return downloadAudioClipWithReferer(allocator, url, null);
}

    // SOURCE: RFC 7231, Section 5.5.2 — Referer header for request context
    // SOURCE: ChromeDevTools MCP live capture 2026-04-25 — /rtag/audio requires Referer header
    // game-core iframe URL serves as the Referer for the audio request
pub fn downloadAudioClipWithReferer(allocator: std.mem.Allocator, url: []const u8, referer: ?[]const u8) AudioDownloaderError![]u8 {
    const parts = try parseUrlParts(url);

    // SOURCE: vendor/zig-std/std/Io/Threaded.zig — default POSIX networking backend
    var io_impl = std.Io.Threaded.init(std.heap.smp_allocator, .{});
    defer io_impl.deinit();
    const io = io_impl.io();

    // SOURCE: vendor/zig-std/std/Io/net/HostName.zig — DNS + TCP connect
    const host = std.Io.net.HostName.init(parts.host) catch return error.DnsFailed;
    const stream = std.Io.net.HostName.connect(host, io, parts.port, .{
        .mode = .stream,
        .protocol = .tcp,
        .timeout = .none,
    }) catch return error.TcpConnectFailed;
    defer stream.close(io);

    // Allocate TLS read/write buffers
    const read_buf = try allocator.alloc(u8, crypto.tls.Client.min_buffer_len);
    errdefer allocator.free(read_buf);
    const write_buf = try allocator.alloc(u8, crypto.tls.Client.min_buffer_len);
    errdefer allocator.free(write_buf);

    // Initialize stream reader/writer
    var reader = std.Io.net.Stream.Reader.init(stream, io, read_buf);
    var writer = std.Io.net.Stream.Writer.init(stream, io, write_buf);

    // SOURCE: man 2 getrandom — fills entropy buffer from kernel entropy pool
    var entropy: [crypto.tls.Client.Options.entropy_len]u8 = undefined;
    // SOURCE: RFC 8446, Section 4.1.2 — ClientHello requires 32 bytes of fresh random
    const gr_rc = std.os.linux.getrandom(&entropy, entropy.len, 0);
    if (gr_rc < entropy.len) {
        for (0..entropy.len) |i| {
            entropy[i] = @truncate(@as(u64, gr_rc) *% 6364136223846793005 +% @as(u64, i));
        }
    }

    // SOURCE: RFC 8446, Section 5.1 — TLS record layer encapsulation
    const now: std.Io.Timestamp = .{ .nanoseconds = 0 };

    var tls = crypto.tls.Client.init(
        &reader.interface,
        &writer.interface,
        .{
            .host = .{ .explicit = parts.host },
            .ca = .no_verification,
            .entropy = &entropy,
            .realtime_now = now,
            .write_buffer = write_buf,
            .read_buffer = read_buf,
            .allow_truncation_attacks = true,
        },
    ) catch return error.TlsHandshakeFailed;

    // Build and send HTTP/1.1 GET request with optional Referer header
    // SOURCE: RFC 7230, Section 5.3.1 — request-target (absolute path)
    // SOURCE: RFC 7231, Section 5.5.2 — Referer header
    // SOURCE: ChromeDevTools MCP live capture 2026-04-25 — Chrome 147 User-Agent
    var req_buf: [HTTP_REQ_BUF_LEN]u8 = undefined;
    const req = if (referer) |ref| blk: {
        break :blk std.fmt.bufPrint(&req_buf,
            "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Referer: {s}\r\n" ++
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36\r\n" ++
            "Accept: */*\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "Connection: close\r\n\r\n",
            .{ parts.path, parts.host, ref },
        ) catch return error.BufferTooSmall;
    } else blk: {
        break :blk std.fmt.bufPrint(&req_buf,
            "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36\r\n" ++
            "Accept: */*\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "Connection: close\r\n\r\n",
            .{ parts.path, parts.host },
        ) catch return error.BufferTooSmall;
    };

    // SOURCE: RFC 8446, Section 5.2 — TLS record writing
    tls.writer.writeAll(req) catch return error.TcpSendFailed;
    tls.writer.flush() catch return error.TcpSendFailed;
    writer.interface.flush() catch return error.TcpSendFailed;

    // Parse HTTP status line
    // SOURCE: RFC 9112, Section 2.1 — status-line = HTTP-version SP status-code SP reason-phrase CRLF
    var status_line_buf: [MAX_STATUS_LINE_LEN]u8 = undefined;
    const status_line = try readHttpLine(&tls.reader, &status_line_buf);

    const space1 = mem.indexOfScalar(u8, status_line, ' ') orelse return error.HttpResponseParseFailed;
    if (space1 + 4 > status_line.len) return error.HttpResponseParseFailed;
    const status_code = std.fmt.parseInt(u16, status_line[space1 + 1 .. space1 + 4], 10) catch {
        return error.HttpResponseParseFailed;
    };
    if (status_code != 200) return error.HttpStatusError;

    // Parse response headers
    var content_length: ?usize = null;
    var is_chunked = false;
    var line_buf: [MAX_HTTP_HEADER_LEN]u8 = undefined;

    // SOURCE: RFC 9112, Section 6.3 — Content-Length / Transfer-Encoding determine body framing
    while (true) {
        const header_line = try readHttpLine(&tls.reader, &line_buf);
        if (header_line.len == 0) break;

        if (ascii.startsWithIgnoreCase(header_line, "transfer-encoding:")) {
            const encoding_value = mem.trim(u8, header_line["transfer-encoding:".len..], &ascii.whitespace);
            is_chunked = hasFinalChunkedTransferCoding(encoding_value);
            continue;
        }
        if (ascii.startsWithIgnoreCase(header_line, "content-length:")) {
            const cl_value = mem.trim(u8, header_line["content-length:".len..], &ascii.whitespace);
            content_length = std.fmt.parseInt(usize, cl_value, 10) catch return error.HttpResponseParseFailed;
        }
    }

    // Read body based on framing
    if (is_chunked) return readChunkedBody(&tls.reader, allocator);
    if (content_length) |cl| {
        if (cl > MAX_RESPONSE_SIZE) return error.BufferTooSmall;
        return readContentLengthBody(&tls.reader, allocator, cl);
    }
    return readBodyUntilClose(&tls.reader, allocator);
}

// ---------------------------------------------------------------------------
// captureAudioUrl — Arkose iframe'indeki rtag/audio URL'sini yakala (tek seferde)
// SOURCE: Arkose Labs Audio API — rtag/audio?challenge=N endpoint (live capture 2026-04-24)
// SOURCE: Chrome DevTools Protocol — Fetch.requestPaused event
// ---------------------------------------------------------------------------
pub fn captureAudioUrl(bridge: *browser_bridge.BrowserBridge, allocator: std.mem.Allocator) AudioDownloaderError![]u8 {
    // SOURCE: Arkose Labs — rtag/audio endpoint URL pattern (live test 2026-04-24)
    const paused = bridge.waitForPausedRequest("rtag/audio", CAPTURE_TIMEOUT_MS) catch |err| {
        std.debug.print("[AUDIO] captureAudioUrl: waitForPausedRequest failed: {}\n", .{err});
        return error.UrlCaptureTimeout;
    };
    defer paused.deinit(allocator);

    const url = try allocator.dupe(u8, paused.bundle.url);

    // Fail the paused request so CDP doesn't hang waiting
    bridge.cdp.failPausedRequest(paused.request_id) catch |err| {
        std.debug.print("[AUDIO] captureAudioUrl: failPausedRequest failed: {}\n", .{err});
    };

    std.debug.print("[AUDIO] Captured rtag/audio URL: {s}\n", .{url});
    return url;
}

// ---------------------------------------------------------------------------
// saveAudioClipToDisk — Audio veriyi tmp/audio_challenge_{index}.mp3 olarak kaydet
// SOURCE: POSIX filesystem API — open/write/close (man 2 open, man 2 write)
// ---------------------------------------------------------------------------
pub fn saveAudioDataToDisk(allocator: std.mem.Allocator, data: []const u8, challenge_index: u8) AudioDownloaderError![]u8 {
    // SOURCE: POSIX filesystem API — mkdir + open/write/close (man 2 open, man 2 write)
    // mkdir returns 0 on success, or -errno cast to usize on failure
    // EEXIST (17) means directory already exists — not an error
    {
        const mkdir_rc = std.os.linux.mkdirat(std.posix.AT.FDCWD, "tmp", 0o755);
        if (mkdir_rc != 0) {
            const err_val = -@as(i64, @bitCast(mkdir_rc));
            if (err_val != 17) return error.DirectoryCreateFailed; // EEXIST = 17 on Linux
        }
    }

    var ts: posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.REALTIME, &ts);
    const timestamp = @as(i64, @intCast(ts.sec));
    const path = try std.fmt.allocPrint(allocator, "tmp/audio_challenge_{d}_{d}.mp3", .{ timestamp, challenge_index });
    errdefer allocator.free(path);

    const fd = posix.openat(posix.AT.FDCWD, path, .{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    }, 0o644) catch return error.FileWriteFailed;
    defer _ = std.c.close(fd);

    var written: usize = 0;
    while (written < data.len) {
        // SOURCE: man 2 write — returns number of bytes written
        const rc_write = std.os.linux.write(fd, data.ptr + written, data.len - written);
        if (rc_write == std.math.maxInt(usize)) return error.FileWriteFailed;
        const n: usize = @intCast(rc_write);
        if (n == 0) return error.FileWriteFailed;
        written += n;
    }

    std.debug.print("[AUDIO] Saved challenge {d}: {d} bytes -> {s}\n", .{ challenge_index, data.len, path });
    return path;
}

// ---------------------------------------------------------------------------
// downloadAndSaveAudio — rtag/audio URL'sinden MP3'ü indir ve diske kaydet
// ---------------------------------------------------------------------------
pub fn downloadAndSaveAudio(
    bridge: *browser_bridge.BrowserBridge,
    allocator: std.mem.Allocator,
    challenge_index: u8,
) AudioDownloaderError!FetchResult {
    const url = try captureAudioUrl(bridge, allocator);
    errdefer allocator.free(url);

    const data = try downloadAudioClip(allocator, url);
    errdefer allocator.free(data);

    const path = try saveAudioDataToDisk(allocator, data, challenge_index);
    errdefer allocator.free(path);

    std.debug.print("[AUDIO] Challenge {d}: {d} bytes from {s} -> {s}\n", .{ challenge_index, data.len, url, path });
    return .{ .url = url, .path = path, .data = data };
}

// ---------------------------------------------------------------------------
// fetchAudioViaCdpEvaluate — Enforcement page'de CDP evaluate() ile
// fetch() çalıştırarak MP3 indirme (game-core cross-process fallback)
// ---------------------------------------------------------------------------
// SOURCE: Chrome DevTools Protocol — Runtime.evaluate executes JS in page context
// SOURCE: Arkose Labs Audio API — rtag/audio?challenge=N&gameToken=X&sessionToken=Y
// SOURCE: RFC 4648 — Base64 encoding
// SOURCE: LIVE DEBUG 2026-04-25 — enforcement page CSP allows fetch to same origin
//
// game_core_ctx = 0 olduğunda game-core iframe'in JS context'ine erişilemez.
// Ancak enforcement page'in kendi context'i (evaluate() without contextId)
// çalışabilir. Bu fonksiyon enforcement page içinde fetch() yaparak:
//   1. gameToken'ı window/locakStorage/iframe src'den bulur
//   2. rtag/audio URL'ini oluşturur (sessionToken zaten biliniyor)
//   3. Fetch'i enforcement page'den (same-origin) çalıştırır
//   4. Yanıtı base64 encode edip döndürür
//   5. Zig tarafında base64 decode edilip MP3 diske yazılır
// SOURCE: Chrome DevTools Protocol — Runtime.evaluate executes JS in page context
// SOURCE: ECMAScript Promise chaining — single tail promise serializes async work
fn buildQueuedAudioFetchExpression(
    allocator: std.mem.Allocator,
    challenge_str: []const u8,
    session_token: []const u8,
    game_token: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\(async () => {{
        \\  const queueKey = '{s}';
        \\  const queue = window[queueKey] || (window[queueKey] = {{ tail: Promise.resolve() }});
        \\  const runFetch = async () => {{
        \\    const challenge = '{s}';
        \\    const sessionTok = '{s}';
        \\    const gt = '{s}';
        \\    let url = '/rtag/audio?challenge=' + challenge + '&gameToken=' + encodeURIComponent(gt);
        \\    if (sessionTok) url += '&sessionToken=' + encodeURIComponent(sessionTok);
        \\    try {{
        \\      const resp = await fetch(url);
        \\      if (!resp.ok) return 'ERROR:HTTP_' + resp.status;
        \\      const buf = await resp.arrayBuffer();
        \\      const bytes = new Uint8Array(buf);
        \\      let binary = '';
        \\      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
        \\      return btoa(binary);
        \\    }} catch(e) {{ return 'ERROR:FETCH'; }}
        \\  }};
        \\  const queued = queue.tail.then(runFetch, runFetch);
        \\  queue.tail = queued.then(() => undefined, () => undefined);
        \\  return await queued;
        \\}})()
    , .{ AUDIO_FETCH_QUEUE_KEY, challenge_str, session_token, game_token });
}

fn looksLikeEncryptedJsonAudioPayload(bytes: []const u8) bool {
    return mem.startsWith(u8, bytes, "{\"ct\":\"") and
        mem.indexOf(u8, bytes, "\",\"iv\":\"") != null and
        mem.indexOf(u8, bytes, "\",\"s\":\"") != null;
}

fn looksLikeBase64Audio(bytes: []const u8) bool {
    // CryptoJS output: base64-encoded MP3 starts with SUQz (which decodes to ID3)
    // Check first 100 bytes are printable ASCII (base64 charset)
    if (bytes.len < 100) return false;
    for (bytes[0..100]) |b| {
        if (b < 32 or b >= 127) return false;
    }
    // Must start with base64 characters
    return std.ascii.isAlphanumeric(bytes[0]) or bytes[0] == '+' or bytes[0] == '/';
}

pub fn fetchAudioViaCdpEvaluate(
    cdp: *browser_bridge.CdpClient,
    allocator: std.mem.Allocator,
    challenge_index: u8,
    session_token: []const u8,
    game_token: []const u8,
) AudioDownloaderError!FetchResult {
    const challenge_str = try std.fmt.allocPrint(allocator, "{d}", .{challenge_index});
    defer allocator.free(challenge_str);

    const js = try buildQueuedAudioFetchExpression(allocator, challenge_str, session_token, game_token);
    defer allocator.free(js);

    std.debug.print("[AUDIO] CDP fetch: challenge={s}, sessionToken={s}\n", .{ challenge_str, session_token });

    const response = cdp.evaluateWithTimeout(js, AUDIO_FETCH_EVALUATE_TIMEOUT_MS) catch |err| {
        std.debug.print("[AUDIO] CDP fetch evaluate failed: {}\n", .{err});
        return error.CdpEvalFailed;
    };
    defer allocator.free(response);

    const b64_string = browser_bridge.extractRuntimeEvaluateStringValue(allocator, response) catch |err| {
        std.debug.print("[AUDIO] CDP fetch string extraction failed: {}\n", .{err});
        return error.CdpEvalFailed;
    };
    defer allocator.free(b64_string);

    if (mem.startsWith(u8, b64_string, "ERROR:")) {
        std.debug.print("[AUDIO] CDP fetch error: {s}\n", .{b64_string});
        if (mem.startsWith(u8, b64_string, "ERROR:NO_GAME_TOKEN")) return error.GameTokenNotFound;
        if (mem.startsWith(u8, b64_string, "ERROR:HTTP_")) return error.FetchFailed;
        if (mem.startsWith(u8, b64_string, "ERROR:FETCH")) return error.FetchFailed;
        return error.FetchFailed;
    }

    std.debug.print("[AUDIO] CDP fetch got base64 response ({d} chars)\n", .{b64_string.len});

    const decoder = std.base64.standard.Decoder;
    const decoded_len = decoder.calcSizeForSlice(b64_string) catch |err| {
        std.debug.print("[AUDIO] Base64 calcSizeForSlice failed: {}\n", .{err});
        return error.Base64DecodeFailed;
    };
    const raw_data = try allocator.alloc(u8, decoded_len);
    errdefer allocator.free(raw_data);
    decoder.decode(raw_data, b64_string) catch |err| {
        std.debug.print("[AUDIO] Base64 decode failed: {}\n", .{err});
        return error.Base64DecodeFailed;
    };

    // Handle both encrypted JSON and base64-encoded (SUQz) formats
    var mp3_data: []u8 = undefined;
    if (looksLikeEncryptedJsonAudioPayload(raw_data)) {
        // Encrypted mode: need decryption_key from ekey endpoint
        // The enforcement page can fetch it same-origin
        std.debug.print("[AUDIO] Audio is encrypted, fetching decryption_key via CDP...\n", .{});
        const ekey_js = try std.fmt.allocPrint(allocator,
            \\(async () => {{
            \\  try {{
            \\    const body = 'session_token={s}&game_token={s}&sid=eu-west-1';
            \\    const r = await fetch('/fc/ekey/', {{ method: 'POST',
            \\      headers: {{ 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' }},
            \\      body: body }});
            \\    if (!r.ok) return 'ERROR:EKEY_HTTP_' + r.status;
            \\    const j = await r.json();
            \\    return j.decryption_key || 'ERROR:NO_DKEY';
            \\  }} catch(e) {{ return 'ERROR:EKEY_FETCH'; }}
            \\}})()
        , .{ session_token, game_token });
        defer allocator.free(ekey_js);

        const ekey_resp = cdp.evaluateWithTimeout(ekey_js, 15000) catch |err| {
            std.debug.print("[AUDIO] ekey fetch failed: {}\n", .{err});
            return error.FetchFailed;
        };
        defer allocator.free(ekey_resp);

        const dkey = browser_bridge.extractRuntimeEvaluateStringValue(allocator, ekey_resp) catch |err| {
            std.debug.print("[AUDIO] ekey result extraction failed: {}\n", .{err});
            return error.FetchFailed;
        };
        defer allocator.free(dkey);

        if (mem.startsWith(u8, dkey, "ERROR:")) {
            std.debug.print("[AUDIO] ekey error: {s}\n", .{dkey});
            return error.EncryptedJsonAudioPayload;
        }

        std.debug.print("[AUDIO] Decrypting with key={s}\n", .{dkey});
        mp3_data = audio_decrypt.decryptArkoseAudio(allocator, raw_data, dkey) catch |err| {
            std.debug.print("[AUDIO] Decrypt failed: {}\n", .{err});
            return error.EncryptedJsonAudioPayload;
        };
        allocator.free(raw_data);
        std.debug.print("[AUDIO] Decrypted {d} bytes, checking if needs base64 decode...\n", .{mp3_data.len});

        // CryptoJS decrypt outputs base64-encoded MP3 (SUQz format) — decode once more
        if (looksLikeBase64Audio(mp3_data)) {
            const b64_decoded_len = decoder.calcSizeForSlice(mp3_data) catch {
                return error.Base64DecodeFailed;
            };
            const b64_decoded = try allocator.alloc(u8, b64_decoded_len);
            decoder.decode(b64_decoded, mp3_data) catch {
                allocator.free(b64_decoded);
                return error.Base64DecodeFailed;
            };
            allocator.free(mp3_data);
            mp3_data = b64_decoded;
            std.debug.print("[AUDIO] Base64 decoded after decrypt: {d} bytes\n", .{mp3_data.len});
        }
    } else if (looksLikeBase64Audio(raw_data)) {
        // CryptoJS decrypt output is base64-encoded MP3 (SUQz format)
        std.debug.print("[AUDIO] Audio is base64-encoded (SUQz/CryptoJS format), decoding...\n", .{});
        const decoded_mp3_len = decoder.calcSizeForSlice(raw_data) catch |err| {
            std.debug.print("[AUDIO] Base64 calcSizeForSlice for SUQz format failed: {}\n", .{err});
            allocator.free(raw_data);
            return error.Base64DecodeFailed;
        };
        mp3_data = try allocator.alloc(u8, decoded_mp3_len);
        decoder.decode(mp3_data, raw_data) catch |err| {
            std.debug.print("[AUDIO] Base64 decode for SUQz format failed: {}\n", .{err});
            allocator.free(mp3_data);
            allocator.free(raw_data);
            return error.Base64DecodeFailed;
        };
        allocator.free(raw_data);
        std.debug.print("[AUDIO] Base64 decoded: {d} bytes\n", .{mp3_data.len});
    } else {
        mp3_data = raw_data;
    }

    const path = try saveAudioDataToDisk(allocator, mp3_data, challenge_index);
    errdefer allocator.free(path);

    const url = try std.fmt.allocPrint(allocator, "cdp://challenge_{d}", .{challenge_index});

    std.debug.print("[AUDIO] CDP fetch saved challenge {d}: {d} bytes -> {s}\n", .{ challenge_index, mp3_data.len, path });
    return .{ .url = url, .path = path, .data = mp3_data };
}

fn currentTimestampNs() i64 {
    var ts: posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * std.time.ns_per_s + @as(i64, @intCast(ts.nsec));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "audio_downloader: URL'den session_token extraction" {
    const url = "https://client-api.arkoselabs.com/fc/get_audio?session_token=abc123def456&pk=def789&r=test123&game_token=gtok";
    const token = try extractSessionToken(url);
    try std.testing.expectEqualStrings("abc123def456", token);
}

test "audio_downloader: URL'den pk extraction" {
    const url = "https://client-api.arkoselabs.com/fc/get_audio?session_token=abc&pk=def789&r=test";
    const pk = try extractQueryParam(url, "pk=");
    try std.testing.expectEqualStrings("def789", pk);
}

test "audio_downloader: session_token URL sonunda" {
    const url = "https://client-api.arkoselabs.com/fc/get_audio?pk=def&r=test&session_token=xyz123";
    const token = try extractSessionToken(url);
    try std.testing.expectEqualStrings("xyz123", token);
}

test "audio_downloader: session_token eksik hata" {
    const url = "https://client-api.arkoselabs.com/fc/get_audio?pk=def&r=test";
    const result = extractSessionToken(url);
    try std.testing.expectError(AudioDownloaderError.ParseFailed, result);
}

test "audio_downloader: URL'den pk eksik hata" {
    const url = "https://client-api.arkoselabs.com/fc/get_audio?session_token=abc&r=test";
    const result = extractQueryParam(url, "pk=");
    try std.testing.expectError(AudioDownloaderError.ParseFailed, result);
}

test "audio_downloader: parseUrlParts" {
    const url = "https://client-api.arkoselabs.com/fc/get_audio?session_token=abc&pk=def";
    const parts = try parseUrlParts(url);
    try std.testing.expectEqualStrings("client-api.arkoselabs.com", parts.host);
    try std.testing.expectEqualStrings("/fc/get_audio?session_token=abc&pk=def", parts.path);
    try std.testing.expectEqual(@as(u16, 443), parts.port);
}

test "audio_downloader: AudioClip struct size" {
    comptime {
        std.debug.assert(@sizeOf(AudioClip) > 0);
    }
}

test "audio_downloader: AudioDownloadResult struct size" {
    comptime {
        std.debug.assert(@sizeOf(AudioDownloadResult) > 0);
    }
}

test "audio_downloader: queued CDP fetch JS serializes audio downloads" {
    const allocator = std.testing.allocator;
    const js = try buildQueuedAudioFetchExpression(allocator, "2", "session-abc", "game-def");
    defer allocator.free(js);

    try std.testing.expect(std.mem.indexOf(u8, js, AUDIO_FETCH_QUEUE_KEY) != null);
    try std.testing.expect(std.mem.indexOf(u8, js, "queue.tail.then(runFetch, runFetch)") != null);
    try std.testing.expect(std.mem.indexOf(u8, js, "queue.tail = queued.then(() => undefined, () => undefined)") != null);
    try std.testing.expect(std.mem.indexOf(u8, js, "return await queued") != null);
    try std.testing.expect(std.mem.indexOf(u8, js, "const challenge = '2'") != null);
}
