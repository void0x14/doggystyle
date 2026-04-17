const std = @import("std");
const network = @import("network_core.zig");
const http2 = @import("http2_core.zig");
const jitter = @import("jitter_core.zig");
const digistallone = @import("digistallone.zig");
const browser_init = @import("browser_init.zig");
const browser_bridge = @import("browser_bridge.zig");
const process = std.process;
const Io = std.Io;

fn resolveIpv4Host(host: [:0]const u8) !u32 {
    var hints: std.c.addrinfo = .{
        .flags = .{},
        .family = std.posix.AF.INET,
        .socktype = std.posix.SOCK.STREAM,
        .protocol = 0,
        .addrlen = 0,
        .canonname = null,
        .addr = null,
        .next = null,
    };

    var result: ?*std.c.addrinfo = null;
    const gai_rc = std.c.getaddrinfo(host.ptr, null, &hints, &result);
    if (@intFromEnum(gai_rc) != 0) return error.TcpConnectFailed;
    defer if (result) |res| std.c.freeaddrinfo(res);

    var current = result;
    while (current) |entry| : (current = entry.next) {
        const addr = entry.addr orelse continue;
        if (addr.family != std.posix.AF.INET) continue;

        const ipv4: *const std.os.linux.sockaddr.in = @ptrCast(@alignCast(addr));
        return @byteSwap(ipv4.addr);
    }

    return error.TcpConnectFailed;
}

fn currentMonotonicMs() u32 {
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @intCast((@as(u64, @intCast(ts.sec)) * 1000) + (@as(u64, @intCast(ts.nsec)) / 1000000));
}

fn createArtifactDir(allocator: std.mem.Allocator, io: std.Io) ![]u8 {
    var cwd_buf: [std.posix.PATH_MAX]u8 = undefined;
    const cwd_ptr = std.c.getcwd(&cwd_buf, cwd_buf.len) orelse return error.TraceDirCreateFailed;
    const cwd = std.mem.sliceTo(@as([*:0]u8, @ptrCast(cwd_ptr)), 0);

    const trace_dir = try std.fmt.allocPrint(allocator, "{s}/artifacts/browser-trace-{d}", .{ cwd, currentMonotonicMs() });
    errdefer allocator.free(trace_dir);

    std.Io.Dir.cwd().createDirPath(io, trace_dir) catch return error.TraceDirCreateFailed;
    return trace_dir;
}

fn refreshGitHubTransport(
    allocator: std.mem.Allocator,
    io: std.Io,
    github_client: *network.GitHubHttpClient,
    sock: anytype,
) !void {
    const now_ms = currentMonotonicMs();
    const client_isn: u32 = now_ms;
    const client_tsval: u32 = @intCast(@as(u64, now_ms) / 10);

    std.debug.print("[GITHUB] Transport refresh: sending new SYN on {d}->{d}\n", .{
        github_client.src_port,
        github_client.dst_port,
    });

    const syn_packet = try network.buildTCPSynAlloc(
        allocator,
        github_client.src_ip,
        github_client.dst_ip,
        github_client.src_port,
        github_client.dst_port,
        client_isn,
        client_tsval,
        0,
    );
    defer allocator.free(syn_packet);

    _ = try sock.sendPacket(syn_packet, github_client.dst_ip);

    const handshake = try network.completeHandshakeFull(
        allocator,
        io,
        github_client.dst_ip,
        github_client.dst_port,
        github_client.host,
        github_client.src_ip,
        github_client.src_port,
        sock,
        client_isn,
        client_tsval,
    );
    try github_client.adoptHandshake(allocator, handshake);
    std.debug.print("[GITHUB] Transport refresh complete; HTTP/2 state reset\n", .{});
}

/// Ghost Engine — Master Orchestrator (PRODUCTION)
///
/// Bu dosya tüm modülleri kronolojik sırada birleştirir:
///   1. Jitter Engine Initialization
///   2. Raw Socket Setup + Ephemeral Port Binding
///   3. Firewall Rules (NOTRACK + INPUT ACCEPT)
///   4. TCP SYN Transmission
///   5. TCP + TLS 1.3 Handshake (completeHandshakeFull → HandshakeResultFull)
///   6. HTTP/2 GET Request → Decrypt → Print HTML
///   7. Safe Shutdown + Resource Cleanup
///
/// KULLANIM:
///   sudo ./zig-out/bin/ghost_engine <interface>
///
/// ÖRNEK:
///   sudo ./zig-out/bin/ghost_engine enp37s0
///
/// NOT: Raw socket için root yetkisi gereklidir.
pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;

    // =========================================================================
    // ARGUMENT PARSING — Zig 0.16 init pattern
    // =========================================================================
    var args_iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args_iter.deinit();

    _ = args_iter.skip(); // argv[0]

    const iface_name = args_iter.next() orelse {
        std.debug.print("KULLANIM: sudo ./zig-out/bin/ghost_engine <interface>\n", .{});
        std.debug.print("ÖRNEK:  sudo ./zig-out/bin/ghost_engine enp37s0\n", .{});
        std.process.exit(1);
    };

    // =========================================================================
    // SABITLER: GitHub Hedefi
    // =========================================================================
    const target_host = "github.com";
    const target_port: u16 = 443;
    const request_path = "/signup";

    const dst_ip: u32 = try resolveIpv4Host(target_host);

    // =========================================================================
    // ADIM 1: Jitter Engine Initialization
    // =========================================================================
    std.debug.print("\n", .{});
    std.debug.print("╔══════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║           GHOST ENGINE — PRODUCTION MODE                ║\n", .{});
    std.debug.print("╚══════════════════════════════════════════════════════════╝\n", .{});
    std.debug.print("\n", .{});

    std.debug.print("[INIT] Booting Ghost Engine...\n", .{});
    try jitter.JitterEngine.initJitterEngine();
    std.debug.print("[JITTER] Engine initialized (monotonic + getrandom)\n", .{});

    // =========================================================================
    // ADIM 2: Platform Check
    // =========================================================================
    if (!network.is_linux) {
        std.debug.print("[FATAL] Only Linux is supported for raw socket operations\n", .{});
        std.process.exit(1);
    }

    // =========================================================================
    // ADIM 3: Interface Resolution
    // =========================================================================
    const src_ip: u32 = try network.getInterfaceIp(iface_name);
    std.debug.print("[NETWORK] Interface: {s}\n", .{iface_name});
    std.debug.print("[NETWORK] Source IP: {}.{}.{}.{}\n", .{
        @as(u8, @truncate((src_ip >> 24) & 0xFF)),
        @as(u8, @truncate((src_ip >> 16) & 0xFF)),
        @as(u8, @truncate((src_ip >> 8) & 0xFF)),
        @as(u8, @truncate(src_ip & 0xFF)),
    });
    std.debug.print("[NETWORK] Destination: {}.{}.{}.{}:{d}\n", .{
        @as(u8, @truncate((dst_ip >> 24) & 0xFF)),
        @as(u8, @truncate((dst_ip >> 16) & 0xFF)),
        @as(u8, @truncate((dst_ip >> 8) & 0xFF)),
        @as(u8, @truncate(dst_ip & 0xFF)),
        target_port,
    });

    // =========================================================================
    // ADIM 4: Ephemeral Port Generation
    // =========================================================================
    const now_ms: u32 = currentMonotonicMs();
    var r_state: u32 = now_ms;
    r_state ^= r_state << 13;
    r_state ^= r_state >> 17;
    r_state ^= r_state << 5;
    const src_port: u16 = @as(u16, @truncate(r_state % (65535 - 49152) + 49152));

    std.debug.print("[NETWORK] Ephemeral port: {d}\n", .{src_port});

    // =========================================================================
    // ADIM 5: Raw Socket Binding
    // =========================================================================
    std.debug.print("[SOCKET] Binding raw socket...\n", .{});

    const sock = try network.LinuxRawSocket.init(iface_name, src_ip, src_port, target_port);
    defer sock.deinit();

    std.debug.print("[SOCKET] Raw socket bound (fd={d})\n", .{sock.fd});

    // =========================================================================
    // ADIM 6: Firewall Rules
    // =========================================================================
    std.debug.print("[FIREWALL] Applying RST suppression...\n", .{});
    try network.applyRstSuppression(allocator, src_port);
    defer network.removeRstSuppression(allocator, src_port);
    std.debug.print("[FIREWALL] Rules applied (NOTRACK + INPUT ACCEPT)\n", .{});

    // =========================================================================
    // ADIM 7: TCP SYN Transmission
    // =========================================================================
    const seq_num: u32 = now_ms;
    const tsval: u32 = @as(u32, @intCast(now_ms / 10));

    std.debug.print("[TCP] Sending SYN (seq={d})...\n", .{seq_num});
    const syn_packet = try network.buildTCPSynAlloc(
        allocator,
        src_ip,
        dst_ip,
        src_port,
        target_port,
        seq_num,
        tsval,
        0,
    );
    defer allocator.free(syn_packet);

    _ = try sock.sendPacket(syn_packet, dst_ip);
    std.debug.print("[TCP] SYN transmitted\n", .{});

    // =========================================================================
    // ADIM 8: Full Handshake (TCP + TLS 1.3)
    // =========================================================================
    std.debug.print("\n", .{});
    std.debug.print("[HANDSHAKE] Starting TCP + TLS 1.3 handshake...\n", .{});

    // SOURCE: vendor/zig-std/std/process.zig — std.process.Init carries a valid process I/O context
    const io = init.io;

    const handshake = try network.completeHandshakeFull(
        allocator,
        io,
        dst_ip,
        target_port,
        target_host,
        src_ip,
        src_port,
        &sock,
        seq_num, // SYN'nin ISN'i
        tsval, // SYN'nin TSval'i — monotonik artış buradan devam eder
    );

    std.debug.print("[HANDSHAKE] Complete!\n", .{});
    std.debug.print("[HANDSHAKE] Cipher suite: 0x{x:04}\n", .{handshake.cipher_suite});
    std.debug.print("[HANDSHAKE] Server random: ", .{});
    for (handshake.server_random[0..8]) |b| {
        std.debug.print("{x:0>2}", .{b});
    }
    std.debug.print("...\n", .{});
    std.debug.print("[TLS] Session established (sock_fd={d}, seq_send={d})\n", .{
        handshake.sock_fd,
        handshake.tls_session.seq_send,
    });

    // =========================================================================
    // ADIM 9: HTTP/2 GET Request → Decrypt → Display
    // =========================================================================
    std.debug.print("\n", .{});
    std.debug.print("[HTTP/2] Initializing GitHubHttpClient with real handshake state...\n", .{});

    var github_client = network.GitHubHttpClient.initFromHandshake(
        target_host,
        target_port,
        handshake.sock_fd,
        handshake.tls_session,
        handshake.pending_server_tls_ciphertext,
        handshake.src_ip,
        handshake.dst_ip,
        handshake.src_port,
        handshake.dst_port,
        handshake.client_seq,
        handshake.server_seq,
        handshake.client_tsval,
        handshake.server_tsval,
    );
    defer github_client.deinit(allocator);

    std.debug.print("[HTTP/2] Client initialized (sock_fd={d})\n", .{github_client.sock_fd.?});
    std.debug.print("[HTTP/2] Requesting: https://{s}{s}\n", .{ target_host, request_path });

    // PERFORM THE GET REQUEST — BU KRITIK NOKTA!
    std.debug.print("\n[HTTP/2] Sending GET request and waiting for response...\n", .{});

    var response = try github_client.performGet(allocator, "https://github.com/signup", &sock, dst_ip);
    defer response.deinit(allocator);

    // DECRYPT & DISPLAY
    std.debug.print("\n", .{});
    std.debug.print("╔══════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║              DECRYPTED HTTP RESPONSE                     ║\n", .{});
    std.debug.print("╚══════════════════════════════════════════════════════════╝\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("[RESPONSE] Status: {d}\n", .{response.status_code});
    std.debug.print("[RESPONSE] Headers:\n", .{});
    for (response.headers) |header| {
        std.debug.print("{s}: {s}\n", .{ header.name, header.value });
    }

    // Display first 1000 bytes of HTML body
    const display_len = if (response.body.len > 1000) 1000 else response.body.len;
    std.debug.print("\n[HTML BODY - First {d} bytes]:\n", .{display_len});
    std.debug.print("────────────────────────────────────────────────────────────\n", .{});
    std.debug.print("{s}", .{response.body[0..display_len]});
    std.debug.print("\n────────────────────────────────────────────────────────────\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("[SUCCESS] Received {d} bytes decrypted HTML response\n", .{response.body.len});
    std.debug.print("\n", .{});

    // =========================================================================
    // ADIM 10: Token Extraction    // =========================================================================
    std.debug.print("[TOKEN] Extracting authenticity_token from HTML...\n", .{});
    const auth_token = network.extractAuthenticityToken(response.body) catch |err| {
        std.debug.print("[FATAL] Failed to extract token: {}\n", .{err});
        std.process.exit(1);
    };
    std.debug.print("[SUCCESS] Extracted Token: {s}\n", .{auth_token});

    // =========================================================================
    // ADIM 11.4: headless=new + CDP Browser + Token Harvest
    // =========================================================================
    // SOURCE: src/browser_bridge.zig — CdpClient connects to Chrome CDP WebSocket
    // SOURCE: src/browser_bridge.zig — BrowserBridge injects harvest.js via Runtime.evaluate
    // SOURCE: src/harvest.js — Sets window.__ghost_token / window.__ghost_identity globals
    //
    // IMPORTANT: Chrome headless=new does NOT support extensions (confirmed by Chrome team).
    // CDP Runtime.evaluate is the ONLY reliable way to inject JS and read results.
    //
    // NOTE: Browser + fingerprint collection moved before BDA creation so that
    // real browser fingerprint data can populate the BDA payload (lowers Arkose risk score).
    //
    // Flow:
    //   1. Spawn Chrome with --remote-debugging-port=9222 in headless=new mode
    //   2. BrowserBridge connects to CDP WebSocket for the signup tab
    //   3. Collect fingerprint BEFORE any Arkose interaction
    //   4. Use fingerprint to build BDA payload with real values
    //   5. Inject harvest.js via Runtime.evaluate for later token harvesting

    // Step 1: Spawn Chrome with CDP in headless=new mode
    std.debug.print("[BROWSER] Launching stealth Chrome for token harvest (headless=new + CDP)...\n", .{});
    var stealth_browser = try browser_init.StealthBrowser.init(allocator, io);
    defer stealth_browser.deinit();

    if (stealth_browser.getPid()) |browser_pid| {
        std.debug.print("[BROWSER] Stealth Chrome ready (pid={d}, profile={s})\n", .{
            browser_pid,
            stealth_browser.getProfileDir(),
        });
    } else {
        std.debug.print("[BROWSER] Stealth Chrome spawned without PID handle (profile={s})\n", .{
            stealth_browser.getProfileDir(),
        });
    }

    // Step 3: Connect to Chrome CDP and install the browser session bridge.
    std.debug.print("[CDP] Connecting to Chrome CDP on localhost:{d}...\n", .{browser_bridge.CDP_PORT});
    var bridge = try browser_bridge.BrowserBridge.init(allocator, "https://github.com/signup");
    defer {
        bridge.verifyArtifacts();
        bridge.deinit();
    }

    // Create artifact directory for browser diagnostics (no Xvfb needed)
    const artifact_dir = createArtifactDir(allocator, io) catch |err| blk: {
        std.debug.print("[ARTIFACTS] ⚠ Could not create artifact dir: {} — continuing without diagnostics\n", .{err});
        break :blk null;
    };
    defer if (artifact_dir) |dir| allocator.free(dir);

    if (artifact_dir) |dir| {
        bridge.enableDiagnostics(dir) catch |err| {
            std.debug.print("[ARTIFACTS] ⚠ Could not enable diagnostics: {}\n", .{err});
        };
        std.debug.print("[ARTIFACTS] Diagnostics enabled: {s}\n", .{dir});
    }

    // =========================================================================
    // FINGERPRINT DIAGNOSTIC — Collect baseline BEFORE any Arkose interaction
    // This writes browser-fingerprint.ndjson with ALL 25+ signals Arkose sees
    // =========================================================================
    std.debug.print("\n[FINGERPRINT] Collecting baseline fingerprint diagnostic...\n", .{});

    const fingerprint_opt: ?browser_bridge.FingerprintDiagnostic = bridge.collectFingerprint() catch |err| blk: {
        std.debug.print("[FINGERPRINT] Failed to collect fingerprint: {}\n", .{err});
        break :blk null;
    };

    // Keep fingerprint slices alive through BDA creation — deinit after BDA is encrypted
    defer {
        if (fingerprint_opt) |fp| {
            var fp_mut = fp;
            fp_mut.deinit(allocator);
        }
    }

    // Write to NDJSON file if we have data
    if (fingerprint_opt) |fingerprint| {
        var fp = fingerprint;
        browser_bridge.writeFingerprintNDJSON(allocator, &fp, "before-arkose") catch |err| {
            std.debug.print("[FINGERPRINT] Failed to write NDJSON: {}\n", .{err});
        };

        // Log key suspicious signals to console for immediate visibility
        std.debug.print("\n[FINGERPRINT] === KEY SIGNALS ===\n", .{});
        std.debug.print("[FINGERPRINT] navigator.webdriver: {?}\n", .{fp.navigator_webdriver});
        std.debug.print("[FINGERPRINT] window.chrome exists: {}\n", .{fp.window_chrome_exists});
        std.debug.print("[FINGERPRINT] chrome.runtime.connect: {}\n", .{fp.chrome_runtime_connect});
        std.debug.print("[FINGERPRINT] WebGL vendor: {s}\n", .{fp.webgl_vendor});
        std.debug.print("[FINGERPRINT] WebGL renderer: {s}\n", .{fp.webgl_renderer});
        std.debug.print("[FINGERPRINT] CDP side-effect: {}\n", .{fp.cdp_runtime_enable_side_effect});
        std.debug.print("[FINGERPRINT] SourceURL leak: {}\n", .{fp.sourceurl_leak});
        std.debug.print("[FINGERPRINT] Console side-effects: {}\n", .{fp.console_debug_side_effects});
        std.debug.print("[FINGERPRINT] NDJSON: browser-fingerprint.ndjson\n", .{});
        std.debug.print("[FINGERPRINT] =====================\n\n", .{});
    } else {
        std.debug.print("[FINGERPRINT] Skipping diagnostic — fingerprint not available\n", .{});
    }

    // =========================================================================
    // ADIM 11: BDA Telemetry Packaging & Risk Check Submission
    // =========================================================================
    // SOURCE: FingerprintDiagnostic → BrowserEnvironment field mapping
    //   webgl_renderer        → env.webgl.renderer
    //   webgl_vendor          → env.webgl.vendor
    //   screen_width          → env.screen.width             (u32 → u16)
    //   screen_height         → env.screen.height            (u32 → u16)
    //   screen_avail_width    → env.screen.availWidth        (u32 → u16)
    //   screen_avail_height   → env.screen.availHeight       (u32 → u16)
    //   canvas_hash           → env.canvas.hash
    //   navigator_userAgent   → env.navigator.userAgent
    //   navigator_platform   → env.navigator.platform
    //   navigator_languages   → env.navigator.languages_json  (JSON array string)
    //   navigator_hardware_concurrency → env.navigator.hardwareConcurrency (u8)
    //   navigator_device_memory        → env.navigator.deviceMemory        (u8)
    //   timezone_offset       → env.timezone.offset
    std.debug.print("\n[BDA] Preparing Browser Data Analytics (BDA) payload...\n", .{});
    var env = try network.BrowserEnvironment.init(allocator, io);

    // Round timestamp to 6-hour boundary per Arkose Labs BDA format
    // SOURCE: Arkose Labs BDA — timestamp rounded to 21600-second windows
    env.timestamp = env.timestamp - (env.timestamp % 21600000); // 21600s * 1000ms

    if (fingerprint_opt) |fp| {
        env.navigator.userAgent = fp.navigator_userAgent;
        env.navigator.platform = fp.navigator_platform;
        env.navigator.languages_json = fp.navigator_languages;
        env.navigator.hardwareConcurrency = fp.navigator_hardware_concurrency;
        env.navigator.deviceMemory = fp.navigator_device_memory;
        env.webgl.renderer = fp.webgl_renderer;
        env.webgl.vendor = fp.webgl_vendor;
        env.screen.width = @intCast(fp.screen_width);
        env.screen.height = @intCast(fp.screen_height);
        env.screen.availWidth = @intCast(fp.screen_avail_width);
        env.screen.availHeight = @intCast(fp.screen_avail_height);
        env.canvas.hash = fp.canvas_hash;
        env.timezone.offset = fp.timezone_offset;
        std.debug.print("[BDA] Populated from real browser fingerprint\n", .{});
    } else {
        env.navigator.hardwareConcurrency = 16;
        env.navigator.deviceMemory = 32;
        env.webgl.renderer = "AMD Radeon RX 7900 XTX (RADV NAVI31, LLVM 18.1.8, DRM 3.57, CachyOS)";
        std.debug.print("[BDA] Fingerprint unavailable — using hardcoded fallback values\n", .{});
    }

    const bda_payload = try network.encryptBda(allocator, &env);
    defer allocator.free(bda_payload);

    const bda_json = try env.toJsonAlloc(allocator);
    defer allocator.free(bda_json);
    std.debug.print("[BDA] JSON payload ({d} bytes): {s}\n", .{ bda_json.len, bda_json[0..@min(bda_json.len, 500)] });
    std.debug.print("[BDA] Encrypted payload generated ({d} bytes)\n", .{bda_payload.len});
    std.debug.print("[RISK CHECK] Sending POST to /signup_check/usage...\n", .{});

    const risk_status = blk: {
        break :blk github_client.performRiskCheck(
            allocator,
            auth_token,
            bda_payload,
            &sock,
            dst_ip,
        ) catch |err| blk2: {
            std.debug.print("[RISK CHECK] FAILED with error: {}\n", .{err});
            std.debug.print("[RISK CHECK] This usually means:\n", .{});
            std.debug.print("[RISK CHECK]   1. BDA payload format is wrong (check JSON above)\n", .{});
            std.debug.print("[RISK CHECK]   2. GitHub closed the connection (TLS close_notify)\n", .{});
            std.debug.print("[RISK CHECK]   3. HTTP/2 framing error\n", .{});
            std.debug.print("[RISK CHECK] Continuing with challenge_required=true as fallback\n", .{});
            break :blk2 network.RiskStatus{ .challenge_required = true };
        };
    };

    if (!risk_status.challenge_required) {
        std.debug.print("[SUCCESS] Arkose Bypassed via Low-Risk Signature\n", .{});
    } else {
        std.debug.print("[WARN] Challenge required! Risk score might be too high.\n", .{});
    }

    // =========================================================================
    // ADIM 11.5: Final Signup Submission
    // =========================================================================
    std.debug.print("\n[SIGNUP] Preparing random credentials via digistallone...\n", .{});
    var mail_client = try digistallone.DigistalloneClient.init(allocator);
    defer mail_client.deinit();

    const email = try mail_client.getNewEmailAddress(null);
    defer allocator.free(email);

    // Generate secure password and human-like username
    var username_buf: [16]u8 = undefined;
    var pwd_buf: [20]u8 = undefined;
    const charset = "abcdefghijklmnopqrstuvwxyz0123456789";
    const pwd_charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
    var rand_bytes: [36]u8 = undefined;

    _ = std.os.linux.getrandom(&rand_bytes, rand_bytes.len, 0);
    for (0..12) |i| {
        username_buf[i] = charset[rand_bytes[i] % charset.len];
    }
    const username = username_buf[0..12];
    for (0..16) |i| {
        pwd_buf[i] = pwd_charset[rand_bytes[i + 12] % pwd_charset.len];
    }
    // ensure at least one number, one lower, one upper, one special
    pwd_buf[16] = '1';
    pwd_buf[17] = 'a';
    pwd_buf[18] = 'A';
    pwd_buf[19] = '!';
    const password = pwd_buf[0..20];

    std.debug.print("[SIGNUP] Generated Username: {s}\n", .{username});
    std.debug.print("[SIGNUP] Using Email: {s} (TEST MODE - Digistallone bypassed)\n", .{email});
    std.debug.print("[SIGNUP] Submitting POST to /signup...\n", .{});

    std.debug.print("[BROWSER] Capturing exact browser-owned signup bundle...\n", .{});
    var signup_bundle = bridge.captureSignupBundle(username, email, password, "") catch |err| {
        std.debug.print("[BROWSER] FAILED: Could not capture signup bundle: {}\n", .{err});
        return err;
    };
    defer signup_bundle.deinit(allocator);

    var signup_success = github_client.performCapturedBrowserRequest(
        allocator,
        &signup_bundle.request,
        &sock,
        dst_ip,
        10000,
        "HTTP/2 browser signup HEADERS",
        "HTTP/2 browser signup DATA CHUNK",
    ) catch |err| blk: {
        if (err == error.ConnectionClosed) {
            std.debug.print("[SIGNUP] GitHub transport was closed after the long browser/mail phase; refreshing and retrying once...\n", .{});
            try refreshGitHubTransport(allocator, io, &github_client, &sock);
            break :blk try github_client.performCapturedBrowserRequest(
                allocator,
                &signup_bundle.request,
                &sock,
                dst_ip,
                10000,
                "HTTP/2 browser signup HEADERS",
                "HTTP/2 browser signup DATA CHUNK",
            );
        }
        return err;
    };
    defer signup_success.deinit(allocator);

    try network.extractCookiesFromHttp2Response(&signup_success, &github_client.cookie_jar);
    try bridge.syncGitHubCookies(
        if (github_client.cookie_jar.user_session_len > 0) github_client.cookie_jar.user_session[0..github_client.cookie_jar.user_session_len] else null,
        if (github_client.cookie_jar.host_user_session_len > 0) github_client.cookie_jar.host_user_session[0..github_client.cookie_jar.host_user_session_len] else null,
        if (github_client.cookie_jar.gh_sess_len > 0) github_client.cookie_jar.gh_sess[0..github_client.cookie_jar.gh_sess_len] else null,
        if (github_client.cookie_jar.octo_len > 0) github_client.cookie_jar.octo[0..github_client.cookie_jar.octo_len] else null,
    );

    if (network.GitHubHttpClient.isSignupVerificationState(signup_success.status_code, signup_success.body)) {
        std.debug.print("[SUCCESS] Signup Form Submitted. Waiting for Redirect...\n", .{});
    } else {
        std.debug.print("[FATAL] Signup did not reach the verification step. Polling mailbox would stall because no verification mail is guaranteed.\n", .{});
        std.process.exit(1);
    }

    // =========================================================================
    // ADIM 11.6: Module 3.2 — Email Verification via Digistallone Livewire
    // =========================================================================
    // GitHub signup returned 302 → we're on the "Enter Verification Code" page.
    // Now we:
    //   1. Persist credentials to accounts.txt
    //   2. Poll digistallone mailbox via Livewire sync for the GitHub verification email
    //   3. Extract the 6-digit code
    //   4. POST it back to GitHub /signup/verify_email
    // =========================================================================

    // --- 1. Persist credentials ---
    const accounts_file = "accounts.txt";
    {
        const line = try std.fmt.allocPrint(
            allocator,
            "{s}:{s}:{s}\n",
            .{ username, password, email },
        );
        defer allocator.free(line);
        const file = std.Io.Dir.cwd().createFile(io, accounts_file, .{ .truncate = false }) catch |err| blk: {
            // If file already exists, open it for writing instead
            if (err == error.PathAlreadyExists) {
                break :blk try std.Io.Dir.cwd().openFile(io, accounts_file, .{ .mode = .write_only });
            }
            return err;
        };
        defer file.close(io);
        // Append: write at end of file
        const file_len = try file.length(io);
        try file.writePositionalAll(io, line, file_len);
        std.debug.print("[ACCOUNTS] Credentials saved to {s}\n", .{accounts_file});
    }

    // --- 2. Poll digistallone mailbox for GitHub verification code ---
    std.debug.print("\n[MAIL] Polling digistallone mailbox for GitHub verification code...\n", .{});

    const github_code = mail_client.pollInboxForGitHubCode(
        digistallone.MAX_POLL_ATTEMPTS,
        digistallone.DEFAULT_POLL_INTERVAL_MS,
    ) catch |err| {
        std.debug.print("[MAIL] FAILED: Could not retrieve verification code: {}\n", .{err});
        std.debug.print("[MAIL] Tip: Check if GitHub email was sent to {s}\n", .{email});
        std.process.exit(1);
    };
    defer allocator.free(github_code);

    std.debug.print("[MAIL] Livewire sync successful. Code {s} found. Submitting...\n", .{github_code});

    // --- 3. Submit code to GitHub ---
    const post_signup_grace = std.os.linux.timespec{ .sec = 1, .nsec = 500 * std.time.ns_per_ms };
    _ = std.os.linux.nanosleep(&post_signup_grace, null);
    try bridge.navigateToAccountVerifications();

    std.debug.print("[BROWSER] Capturing exact browser-owned verify bundle...\n", .{});
    var verify_bundle = bridge.captureVerifyBundle(github_code) catch |err| {
        std.debug.print("[BROWSER] FAILED: Could not capture verify bundle: {}\n", .{err});
        return err;
    };
    defer verify_bundle.deinit(allocator);

    var verify_response = github_client.performCapturedBrowserRequest(
        allocator,
        &verify_bundle.request,
        &sock,
        dst_ip,
        10000,
        "HTTP/2 browser verify HEADERS",
        "HTTP/2 browser verify DATA CHUNK",
    ) catch |err| blk: {
        if (err == error.ConnectionClosed) {
            std.debug.print("[VERIFY] GitHub transport was closed while waiting for the mailbox code; refreshing and retrying once...\n", .{});
            try refreshGitHubTransport(allocator, io, &github_client, &sock);
            break :blk try github_client.performCapturedBrowserRequest(
                allocator,
                &verify_bundle.request,
                &sock,
                dst_ip,
                10000,
                "HTTP/2 browser verify HEADERS",
                "HTTP/2 browser verify DATA CHUNK",
            );
        }
        std.debug.print("[VERIFY] FAILED: Email verification error: {}\n", .{err});
        std.process.exit(1);
    };
    defer verify_response.deinit(allocator);

    try network.extractCookiesFromHttp2Response(&verify_response, &github_client.cookie_jar);
    const verify_success = network.GitHubHttpClient.isAccountVerificationSuccessState(
        verify_response.status_code,
        verify_response.body,
    );

    if (verify_success) {
        std.debug.print("\n╔══════════════════════════════════════════════════════════╗\n", .{});
        std.debug.print("║           ACCOUNT VERIFIED — FULLY CREATED!              ║\n", .{});
        std.debug.print("║   Username: {s:<36}║\n", .{username});
        std.debug.print("║   Email:    {s:<36}║\n", .{email});
        std.debug.print("╚══════════════════════════════════════════════════════════╝\n", .{});
    } else {
        std.debug.print("[VERIFY] FAILED: Verification code was rejected by GitHub.\n", .{});
        std.debug.print("[VERIFY] Code attempted: {s}\n", .{github_code});
        std.process.exit(1);
    }

    // =========================================================================
    // ADIM 12: Safe Shutdown
    // =========================================================================
    std.debug.print("\n[SHUTDOWN] Initiating safe shutdown...\n", .{});
    std.debug.print("[SHUTDOWN] Firewall cleanup (defer removeRstSuppression)...\n", .{});
    std.debug.print("[SHUTDOWN] Socket cleanup (defer sock.deinit)...\n", .{});
    std.debug.print("[SHUTDOWN] Ghost Engine shutdown complete.\n", .{});
    std.debug.print("\n", .{});
}
