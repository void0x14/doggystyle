const std = @import("std");
const network = @import("network_core.zig");
const http2 = @import("http2_core.zig");
const jitter = @import("jitter_core.zig");
const digistallone = @import("digistallone.zig");

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

    // GitHub.com IP: 140.82.121.4
    const dst_ip: u32 = blk: {
        const octets = [_]u8{ 140, 82, 121, 4 };
        break :blk (@as(u32, octets[0]) << 24) |
            (@as(u32, octets[1]) << 16) |
            (@as(u32, octets[2]) << 8) |
            @as(u32, octets[3]);
    };

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
    var ts: std.posix.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    const now_ms: u32 = @intCast((@as(u64, @intCast(ts.sec)) * 1000) + (@as(u64, @intCast(ts.nsec)) / 1000000));
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
    // ADIM 11: BDA Telemetry Packaging & Risk Check Submission
    // =========================================================================
    std.debug.print("\n[BDA] Preparing Browser Data Analytics (BDA) payload...\n", .{});
    var env = try network.BrowserEnvironment.init(allocator, io);
    // Using realistic CachyOS/Ryzen specs to enforce "Low Risk"
    env.navigator.hardwareConcurrency = 16; // e.g., Ryzen 7
    env.navigator.deviceMemory = 32; // 32 GB RAM
    env.webgl.renderer = "AMD Radeon RX 7900 XTX (RADV NAVI31, LLVM 18.1.8, DRM 3.57, CachyOS)";

    const bda_payload = try network.encryptBda(allocator, &env);
    defer allocator.free(bda_payload);

    std.debug.print("[BDA] Encrypted payload generated ({d} bytes)\n", .{bda_payload.len});
    std.debug.print("[RISK CHECK] Sending POST to /signup_check/usage...\n", .{});

    const risk_status = try github_client.performRiskCheck(
        allocator,
        auth_token,
        bda_payload,
        &sock,
        dst_ip,
    );

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

    const signup_success = github_client.performSignup(
        allocator,
        response.body,
        username,
        email,
        password,
        &sock,
        dst_ip,
    ) catch |err| {
        if (err == error.UnexpectedChallenge) {
            std.debug.print("[FATAL] Unexpected Arkose Challenge triggered during signup submission!\n", .{});
            return err;
        }
        return err;
    };

    if (signup_success) {
        std.debug.print("[SUCCESS] Signup Form Submitted. Waiting for Redirect...\n", .{});
    } else {
        std.debug.print("[WARN] Signup did not redirect as expected.\n", .{});
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
