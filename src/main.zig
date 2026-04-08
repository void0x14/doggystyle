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
///   6. HTTP/2 HEADERS Frame (HPACK Literal, H=0)
///   7. GitHubHttpClient with real socket + TlsSession
///   8. Mailbox Polling (digistallone.DigistalloneClient)
///   9. Safe Shutdown + Resource Cleanup
///
/// KULLANIM:
///   sudo ./zig-out/bin/ghost_engine [interface|ip] [dest_ip] [dest_port]
///
/// NOT: Raw socket için root yetkisi gereklidir.
pub fn main() !void {
    const allocator = std.heap.page_allocator;

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
    // ADIM 3: Interface + Destination Resolution
    // =========================================================================
    const iface_name = try network.resolveLinuxInterface(allocator, null);
    defer allocator.free(iface_name);

    const target_host = "github.com";
    const target_port: u16 = 443;

    // GitHub.com IP: 140.82.121.4
    const dst_ip: u32 = blk: {
        const octets = [_]u8{ 140, 82, 121, 4 };
        break :blk (@as(u32, octets[0]) << 24) |
            (@as(u32, octets[1]) << 16) |
            (@as(u32, octets[2]) << 8) |
            @as(u32, octets[3]);
    };

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

    // io placeholder (future async I/O)
    const io: std.Io = undefined;

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
    defer {} // sock is borrowed, deinit handled above

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
    // ADIM 9: HTTP/2 HPACK Header Preparation
    // =========================================================================
    std.debug.print("\n", .{});
    std.debug.print("[HTTP/2] Building HPACK header block (Literal, H=0)...\n", .{});

    const request_path = "/login";
    const hpack_block = try http2.buildGitHubHeaders(allocator, request_path, target_host, true);
    defer allocator.free(hpack_block);

    std.debug.print("[HPACK] Block: {d} bytes\n", .{hpack_block.len});

    const headers_frame = try http2.packInHeadersFrame(allocator, hpack_block, 1);
    defer allocator.free(headers_frame);

    std.debug.print("[HTTP/2] HEADERS frame: {d} bytes (stream_id=1, flags=0x05)\n", .{
        headers_frame.len,
    });

    // =========================================================================
    // ADIM 10: GitHubHttpClient with Real Socket + Session
    // =========================================================================
    std.debug.print("\n", .{});
    std.debug.print("[GITHUB] Initializing GitHubHttpClient with real handshake state...\n", .{});

    const github_client = network.GitHubHttpClient.initFromHandshake(
        target_host,
        target_port,
        handshake.sock_fd,
        handshake.tls_session,
        handshake.src_ip,
        handshake.dst_ip,
        handshake.src_port,
        handshake.dst_port,
        handshake.client_seq,
        handshake.server_seq,
        handshake.client_tsval,
        handshake.server_tsval,
    );

    std.debug.print("[GITHUB] Client initialized:\n", .{});
    std.debug.print("[GITHUB]   sock_fd: {d}\n", .{github_client.sock_fd.?});
    std.debug.print("[GITHUB]   src_port: {d}, dst_port: {d}\n", .{
        github_client.src_port,
        github_client.dst_port,
    });
    std.debug.print("[GITHUB]   client_seq: {d}, server_seq: {d}\n", .{
        github_client.client_seq,
        github_client.server_seq,
    });

    // =========================================================================
    // ADIM 11: Cookie Jar State
    // =========================================================================
    std.debug.print("\n", .{});
    std.debug.print("[COOKIES] Jar state: user_session={d}, host_session={d}, gh_sess={d}\n", .{
        github_client.cookie_jar.user_session_len,
        github_client.cookie_jar.host_user_session_len,
        github_client.cookie_jar.gh_sess_len,
    });

    // =========================================================================
    // ADIM 12: Layer Trace Summary
    // =========================================================================
    std.debug.print("\n", .{});
    std.debug.print("╔══════════════════════════════════════════════════════════╗\n", .{});
    std.debug.print("║              LAYER TRACE SUMMARY                        ║\n", .{});
    std.debug.print("╚══════════════════════════════════════════════════════════╝\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("[Layer 1 (Network)]     Raw socket fd={d}, iface={s}, ephemeral={d}\n", .{
        sock.fd, iface_name, src_port,
    });
    std.debug.print("[Layer 2 (TLS)]         TLS 1.3 session active (cipher=0x{x:04}, seq_send={d})\n", .{
        handshake.cipher_suite, handshake.tls_session.seq_send,
    });
    std.debug.print("[Layer 3 (HTTP/2)]      HEADERS frame ready (HPACK Literal, H=0, {d} bytes)\n", .{
        headers_frame.len,
    });
    std.debug.print("[Layer 4 (Logic)]       GET {s} prepared (GitHubHttpClient wired)\n", .{request_path});
    std.debug.print("\n", .{});

    // =========================================================================
    // ADIM 13: Mailbox Controller (Digistallone) Metadata
    // =========================================================================
    std.debug.print("[MAILBOX] Digistallone metadata: {d} domains, poll_interval={d}ms\n", .{
        digistallone.DEFAULT_DOMAINS_COUNT,
        digistallone.DEFAULT_POLL_INTERVAL_MS,
    });
    std.debug.print("[MAILBOX] Target: {s}:{d} (Livewire v3 over TLS 1.3)\n", .{
        digistallone.DIGISTALLONE_IP,
        digistallone.DIGISTALLONE_PORT,
    });

    // NOTE: DigistalloneClient.init() std.Io.Event gerektirir.
    // Production'da async I/O loop içinde pollInboxForGitHubCode() çağrılır.
    // Bu sequenced execution'da metadata gösteriliyor, gerçek polling
    // GitHub response alındıktan sonra tetiklenir.

    std.debug.print("\n", .{});
    std.debug.print("[WIRE-TRUTH] All modules connected. Real handshake complete.\n", .{});
    std.debug.print("[WIRE-TRUTH] TCP+TLS 1.3 handshake verified (cipher=0x{x:04})\n", .{handshake.cipher_suite});
    std.debug.print("[WIRE-TRUTH] HTTP/2 HPACK engine wired (Module 2.3 → network_core → main)\n", .{});
    std.debug.print("[WIRE-TRUTH] GitHubHttpClient wired with real socket + TlsSession\n", .{});
    std.debug.print("\n", .{});

    // =========================================================================
    // ADIM 14: Safe Shutdown
    // =========================================================================
    std.debug.print("[SHUTDOWN] Initiating safe shutdown...\n", .{});
    std.debug.print("[SHUTDOWN] Firewall cleanup (defer removeRstSuppression)...\n", .{});
    std.debug.print("[SHUTDOWN] Socket cleanup (defer sock.deinit)...\n", .{});
    std.debug.print("[SHUTDOWN] Ghost Engine shutdown complete.\n", .{});
    std.debug.print("\n", .{});
}
