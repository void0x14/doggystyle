// Memory Safety Notes:
// - Zig's Debug mode (-ODebug) provides comprehensive bounds checking
// - All PacketWriter operations use std.debug.assert for overflow detection
// - std.heap.GeneralPurposeAllocator with safety enabled detects leaks
// - This is equivalent to ASAN/UBSan in Rust/C++ debug builds
//
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ghost_engine",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .zig_lib_dir = b.path("vendor/zig-std"),
    });

    // ZERO DEPENDENCY: No libpcap, no external C libraries
    // Only link system libc for basic system calls
    exe.root_module.linkSystemLibrary("c", .{});

    // Aggressive testing (ASAN-like behavior) achieved through default Debug zig bounds-checks and GPA.

    b.installArtifact(exe);

    // Setup Fuzzing / Unit Testing with strict std.testing mechanisms
    const test_exe = b.addTest(.{
        .name = "ghost_engine_tests",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/network_core.zig"),
            .target = target,
            .optimize = optimize,
        }),
        .zig_lib_dir = b.path("vendor/zig-std"),
    });

    // ZERO DEPENDENCY: Test executable also has no external dependencies
    test_exe.root_module.linkSystemLibrary("c", .{});

    const test_step = b.step("test", "Run rigorous unit and fuzz tests");
    // FIX: Use vendor Zig binary (0.16.0-dev.3132) instead of system Zig.
    // addRunArtifact on test binaries in Zig 0.16-dev injects --listen=- which causes
    // the test runner to hang waiting for IPC on stdin/stdout.
    const vendor_zig = b.pathFromRoot("vendor/zig/zig");
    const test_run = b.addSystemCommand(&.{
        vendor_zig,      "test",           "src/network_core.zig",
        "--zig-lib-dir", "vendor/zig-std", "-lc",
    });
    test_run.has_side_effects = true;
    test_step.dependOn(&test_run.step);

    // Module 2.2: HTTP/2 core tests
    const http2_test_run = b.addSystemCommand(&.{
        vendor_zig,      "test",           "src/http2_core.zig",
        "--zig-lib-dir", "vendor/zig-std", "-lc",
    });
    http2_test_run.has_side_effects = true;
    test_step.dependOn(&http2_test_run.step);

    // Module 3.3: Stealth Browser Initialization tests
    const browser_init_test_run = b.addSystemCommand(&.{
        vendor_zig,      "test",           "src/browser_init.zig",
        "--zig-lib-dir", "vendor/zig-std", "-lc",
    });
    browser_init_test_run.has_side_effects = true;
    test_step.dependOn(&browser_init_test_run.step);

    // Module 4: Browser Bridge (Chrome stdout interceptor) tests
    const browser_bridge_test_run = b.addSystemCommand(&.{
        vendor_zig,      "test",           "src/browser_bridge.zig",
        "--zig-lib-dir", "vendor/zig-std", "-lc",
    });
    browser_bridge_test_run.has_side_effects = true;
    test_step.dependOn(&browser_bridge_test_run.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    } else {
        // Default interface if no args provided
        run_cmd.addArg("enp37s0");
    }

    const run_step = b.step("run", "Run the ghost engine");
    run_step.dependOn(&run_cmd.step);

    // Convenience: zig build run -- <interface>
    // Or with default: zig build run
}
