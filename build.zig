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
            .root_source_file = b.path("src/network_core.zig"),
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
    const test_run = b.addRunArtifact(test_exe);
    test_step.dependOn(&test_run.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the ghost engine");
    run_step.dependOn(&run_cmd.step);
}
