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

    // Platform-specific linking
    if (target.result.os.tag == .windows) {
        // Npcap (wpcap.lib) - assumes Npcap SDK installed
        exe.root_module.linkSystemLibrary("wpcap", .{});
        exe.root_module.linkSystemLibrary("c", .{});
    } else if (target.result.os.tag == .linux) {
        // No extra libraries for AF_PACKET
        exe.root_module.linkSystemLibrary("c", .{});
    }

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the ghost engine");
    run_step.dependOn(&run_cmd.step);
}
