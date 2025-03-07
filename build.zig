const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dns_mod = b.createModule(.{
        .root_source_file = b.path("src/dns.zig"),
        .target = target,
        .optimize = optimize,
    });

    const dnsc_mod = b.createModule(.{
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .optimize = optimize,
    });

    const dnsd_mod = b.createModule(.{
        .root_source_file = b.path("src/server.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe_c = b.addExecutable(.{
        .name = "dnsc",
        .root_module = dnsc_mod,
    });

    b.installArtifact(exe_c);

    const run_cmd = b.addRunArtifact(exe_c);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run unit tests");
    inline for (.{ dns_mod, dnsc_mod, dnsd_mod }) |mod| {
        const tests = b.addTest(.{ .root_module = mod });
        const test_run = b.addRunArtifact(tests);
        test_step.dependOn(&test_run.step);
    }
}
