const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dns_mod = b.createModule(.{
        .root_source_file = b.path("src/dns.zig"),
        .target = target,
        .optimize = optimize,
    });

    const client_mod = b.createModule(.{
        .root_source_file = b.path("src/client.zig"),
        .target = target,
        .optimize = optimize,
    });

    const daemon_mod = b.createModule(.{
        .root_source_file = b.path("src/server.zig"),
        .target = target,
        .optimize = optimize,
    });

    const client = b.addExecutable(.{ .name = "dnsc", .root_module = client_mod });
    b.installArtifact(client);

    const run_cmd = b.addRunArtifact(client);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run unit tests");
    inline for (.{ dns_mod, client_mod, daemon_mod }) |mod| {
        const tests = b.addTest(.{ .root_module = mod });
        const test_run = b.addRunArtifact(tests);
        test_step.dependOn(&test_run.step);
    }
}
