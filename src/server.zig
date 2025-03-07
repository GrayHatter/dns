pub fn server() !void {
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.SOCK.NONBLOCK);

    const addr: std.net.Address = .{ .in = .{ .sa = .{
        .port = 53,
        .addr = 0,
    } } };
    const bind = try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
    _ = bind;

    const buffer: [1024]u8 = undefined;
    const icnt = try std.posix.recv(sock, &buffer, 0);
    std.debug.print("sent {}\n", .{icnt});
}

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
