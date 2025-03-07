pub fn main() !void {
    const a = std.heap.page_allocator;
    std.debug.print("started\n", .{});

    const addr: std.net.Address = .{ .in = .{ .sa = .{
        .port = std.mem.nativeToBig(u16, 53),
        .addr = std.mem.bytesToValue(u32, &[4]u8{ 0, 0, 0, 0 }),
    } } };

    const msg = try DNS.Message.query(a, &[1][]const u8{"gr.ht."});
    var request: [1024]u8 = undefined;
    const msgsize = try msg.write(&request);

    std.debug.print("msg {}\n", .{msgsize});
    std.debug.print("data {any}\n", .{request[0..msgsize]});
    std.debug.print("data {s}\n", .{request[0..msgsize]});

    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());
    const ocnt = try std.posix.send(sock, request[0..msgsize], 0);
    std.debug.print("sent {}\n", .{ocnt});

    var buffer: [1024]u8 = undefined;
    const icnt = try std.posix.recv(sock, &buffer, 0);
    std.debug.print("received {}\n", .{icnt});
    std.debug.print("data {any}\n", .{buffer[0..icnt]});
    std.debug.print("data {s}\n", .{buffer[0..icnt]});

    std.debug.print("done\n", .{});
}

const DNS = @import("dns.zig");

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
