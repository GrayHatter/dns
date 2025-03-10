pub fn main() !void {
    const a = std.heap.page_allocator;
    var argsi = std.process.args();
    while (argsi.next()) |arg| {
        _ = arg;
    }

    const downstream: DNS.Peer = try .listen(.{ 127, 0, 0, 1 }, 53);

    // nobody on my machine
    if (std.os.linux.getuid() == 0) {
        std.debug.print("dropping root\n", .{});
        _ = try std.posix.setgid(99);
        _ = try std.posix.setuid(99);
    }

    std.debug.print("started\n", .{});

    //const msg = try DNS.Message.query(a, &[1][]const u8{domain orelse "gr.ht."});
    //var request: [1024]u8 = undefined;
    //const msgsize = try msg.write(&request);

    var addr: std.net.Address = .{ .any = undefined };
    var buffer: [1024]u8 = undefined;
    const icnt = try downstream.recvFrom(&buffer, &addr);
    std.debug.print("received {}\n", .{icnt});
    std.debug.print("data {any}\n", .{buffer[0..icnt]});

    const msg = try DNS.Message.fromBytes(a, buffer[0..icnt]);
    std.debug.print("data {any}\n", .{msg});

    std.debug.print("done\n", .{});
}

const DNS = @import("dns.zig");

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
