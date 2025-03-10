pub fn main() !void {
    const a = std.heap.page_allocator;
    std.debug.print("started\n", .{});

    var domain: ?[]const u8 = null;
    var nameserver: [4]u8 = @splat(0);
    var argsi = std.process.args();
    while (argsi.next()) |arg| {
        if (arg[0] == '@') {
            var itr = std.mem.splitScalar(u8, arg[1..], '.');
            for (&nameserver) |*n| {
                n.* = std.fmt.parseInt(u8, itr.next() orelse "0", 10) catch 0;
            }
        } else {
            domain = arg;
        }
    }

    const upstream = try DNS.Upstream.init(nameserver);

    const msg = try DNS.Message.query(a, &[1][]const u8{domain orelse "gr.ht."});
    var request: [1024]u8 = undefined;
    const msgsize = try msg.write(&request);

    std.debug.print("msg {}\n", .{msgsize});
    std.debug.print("data {any}\n", .{request[0..msgsize]});
    std.debug.print("data {s}\n", .{request[0..msgsize]});

    try upstream.send(request[0..msgsize]);

    var buffer: [1024]u8 = undefined;
    const icnt = try upstream.recv(&buffer);
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
