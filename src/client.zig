pub fn main() !void {
    const a = std.heap.page_allocator;
    log.err("started", .{});

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

    const upstream = try DNS.Peer.connect(nameserver, 53);

    const msg = try DNS.Message.query(a, &[1][]const u8{domain orelse "gr.ht."});
    var request: [1024]u8 = undefined;
    const msgsize = try msg.write(&request);

    log.err("msg {}", .{msgsize});
    log.err("data {any}", .{request[0..msgsize]});
    log.err("data {s}", .{request[0..msgsize]});

    try upstream.send(request[0..msgsize]);

    var buffer: [1024]u8 = undefined;
    const icnt = try upstream.recv(&buffer);
    log.err("received {}", .{icnt});
    log.err("data {any}", .{buffer[0..icnt]});
    log.err("data {s}", .{buffer[0..icnt]});

    log.err("done", .{});
}

const DNS = @import("dns.zig");

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
