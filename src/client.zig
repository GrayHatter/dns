pub fn main() !void {
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

    const upstream = try network.Peer.connect(nameserver, 53);

    var request: [1024]u8 = undefined;
    const msg = try DNS.Message.query(&[1][]const u8{domain orelse "gr.ht."}, &request);

    log.err("msg {}", .{msg.bytes.len});
    log.err("data {any}", .{request[0..msg.bytes.len]});
    log.err("data {s}", .{request[0..msg.bytes.len]});

    try upstream.send(request[0..msg.bytes.len]);

    var buffer: [1024]u8 = undefined;
    const icnt = try upstream.recv(&buffer);
    log.err("received {}", .{icnt});
    log.err("data {any}", .{buffer[0..icnt]});
    log.err("data {s}", .{buffer[0..icnt]});

    log.err("done", .{});
}

test main {
    _ = &main;
}

const DNS = @import("dns.zig");
const network = @import("network.zig");

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
