pub fn main() !void {
    log.err("started", .{});

    var threaded: std.Io.Threaded = .init_single_threaded;
    defer threaded.deinit();
    const io = threaded.io();

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

    const addr: net.IpAddress = .{ .ip4 = .{ .bytes = nameserver, .port = 53 } };
    const upstream: net.Stream = try addr.connect(io, .{ .mode = .dgram, .protocol = .udp });

    var request: [1024]u8 = undefined;
    const msg = try DNS.Message.query(&[1][]const u8{domain orelse "gr.ht."}, &request);

    log.err("msg {}", .{msg.bytes.len});
    log.err("data {any}", .{request[0..msg.bytes.len]});
    log.err("data {s}", .{request[0..msg.bytes.len]});

    var w_b: [512]u8 = undefined;
    var w = upstream.writer(io, &w_b);
    var r_b: [512]u8 = undefined;
    var r = upstream.reader(io, &r_b);

    try w.interface.writeAll(request[0..msg.bytes.len]);

    try r.interface.fillMore();
    const buffer = r.interface.buffered();
    log.err("received {}", .{buffer.len});
    log.err("data {any}", .{buffer});
    log.err("data {s}", .{buffer});

    log.err("done", .{});
}

test main {
    _ = &main;
}

const DNS = @import("dns.zig");

const std = @import("std");
const Io = std.Io;
const net = Io.net;
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
