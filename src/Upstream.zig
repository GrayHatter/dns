conns: [4]Connection,
next: u8 = 0,

const Upstream = @This();

pub const Connection = struct {
    stream: net.Stream,
    reader: net.Stream.Reader,
    writer: net.Stream.Writer,
    r_buf: [4096]u8 = undefined,
    w_buf: [1024]u8 = undefined,
};

pub const Peer = struct {
    addr: Io.net.IpAddress,

    pub const cloudflare_0: Peer = .{ .addr = .{ .ip4 = .{ .bytes = .{ 1, 1, 1, 1 }, .port = 53 } } };
    pub const cloudflare_1: Peer = .{ .addr = .{ .ip4 = .{ .bytes = .{ 1, 0, 0, 1 }, .port = 53 } } };
    pub const google_0: Peer = .{ .addr = .{ .ip4 = .{ .bytes = .{ 8, 8, 8, 8 }, .port = 53 } } };
    pub const google_1: Peer = .{ .addr = .{ .ip4 = .{ .bytes = .{ 8, 8, 4, 4 }, .port = 53 } } };
};

pub const peers: [4]Peer = .{
    .cloudflare_0,
    .cloudflare_1,
    .google_0,
    .google_1,
};

pub fn init(up: *Upstream, io: Io) !void {
    for (&up.conns, peers) |*stream, peer| {
        const stream_fd = try peer.addr.connect(io, .{ .mode = .dgram, .protocol = .udp });
        stream.* = .{
            .stream = stream_fd,
            .reader = stream_fd.reader(io, &stream.r_buf),
            .writer = stream_fd.writer(io, &stream.w_buf),
        };
    }
}

pub fn get(up: *Upstream) struct { *const Peer, *Connection } {
    var next = @atomicLoad(u8, &up.next, .unordered);
    while (true) {
        if (@cmpxchgWeak(
            u8,
            &up.next,
            next,
            @intCast((next + 1) % up.conns.len),
            .monotonic,
            .monotonic,
        )) |new| {
            next = new;
        } else {
            return .{ &peers[next], &up.conns[next] };
        }
    }
}

const std = @import("std");
const Io = std.Io;
const net = Io.net;
