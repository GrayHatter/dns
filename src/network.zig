pub const Peer = struct {
    addr: std.net.Address,
    sock: std.posix.socket_t,

    const Options = struct {
        recv_timeout_us: ?u32 = null,
    };

    /// TODO ipv6
    pub fn init(addr_ip: [4]u8, port: u16) !Peer {
        const up: Peer = .{
            .addr = .{ .in = .{ .sa = .{
                .port = nativeToBig(u16, port),
                .addr = bytesToValue(u32, &addr_ip),
            } } },
            .sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0),
        };
        return up;
    }

    pub fn connectOptions(addr_ip: [4]u8, port: u16, opts: Options) !Peer {
        const up: Peer = try .init(addr_ip, port);
        try std.posix.connect(up.sock, &up.addr.any, up.addr.getOsSockLen());
        if (opts.recv_timeout_us) |rcvto| {
            try std.posix.setsockopt(
                up.sock,
                sys.SOCKET,
                sys.RCVTIMEO,
                asBytes(&sys.timeval{ .sec = 0, .usec = rcvto }),
            );
        }
        return up;
    }

    pub fn connect(addr_ip: [4]u8, port: u16) !Peer {
        return try connectOptions(addr_ip, port, .{ .recv_timeout_us = 800000 });
    }

    pub fn listen(addr_ip: [4]u8, port: u16) !Peer {
        const up: Peer = try .init(addr_ip, port);
        try std.posix.bind(up.sock, &up.addr.any, up.addr.getOsSockLen());
        return up;
    }

    pub fn send(upstrm: Peer, data: []const u8) !void {
        const cnt = try std.posix.send(upstrm.sock, data, 0);
        if (cnt != data.len) return error.TxFailed;
    }

    pub fn sendTo(upstrm: Peer, addr: std.net.Address, data: []const u8) !void {
        const cnt = try std.posix.sendto(upstrm.sock, data, 0, &addr.any, addr.getOsSockLen());
        if (cnt != data.len) return error.TxFailed;
    }

    pub fn recv(upstrm: Peer, buffer: []u8) !usize {
        if (buffer.len < 512) return error.BufferTooSmall;
        const icnt = try std.posix.recv(upstrm.sock, buffer, 0);
        return icnt;
    }

    pub fn recvFrom(upstrm: Peer, buffer: []u8, addr: *std.net.Address) !usize {
        if (buffer.len < 512) return error.BufferTooSmall;
        var src_len: u32 = addr.getOsSockLen();
        const cnt = try std.posix.recvfrom(upstrm.sock, buffer, 0, &addr.any, &src_len);
        if (cnt >= 512) {
            @panic("packet too large");
        }
        return cnt;
    }

    pub fn format(peer: Peer, w: *Writer) !void {
        const a: *const [4]u8 = @ptrCast(&peer.addr.in.sa.addr);
        try w.print("{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] });
    }
};

const std = @import("std");
const sys = struct {
    const timeval = std.os.linux.timeval;
    const SOCKET = std.os.linux.SOL.SOCKET;
    const RCVTIMEO = std.os.linux.SO.RCVTIMEO;
};
const asBytes = std.mem.asBytes;
const nativeToBig = std.mem.nativeToBig;
const bytesToValue = std.mem.bytesToValue;
const Writer = std.Io.Writer;
