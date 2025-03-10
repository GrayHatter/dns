pub fn main() !void {
    const a = std.heap.page_allocator;
    var argsi = std.process.args();
    while (argsi.next()) |arg| {
        _ = arg;
    }

    const addr: std.net.Address = .{ .in = .{ .sa = .{
        .port = @byteSwap(@as(u16, 53)),
        .addr = std.mem.readInt(u32, &[4]u8{ 127, 0, 0, 1 }, .little),
    } } };
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    const bind = try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
    _ = bind;

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

    var src_addr: std.net.Address = .{ .any = undefined };
    var src_len: u32 = 0;

    var buffer: [1024]u8 = undefined;
    const icnt = try std.posix.recvfrom(sock, &buffer, 0, &src_addr.any, &src_len);
    if (icnt >= 512) {
        @panic("packet too large");
    }
    std.debug.print("received {}\n", .{icnt});
    std.debug.print("data {any}\n", .{buffer[0..icnt]});

    const msg = try DNS.Message.fromBytes(a, buffer[0..icnt]);
    std.debug.print("data {any}\n", .{msg});

    std.debug.print("done\n", .{});
}

const Upstream = struct {
    sock: std.posix.socket_t,

    pub fn init() Upstream {
        return .{
            .sock = undefined,
        };
    }
};

const DNS = @import("dns.zig");

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
