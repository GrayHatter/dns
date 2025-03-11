fn usage() !void {}

pub fn main() !void {
    const a = std.heap.page_allocator;

    var blocks: ?[]const u8 = null;
    var blocked_ips: std.ArrayListUnmanaged([4]u8) = .{};

    var argv = std.process.args();
    while (argv.next()) |arg| {
        if (std.mem.eql(u8, arg, "--block")) {
            blocks = argv.next() orelse @panic("invalid argv --block");
        }
        if (std.mem.eql(u8, arg, "--drop-ip")) {
            const ip_str = argv.next() orelse @panic("invalid argv --drop-ip");
            var ip: [4]u8 = undefined;
            var itr = std.mem.splitScalar(u8, ip_str, '.');
            for (&ip) |*oct| {
                oct.* = std.fmt.parseInt(u8, itr.next() orelse "0", 10) catch 0;
            }
            try blocked_ips.append(a, ip);
        }
    }

    const downstream: DNS.Peer = try .listen(.{ 127, 0, 0, 1 }, 53);

    // nobody on my machine
    if (std.os.linux.getuid() == 0) {
        log.err("dropping root", .{});
        _ = try std.posix.setgid(99);
        _ = try std.posix.setuid(99);
    }

    log.err("started", .{});

    var cache: DNS.Cache = .{
        .tld = .{},
    };

    try cache.tld.put(a, "com", .{ .domain = .{} });
    try cache.tld.put(a, "ht", .{ .domain = .{} });

    if (blocks) |b| {
        a.free(try parse(a, b));
    }

    var upconns: [4]DNS.Peer = undefined;
    for (&upconns, upstreams) |*dst, ip| {
        dst.* = try .connect(ip, 53);
    }
    var up_idx: u2 = 0;

    //const msg = try DNS.Message.query(a, &[1][]const u8{domain orelse "gr.ht."});
    //var request: [1024]u8 = undefined;
    //const msgsize = try msg.write(&request);

    while (true) {
        var addr: std.net.Address = .{ .in = .{ .sa = .{ .port = 0, .addr = 0 } } };
        var buffer: [1024]u8 = undefined;
        const icnt = try downstream.recvFrom(&buffer, &addr);
        log.err("received {}", .{icnt});
        //log.err("data {any}", .{buffer[0..icnt]});
        log.err("received from {any}", .{addr.in});

        const msg = try DNS.Message.fromBytes(a, buffer[0..icnt]);
        //log.err("data {any}", .{msg});
        // defer once in loop
        if (msg.questions) |q| a.free(q);
        if (msg.answers) |an| a.free(an);

        log.err("bounce", .{});
        up_idx +%= 1;
        try upconns[up_idx].send(buffer[0..icnt]);
        var relay_buf: [1024]u8 = undefined;
        const b_cnt = try upconns[up_idx].recv(&relay_buf);
        log.err("bounce received {}", .{b_cnt});
        log.err("bounce data {any}", .{relay_buf[0..b_cnt]});

        for (blocked_ips.items) |banned| {
            if (std.mem.eql(u8, relay_buf[b_cnt - 4 .. b_cnt], &banned)) {
                @memset(relay_buf[b_cnt - 4 .. b_cnt], 0);
            }
        }

        try downstream.sendTo(addr, relay_buf[0..b_cnt]);
        log.err("responded", .{});
    }

    log.err("done", .{});
}

const upstreams: [4][4]u8 = .{
    .{ 1, 1, 1, 1 },
    .{ 1, 0, 0, 1 },
    .{ 8, 8, 8, 8 },
    .{ 8, 8, 4, 4 },
};

fn parseLine(line: []const u8) ![]const u8 {
    if (line[0] == '#') return error.Skip;
    return line;
}

fn parse(a: Allocator, filename: []const u8) ![][]const u8 {
    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();
    const fsize = try file.getEndPos();
    // 21 bytes per line for the test file
    const base_count = fsize / 21;
    var reader = file.reader();
    var list = try std.ArrayListUnmanaged([]const u8).initCapacity(a, base_count);
    errdefer list.clearAndFree(a);
    var lbuf: [1024]u8 = undefined;

    while (try reader.readUntilDelimiterOrEof(&lbuf, '\n')) |line| {
        try list.append(a, parseLine(line) catch continue);
    }

    return try list.toOwnedSlice(a);
}

test main {
    _ = &main;
}

const DNS = @import("dns.zig");

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
