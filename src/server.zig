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
    if (msg.questions) |q| a.free(q);
    if (msg.answers) |an| a.free(an);

    std.debug.print("data {any}\n", .{msg});

    std.debug.print("done\n", .{});
}

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
