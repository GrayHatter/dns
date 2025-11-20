pub const Label = struct {
    len: u6,
    name: []const u8,

    pub const Packed = struct {
        offset: usize,
        str: []const u8,
        rest: ?u16 = null,
    };

    pub fn init(a: Allocator, name: []const u8) ![]Label {
        const label = try a.alloc(Label, std.mem.count(u8, name, "."));
        var itr = std.mem.splitScalar(u8, name, '.');
        for (label) |*l| {
            const n = itr.next().?;
            l.* = .{
                .len = @intCast(n.len),
                .name = n,
            };
        }
        return label;
    }

    pub fn getName(buffer: []u8, r: *Reader) ![]u8 {
        var name: ArrayList(u8) = .{
            .items = buffer,
            .capacity = buffer.len,
        };
        name.items.len = 0;
        const origin: usize = r.seek;
        var idx: usize = r.seek;
        var in_pointer: bool = false;
        sw: switch (try r.peekByte()) {
            0 => {
                if (!in_pointer) r.seek = idx + 1;
                if (r.seek < origin) return error.CorruptLabel;
                return name.items;
            },
            1...63 => |b| {
                idx += b + 1;
                if (idx >= r.buffer.len) return error.InvalidLabel;
                try name.appendSliceBounded(r.buffer[idx - b .. idx]);
                try name.appendBounded('.');
                continue :sw r.buffer[idx];
            },
            192...255 => |b| {
                if (!in_pointer) r.seek = idx + 2;
                if (r.seek < origin) return error.CorruptLabel;
                in_pointer = true;
                idx += 2;
                if (idx >= r.buffer.len) return error.InvalidLabel;
                const offset: u16 = @as(u16, b & 0b111111) << 8 | r.buffer[idx - 1];
                if (offset < 12 or offset >= r.buffer.len) return error.InvalidLabel;
                idx = offset;
                continue :sw r.buffer[idx];
            },
            else => return error.InvalidLabel,
        }
        @panic("unreachable");
    }

    pub fn writeName(name: []const u8, w: *Writer) !usize {
        //std.debug.assert(name.len > 0);
        if (name.len == 0) {
            try w.writeByte(0);
            return 1;
        }
        var len: usize = 0;
        var itr = std.mem.splitScalar(u8, name, '.');
        while (itr.next()) |n| {
            std.debug.assert(n.len <= 63);
            try w.writeByte(@intCast(n.len));
            try w.writeAll(n);
            len += n.len + 1;
        }
        if (name[name.len - 1] != '.') {
            try w.writeByte(0);
            len += 1;
        }

        return len;
    }

    test writeName {
        var buffer: [512]u8 = undefined;
        var w: Writer = .fixed(&buffer);

        try std.testing.expectEqual(try writeName("gr.ht", &w), 7);
        try std.testing.expectEqual(try writeName("gr.ht.", &w), 7);
    }

    pub fn write(l: Label, w: *Writer) !void {
        try w.writeByte(l.len);
        try w.writeAll(l.name);
    }
};

pub const Message = @import("Message.zig");

test "Message.Header" {
    const thing: Message.Header = .{
        .id = 16,
        .qr = .query,
        .opcode = 0,
        .aa = true,
        .tc = false,
        .rd = false,
        .ra = false,
        .rcode = .success,
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };

    try std.testing.expectEqual(
        @as(u96, 19361702579765545376153600),
        @as(u96, @bitCast(thing)),
    );
}

test "build pkt" {
    var buffer: [23]u8 = undefined;
    const msg = try Message.query(&[1][]const u8{"gr.ht."}, &buffer);
    try std.testing.expectEqual(msg.bytes.len, 23);

    try std.testing.expectEqualSlices(
        u8,
        &[23]u8{
            122, 105, 1,   0, 0,   1,   0, 0, 0, 0, 0, 0,
            2,   103, 114, 2, 104, 116, 0, 0, 1, 0, 1,
        },
        buffer[0..23],
    );
}

test "build pkt non-fqdn" {
    var buffer: [23]u8 = undefined;
    const msg = try Message.query(&[1][]const u8{"gr.ht"}, &buffer);
    try std.testing.expectEqual(msg.bytes.len, 23);

    try std.testing.expectEqualSlices(
        u8,
        &[23]u8{
            122, 105, 1,   0, 0,   1,   0, 0, 0, 0, 0, 0,
            2,   103, 114, 2, 104, 116, 0, 0, 1, 0, 1,
        },
        buffer[0..23],
    );
}

test "build answer" {
    var buffer: [39]u8 = undefined;

    const msg0 = try Message.answer(
        31337,
        &[1]Message.AnswerData{
            .{ .fqdn = "gr.ht.", .ips = &[1]Message.Resource.RData{.{ .a = .{ 127, 4, 20, 69 } }} },
        },
        &buffer,
    );

    try std.testing.expectEqualSlices(u8, &[_]u8{
        122, 105, 129, 128, 0,   1,   0, 1, 0,  0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0, 1,  0, 1, 192,
        12,  0,   1,   0,   1,   0,   0, 1, 44, 0, 4, 127,
        4,   20,  69,
    }, &buffer);
    try std.testing.expectEqual(msg0.header.qdcount, 1);
    try std.testing.expectEqual(msg0.header.ancount, 1);

    const msg1 = try Message.answer(
        31337,
        &[1]Message.AnswerData{
            .{ .fqdn = "gr.ht.", .ips = &[1]Message.Resource.RData{.{ .a = .{ 127, 4, 20, 69 } }} },
        },
        &buffer,
    );

    try std.testing.expectEqualSlices(u8, &[_]u8{
        122, 105, 129, 128, 0,   1,   0, 1, 0,  0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0, 1,  0, 1, 192,
        12,  0,   1,   0,   1,   0,   0, 1, 44, 0, 4, 127,
        4,   20,  69,
    }, &buffer);
    try std.testing.expectEqual(msg1.header.qdcount, 1);
    try std.testing.expectEqual(msg1.header.ancount, 1);

    var big_buffer: [100]u8 = undefined;

    const msg2 = try Message.answer(
        31337,
        &[1]Message.AnswerData{
            .{ .fqdn = "gr.ht.", .ips = &[1]Message.Resource.RData{.{ .a = .{ 127, 4, 20, 69 } }} },
        },
        &big_buffer,
    );
    try std.testing.expectEqualSlices(u8, &[_]u8{
        122, 105, 129, 128, 0,   1,   0, 1, 0,  0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0, 1,  0, 1, 192,
        12,  0,   1,   0,   1,   0,   0, 1, 44, 0, 4, 127,
        4,   20,  69,
    }, msg2.bytes);
}

test "response iter" {
    {
        const base = [_]u8{
            197, 22,  129, 128, 0,   1,   0,   1,   0,   0,   0,   0,
            7,   122, 105, 103, 108, 97,  110, 103, 3,   111, 114, 103,
            0,   0,   28,  0,   1,   192, 12,  0,   28,  0,   1,   0,
            0,   1,   44,  0,   16,  42,  1,   4,   249, 48,  81,  75,
            210, 0,   0,   0,   0,   0,   0,   0,   2,
        };
        const msg: Message = try .fromBytes(&base);
        var it = msg.iterator();
        try std.testing.expectEqual(msg.header.qdcount, 1);
        try std.testing.expectEqual(msg.header.ancount, 1);
        var count: usize = 2;
        while (try it.next()) |r| {
            switch (r) {
                .question => try std.testing.expectEqual(count, 2),
                .answer => try std.testing.expectEqual(count, 1),
            }
            count -%= 1;
        }

        try std.testing.expectEqual(count, 0);
    }
    {
        const base = [_]u8{
            242, 38,  129, 128, 0,   1,   0,   4,   0,   1,   0,   0,   3,
            110, 110, 110, 9,   110, 100, 110, 110, 101, 110, 101, 110, 110,
            3,   99,  110, 109, 0,   0,   28,  0,   1,   192, 12,  0,   5,
            0,   1,   0,   0,   11,  214, 0,   25,  17,  110, 110, 110, 45,
            110, 105, 110, 110, 101, 110, 101, 110, 110, 45,  99,  110, 109,
            4,   103, 110, 108, 98,  192, 16,  192, 47,  0,   5,   0,   1,
            0,   0,   11,  214, 0,   32,  14,  50,  45,  48,  49,  45,  51,
            55,  45,  50,  45,  45,  45,  49,  56,  3,   99,  100, 120, 7,
            99,  45,  45,  45,  45,  105, 110, 3,   110, 101, 110, 0,   192,
            84,  0,   5,   0,   1,   0,   0,   0,   32,  0,   28,  3,   110,
            110, 110, 9,   110, 105, 110, 110, 101, 110, 100, 110, 110, 3,
            99,  110, 100, 7,   100, 100, 100, 100, 100, 100, 120, 192, 111,
            192, 128, 0,   5,   0,   1,   0,   0,   83,  84,  0,   21,  5,
            101, 54,  52,  52,  57,  1,   97,  10,  97,  107, 97,  109, 97,
            105, 101, 100, 103, 101, 192, 111, 192, 174, 0,   6,   0,   1,
            0,   0,   2,   220, 0,   46,  3,   110, 48,  97,  192, 176, 10,
            104, 110, 110, 110, 109, 97,  110, 110, 101, 110, 6,   97,  107,
            97,  109, 97,  105, 192, 26,  103, 212, 110, 234, 0,   0,   3,
            232, 0,   0,   3,   232, 0,   0,   3,   232, 0,   0,   7,   8,
        };
        const msg: Message = try .fromBytes(&base);
        var it = msg.iterator();
        try std.testing.expectEqual(msg.header.qdcount, 1);
        try std.testing.expectEqual(msg.header.ancount, 4);
        try std.testing.expectEqual(msg.header.arcount, 0);
        try std.testing.expectEqual(msg.header.nscount, 1);
        var count: usize = 6;
        while (try it.next()) |r| {
            switch (r) {
                .question => try std.testing.expectEqual(count, 6),
                .answer => try std.testing.expect(count <= 5),
            }
            count -%= 1;
        }

        try std.testing.expectEqual(count, 0);
    }

    {
        const base = [_]u8{
            97,  83,  129, 128, 0,   1,   0,   14,  0,   0,   0,   1,
            9,   112, 101, 111, 112, 108, 101, 45,  112, 97,  10,  103,
            111, 111, 103, 108, 101, 97,  112, 105, 115, 3,   99,  111,
            109, 0,   0,   1,   0,   1,
            // zig fmt: off
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 251,  32,  42,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 250, 189, 234,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 251,  46, 202,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 250,  72, 202,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 251,  46, 234,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 251, 214, 138,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 172, 217,  12, 106,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 250, 189, 202,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 250, 191,  42,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 250, 191,  74,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 250, 189, 170,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 172, 217, 164, 106,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 250, 188,  10,
            192,  12,  0, 1, 0, 1, 0, 0, 0, 58, 0, 4, 142, 251,  46, 170,
              0,   0, 41, 2, 0, 0, 0, 128, 0, 0, 0,
          };
        // zig fmt: on
        const msg: Message = try .fromBytes(&base);
        var it = msg.iterator();
        try std.testing.expectEqual(msg.header.qdcount, 1);
        try std.testing.expectEqual(msg.header.ancount, 14);
        try std.testing.expectEqual(msg.header.arcount, 1);
        try std.testing.expectEqual(msg.header.nscount, 0);
        var count: usize = 16;
        while (try it.next()) |r| {
            switch (r) {
                .question => try std.testing.expectEqual(count, 16),
                .answer => try std.testing.expect(count <= 15),
            }
            count -%= 1;
        }

        try std.testing.expectEqual(count, 0);
    }

    { // RFC9460
        const base = [_]u8{
            212, 149, 129, 128, 0,   1,   0, 1,   0,   0,   0,   0,
            5,   102, 111, 110, 116, 115, 7, 103, 115, 116, 97,  116,
            105, 99,  3,   99,  111, 109, 0, 0,   65,  0,   1,   192,
            12,  0,   65,  0,   1,   0,   0, 50,  227, 0,   13,  0,
            1,   0,   0,   1,   0,   6,   2, 104, 50,  2,   104, 51,
        };
        const msg: Message = try .fromBytes(&base);
        var it = msg.iterator();
        try std.testing.expectEqual(msg.header.qdcount, 1);
        try std.testing.expectEqual(msg.header.ancount, 1);
        try std.testing.expectEqual(msg.header.arcount, 0);
        try std.testing.expectEqual(msg.header.nscount, 0);
        var count: usize = 2;
        while (try it.next()) |r| {
            switch (r) {
                .question => try std.testing.expectEqual(count, 2),
                .answer => try std.testing.expect(count <= 1),
            }
            count -%= 1;
        }

        try std.testing.expectEqual(count, 0);
    }
}

test "build answerDrop" {
    var buffer: [23]u8 = @splat(0xff);
    const msg0 = try Message.answerDrop(31337, "gr.ht.", &buffer);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        122, 105, 129, 131, 0,   1,   0, 0, 0, 0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0, 1, 0, 1,
    }, &buffer);
    try std.testing.expectEqual(msg0.header.qdcount, 1);
    try std.testing.expectEqual(msg0.header.ancount, 0);
}

test "grht vectors" {
    //const a = std.testing.allocator;
    const msg0 = try Message.fromBytes(&[_]u8{
        122, 105, 129, 128, 0,   1,   0, 1,  0,  0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0,  1,  0, 1, 192,
        12,  0,   1,   0,   1,   0,   0, 14, 16, 0, 4, 127,
        4,   20,  69,
    });
    try std.testing.expectEqual(msg0.header.qdcount, 1);
    try std.testing.expectEqual(msg0.header.ancount, 1);

    const msg1 = try Message.fromBytes(&[_]u8{
        122, 105, 129, 131, 0,   1,   0,   0,   0,   1,   0,   0,   2,   64,
        49,  1,   49,  1,   49,  1,   49,  0,   0,   1,   0,   1,   0,   0,
        6,   0,   1,   0,   1,   81,  128, 0,   64,  1,   97,  12,  114, 111,
        111, 116, 45,  115, 101, 114, 118, 101, 114, 115, 3,   110, 101, 116,
        0,   5,   110, 115, 116, 108, 100, 12,  118, 101, 114, 105, 115, 105,
        103, 110, 45,  103, 114, 115, 3,   99,  111, 109, 0,   120, 179, 132,
        44,  0,   0,   7,   8,   0,   0,   3,   132, 0,   9,   58,  128, 0,
        1,   81,  128,
    });
    try std.testing.expectEqual(msg1.header.qdcount, 1);
    try std.testing.expectEqual(msg1.header.ancount, 0);
}

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const indexOfScalar = std.mem.indexOfScalar;
const Writer = std.Io.Writer;
const Reader = std.Io.Reader;
