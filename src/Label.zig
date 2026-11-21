len: u6,
name: []const u8,

const Label = @This();

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
    var name: ArrayList(u8) = .initBuffer(buffer);
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

const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const std = @import("std");
const Writer = std.Io.Writer;
const Reader = std.Io.Reader;
