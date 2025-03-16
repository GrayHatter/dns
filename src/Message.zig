const Message = @This();

header: Header,
bytes: []const u8,

pub const Header = @import("Header.zig").Header;

pub const Payload = union(enum) {
    question: Question,
    answer: Resource,
};

pub const Question = struct {
    name: []const u8,
    qtype: Type,
    class: Class,

    pub fn init(name: []const u8) Question {
        return .{
            .name = name,
            .qtype = .a,
            .class = .in,
        };
    }

    pub fn write(q: Question, w: *std.io.AnyWriter) !usize {
        const len = try Label.writeName(q.name, w);
        try w.writeInt(u16, @intFromEnum(q.qtype), .big);
        try w.writeInt(u16, @intFromEnum(q.class), .big);
        return len + 4;
    }
};

pub const Resource = struct {
    name: []const u8,
    rtype: Type,
    class: Class,
    ttl: u32,
    data: RData,

    pub const RData = union(enum) {
        a: [4]u8,
        aaaa: [16]u8,
        cname: []const u8,
        soa: struct {},
    };

    pub fn init(fqdn: []const u8, rdata: RData, ttl: u32) Resource {
        return .{
            .name = fqdn,
            .rtype = switch (rdata) {
                .a => .a,
                .aaaa => .aaaa,
                .cname => .cname,
                .soa => .soa,
            },
            .class = .in,
            .ttl = ttl,
            .data = rdata,
        };
    }

    pub fn write(r: Resource, w: *std.io.AnyWriter, mptr: ?u14) !usize {
        var idx: usize = 0;
        if (mptr) |p| {
            const ptr: u16 = 0xc000 | @as(u16, p);
            try w.writeInt(u16, ptr, .big);
            idx += 2;
        } else {
            idx += try Label.writeName(r.name, w);
        }
        try w.writeInt(u16, @intFromEnum(r.rtype), .big);
        idx += 2;
        try w.writeInt(u16, @intFromEnum(r.class), .big);
        idx += 2;
        try w.writeInt(u32, r.ttl, .big);
        idx += 4;
        switch (r.data) {
            .a => |a| {
                try w.writeInt(u16, 4, .big);
                try w.writeAll(&a);
                idx += 6;
            },
            .aaaa => |aaaa| {
                try w.writeInt(u16, 16, .big);
                try w.writeAll(&aaaa);
                idx += 18;
            },
            .cname => |name| {
                idx += try Label.writeName(name, w);
            },
            .soa => unreachable,
        }

        return idx;
    }
};

pub const Type = enum(u16) {
    a = 1,
    ns,
    md, // obsolote -> mx
    mf, // obsolote -> mx
    cname,
    soa,
    mb,
    mg,
    mr,
    null,
    wks,
    ptr,
    hinfo,
    minfo,
    mx,
    txt,
    aaaa = 28,
    EDNS = 41,
    https = 65, // RFC9460 -- so preoccupied with whether or not they could,
    //                        that they didn't stop to think if they should!
    // The following are QTypes
    axfr = 252,
    mailb,
    maila,
    all_records, // defined in the RFC as *
    _,
};

pub const Class = enum(u16) {
    in = 1,
    cs,
    ch,
    hs,
    any_class = 255,
    _,
};

pub fn fromBytes(bytes: []const u8) !Message {
    if (bytes.len < 12) return error.MessageTooSmall;
    const header: Header = .fromBytes(bytes[0..12].*);

    return .{
        .header = header,
        .bytes = bytes,
    };
}

pub const Iterator = struct {
    msg: *const Message,
    index: usize = 0,
    name_buffer: [255]u8 = undefined,

    pub fn init(msg: *const Message) Iterator {
        return .{
            .index = 0,
            .msg = msg,
        };
    }

    pub fn next(iter: *Iterator) !?Payload {
        const h = iter.msg.header;

        if (iter.index >= h.qdcount + h.ancount + h.nscount + h.arcount) return null;

        defer iter.index += 1;
        return try iter.msg.payload(iter.index, &iter.name_buffer);
    }
};

pub fn iterator(msg: *const Message) Iterator {
    return Iterator.init(msg);
}

pub fn payload(msg: Message, index: usize, name_buf: []u8) !Payload {
    const payload_end = msg.header.qdcount + msg.header.ancount +
        msg.header.nscount + msg.header.arcount;
    if (index >= payload_end) return error.InvalidIndex;

    var idx: usize = 12;
    for (0..payload_end) |payload_idx| {
        if (payload_idx < msg.header.qdcount) {
            const name = try Label.getName(name_buf, msg.bytes, &idx);
            if (payload_idx == index) return .{ .question = .{
                .name = name,
                .qtype = @enumFromInt(@byteSwap(@as(u16, @bitCast(msg.bytes[idx..][0..2].*)))),
                .class = @enumFromInt(@byteSwap(@as(u16, @bitCast(msg.bytes[idx..][2..4].*)))),
            } };
            idx += 4;
            //log.warn("{any}", .{q.*});
        } else if (payload_idx >= msg.header.qdcount) {
            const name = try Label.getName(name_buf, msg.bytes, &idx);
            const rdlen: u16 = @byteSwap(@as(u16, @bitCast(msg.bytes[idx..][8..10].*)));
            if (rdlen > msg.bytes.len - idx) return error.InvalidPacket;
            if (payload_idx != index) {
                idx += 10 + rdlen;
                continue;
            }
            const rtype: Type = @enumFromInt(@byteSwap(@as(u16, @bitCast(msg.bytes[idx..][0..2].*))));
            const addr: Resource.RData = switch (rtype) {
                .a => .{ .a = msg.bytes[idx..][10..][0..4].* },
                .aaaa => .{ .aaaa = msg.bytes[idx..][10..][0..16].* },
                .cname => .{ .cname = msg.bytes[idx..][10..][0..rdlen] },
                .soa => undefined,
                .EDNS => undefined,
                .https => undefined,
                else => |err| {
                    log.err("not implemented {}", .{err});
                    return error.ResponseTypeNotImplemented;
                },
            };

            const r: Resource = .{
                .name = name,
                .rtype = rtype,
                .class = @enumFromInt(@byteSwap(@as(u16, @bitCast(msg.bytes[idx..][2..4].*)))),
                .ttl = @byteSwap(@as(u32, @bitCast(msg.bytes[idx..][4..8].*))),
                .data = addr,
            };

            return .{ .answer = r };
        }
    } else return error.InvalidIndex;
}

pub fn query(fqdns: []const []const u8, buffer: []u8) !Message {
    var msg: Message = .{
        .header = .{
            .id = @as(u16, 31337),
            .qr = false,
            .opcode = 0,
            .aa = false,
            .tc = false,
            .rd = true,
            .ra = false,
            .rcode = .success,
            .qdcount = @as(u16, @truncate(fqdns.len)),
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        },
        .bytes = buffer,
    };

    var fbs = std.io.fixedBufferStream(buffer);
    var writer = fbs.writer();
    var w = writer.any();
    var idx = try msg.write(&w);
    for (fqdns) |fqdn| {
        const q: Question = .init(fqdn);
        idx += try q.write(&w);
    }
    msg.bytes.len = idx;
    return msg;
}

pub fn answer(id: u16, fqdns: []const []const u8, ips: []const Resource.RData, bytes: []u8) !Message {
    var h: Header = .{
        .id = id,
        .qr = true,
        .opcode = 0,
        .aa = true,
        .tc = false,
        .rd = true,
        .ra = true,
        .rcode = if (ips.len == 0) .name else .success,
        .qdcount = @intCast(fqdns.len),
        .ancount = @intCast(ips.len),
        .nscount = 0,
        .arcount = 0,
    };

    var fbs = std.io.fixedBufferStream(bytes);
    var writer = fbs.writer();
    var w = writer.any();
    var idx = try h.write(&w);

    var pbufs: [8]u14 = @splat(0);
    var pointers: []u14 = pbufs[0..fqdns.len];

    for (fqdns, 0..) |fqdn, i| {
        const q: Question = .init(fqdn);
        pointers[i] = @intCast(idx);
        idx += try q.write(&w);
    }

    if (fqdns.len == ips.len) {
        for (fqdns, ips, pointers) |fqdn, ip, p| {
            const r: Resource = .init(fqdn, ip, 300);
            idx += try r.write(&w, p);
        }
    } else if (ips.len != 0) return error.InvalidAnswer;

    return .{
        .header = h,
        .bytes = bytes[0..idx],
    };
}

pub fn answerDrop(id: u16, fqdn: []const u8, bytes: []u8) !Message {
    return try answer(id, &[1][]const u8{fqdn}, &[0]Resource.RData{}, bytes);
}

pub fn write(m: Message, w: *std.io.AnyWriter) !usize {
    const hlen = try m.header.write(w);
    std.debug.assert(hlen == 12);
    return hlen;
}

test query {
    var buffer: [23]u8 = undefined;
    const q = try query(&[1][]const u8{"gr.ht."}, &buffer);
    try std.testing.expectEqual(
        @as(u96, 37884113131630398792389361664),
        @as(u96, @bitCast(q.header)),
    );
}

const Label = @import("dns.zig").Label;

const std = @import("std");
const log = std.log;
