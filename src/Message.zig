header: Header,
bytes: []const u8,
questions: ?ArrayList(Question) = null,
answers: ?ArrayList(Resource) = null,

const Message = @This();

pub const Header = @import("Header.zig").Header;

pub const TTL = enum(u32) {
    zero = 0,
    @"1min" = 60,
    @"5min" = 300,
    @"10min" = 600,
    _,

    pub fn expired(ttl: TTL, now: i64) bool {
        const ttl_s: usize = @intFromEnum(ttl);
        return ttl_s < now;
    }

    pub fn timestamp(ttl: TTL, now: i64) i64 {
        return now +| @intFromEnum(ttl);
    }

    pub fn seconds(s: usize) TTL {
        return @enumFromInt(s);
    }

    pub fn minutes(m: usize) TTL {
        return seconds(m *| 60);
    }

    pub fn plus(ttl: TTL, other: TTL) TTL {
        return @enumFromInt(@intFromEnum(ttl) + @intFromEnum(other));
    }

    pub fn min(ttl: TTL, other: TTL) TTL {
        return @enumFromInt(@min(@intFromEnum(ttl), @intFromEnum(other)));
    }

    pub fn write(ttl: TTL, w: *std.Io.Writer) !void {
        return try w.writeInt(u32, @intFromEnum(ttl), .big);
    }
};

test TTL {
    try std.testing.expectEqual(TTL.@"1min", TTL.seconds(60));
    try std.testing.expectEqual(TTL.@"5min", TTL.minutes(5));
    try std.testing.expectEqual(TTL.@"10min", TTL.minutes(10));

    const pls: TTL = .plus(.@"5min", .@"5min");
    try std.testing.expectEqual(pls, TTL.@"10min");
}

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

    pub fn write(q: Question, w: *Writer) !usize {
        const len = try Label.writeName(q.name, w);
        try w.writeInt(u16, @intFromEnum(q.qtype), .big);
        try w.writeInt(u16, @intFromEnum(q.class), .big);
        return len + 4;
    }

    pub fn format(q: Question, w: *Writer) !void {
        const block =
            \\/ Name: {s: ^40}/
            \\+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            \\|{s: ^47}|
            \\+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            \\|{s: ^47}|
            \\+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        ;
        try w.print(block, .{ q.name, @tagName(q.qtype), @tagName(q.class) });
    }
};

pub const Resource = struct {
    name: []const u8,
    rtype: Type,
    class: Class,
    ttl: TTL,
    data: RData,

    pub const RData = union(enum) {
        a: [4]u8,
        aaaa: [16]u8,
        cname: []const u8,
        soa: struct {
            mname: []const u8, // primary server
            rname: []const u8, // owner mailbox
            serial: u32,
            refresh: u32,
            retry: u32,
            expire: u32,
            minimum: u32,
        },
        _null: void,
    };

    pub fn init(fqdn: []const u8, rdata: RData, ttl: TTL) Resource {
        return .{
            .name = fqdn,
            .rtype = switch (rdata) {
                .a => .a,
                .aaaa => .aaaa,
                .cname => .cname,
                .soa => .soa,
                ._null => unreachable,
            },
            .class = .in,
            .ttl = ttl,
            .data = rdata,
        };
    }

    pub fn write(r: Resource, w: *Writer, mptr: ?u14) !usize {
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
        try r.ttl.write(w);
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
            .soa, ._null => unreachable,
        }

        return idx;
    }

    pub fn format(r: Resource, w: *Writer) !void {
        const block =
            \\/ Name:                                         /
            \\/{s: ^47}/
            \\+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            \\|{s: ^47}|
            \\+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            \\|{s: ^47}|
            \\+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            \\|{d: ^47}|
            \\+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
            \\|{d: ^47}|
            \\+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
            \\/                     RDATA                     /
            \\/                                               /
            \\+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        ;

        const rtype = @tagName(r.rtype);
        const class = switch (r.class) {
            inline else => @tagName(r.class),
            _ => "other",
        };

        try w.print(block, .{
            r.name, rtype, class, r.ttl, switch (r.data) {
                .a => 4,
                .aaaa => 16,
                .cname, .soa, ._null => @as(usize, 0),
            },
        });
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
    name_buffer: [1024]u8 = undefined,

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

pub fn parse(msg: *Message, a: Allocator) !void {
    var itr = iterator(msg);
    msg.questions = .{};
    msg.answers = .{};
    while (try itr.next()) |pyld| switch (pyld) {
        .question => |q| {
            try msg.questions.?.append(a, q);
            const name = try a.dupe(u8, msg.questions.?.items[msg.questions.?.items.len - 1].name);
            msg.questions.?.items[msg.questions.?.items.len - 1].name = name;
        },
        .answer => |ans| {
            try msg.answers.?.append(a, ans);
            const name = try a.dupe(u8, msg.answers.?.items[msg.answers.?.items.len - 1].name);
            msg.answers.?.items[msg.answers.?.items.len - 1].name = name;
        },
    };
}

fn byteSwap(T: type, bytes: [@sizeOf(T)]u8) T {
    return @byteSwap(@as(u16, @bitCast(bytes)));
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

            const class: Class = @enumFromInt(@byteSwap(@as(u16, @bitCast(msg.bytes[idx..][2..4].*))));
            const ttl: TTL = .seconds(@byteSwap(@as(u32, @bitCast(msg.bytes[idx..][4..8].*))));

            idx += 10;
            const rdata: Resource.RData = switch (rtype) {
                .a => .{ .a = msg.bytes[idx..][0..4].* },
                .aaaa => .{ .aaaa = msg.bytes[idx..][0..16].* },
                .cname => .{ .cname = msg.bytes[idx..][0..rdlen] },
                .soa => .{ .soa = .{
                    .mname = try Label.getName(name_buf[128..], msg.bytes, &idx),
                    .rname = try Label.getName(name_buf[256..], msg.bytes, &idx),
                    .serial = @byteSwap(@as(u32, @bitCast(msg.bytes[idx..][0..4].*))),
                    .refresh = @byteSwap(@as(u32, @bitCast(msg.bytes[idx..][4..8].*))),
                    .retry = @byteSwap(@as(u32, @bitCast(msg.bytes[idx..][8..12].*))),
                    .expire = @byteSwap(@as(u32, @bitCast(msg.bytes[idx..][12..16].*))),
                    .minimum = @byteSwap(@as(u32, @bitCast(msg.bytes[idx..][16..20].*))),
                } },
                .EDNS => .{ ._null = {} },
                .https => .{ ._null = {} },
                else => |err| {
                    log.err("not implemented {}", .{err});
                    return error.ResponseTypeNotImplemented;
                },
            };

            const r: Resource = .{
                .name = name,
                .rtype = rtype,
                .class = class,
                .ttl = ttl,
                .data = rdata,
            };

            return .{ .answer = r };
        }
    } else return error.InvalidIndex;
}

pub fn query(fqdns: []const []const u8, buffer: []u8) !Message {
    var msg: Message = .{
        .header = .{
            .id = @as(u16, 31337),
            .qr = .query,
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

    var w: Writer = .fixed(buffer);
    var idx = try msg.write(&w);
    for (fqdns) |fqdn| {
        const q: Question = .init(fqdn);
        idx += try q.write(&w);
    }
    msg.bytes.len = idx;
    return msg;
}

pub const AnswerData = struct {
    fqdn: []const u8,
    ips: []const Resource.RData,
};

pub fn answer(id: u16, answers: []const AnswerData, bytes: []u8) !Message {
    var h: Header = .answer;
    h.id = id;
    h.rcode = if (answers.len == 1 and answers[0].ips.len == 0) .name else .success;
    h.qdcount = @intCast(answers.len);
    for (answers) |ans| {
        h.ancount += @intCast(ans.ips.len);
    }

    var w: Writer = .fixed(bytes);
    var idx = try h.write(&w);

    var pbufs: [8]u14 = @splat(0);
    var pointers: []u14 = pbufs[0..answers.len];

    for (answers, 0..) |ans, i| {
        const q: Question = .init(ans.fqdn);
        pointers[i] = @intCast(idx);
        idx += try q.write(&w);
    }

    if (answers.len == 1) {
        if (answers[0].ips.len == 1) {
            for (answers, pointers) |ans, p| {
                for (ans.ips) |ip| {
                    const r: Resource = .init(ans.fqdn, ip, .@"5min");
                    idx += try r.write(&w, p);
                }
            }
        } else {
            for (answers[0].ips) |ip| {
                const r: Resource = .init(answers[0].fqdn, ip, .@"5min");
                idx += try r.write(&w, pointers[0]);
            }
        }
    } else return error.NotImplemented;

    return .{
        .header = h,
        .bytes = bytes[0..idx],
    };
}

pub fn answerDrop(id: u16, fqdn: []const u8, bytes: []u8) !Message {
    return try answer(id, &[1]AnswerData{.{ .fqdn = fqdn, .ips = &[0]Resource.RData{} }}, bytes);
}

pub fn write(m: Message, w: *Writer) !usize {
    var idx = try m.header.write(w);
    std.debug.assert(idx == 12);

    var pbufs: [32]u14 = @splat(0);
    var ptr_idx: [*]u14 = (&pbufs).ptr;

    if (m.questions) |questions| {
        for (questions.items) |question| {
            ptr_idx[0] = @intCast(idx);
            idx += try question.write(w);
            ptr_idx += 1;
        }
    }

    if (m.answers) |answers| {
        for (answers.items) |ans| {
            for (m.questions.?.items, 0..) |qn, i| {
                if (std.mem.eql(u8, ans.name, qn.name)) {
                    idx += try ans.write(w, pbufs[i]);
                    break;
                }
            } else {
                idx += try ans.write(w, null);
            }
        }
    }

    return idx;
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

test Message {
    const source_bytes = [_]u8{
        197, 22,  129, 128, 0,   1,   0,   1,   0,   0,   0,   0,
        7,   122, 105, 103, 108, 97,  110, 103, 3,   111, 114, 103,
        0,   0,   28,  0,   1,   192, 12,  0,   28,  0,   1,   0,
        0,   1,   44,  0,   16,  42,  1,   4,   249, 48,  81,  75,
        210, 0,   0,   0,   0,   0,   0,   0,   2,
    };

    var msg1 = try Message.fromBytes(&source_bytes);
    var w_b: [source_bytes.len]u8 = undefined;
    try msg1.parse(std.testing.allocator);
    defer msg1.questions.?.deinit(std.testing.allocator);
    defer msg1.answers.?.deinit(std.testing.allocator);
    defer for (msg1.questions.?.items) |itm| std.testing.allocator.free(itm.name);
    defer for (msg1.answers.?.items) |itm| std.testing.allocator.free(itm.name);

    var fixed: Writer = .fixed(&w_b);
    _ = try msg1.write(&fixed);

    try std.testing.expectEqualSlices(u8, &source_bytes, &w_b);
    //const source_bytes_soa = [_]u8{
    //    122, 105, 129, 131, 0,   1,   0,   0,   0,   1,   0,   0,   2,   64,
    //    49,  1,   49,  1,   49,  1,   49,  0,   0,   1,   0,   1,   0,   0,
    //    6,   0,   1,   0,   1,   81,  128, 0,   64,  1,   97,  12,  114, 111,
    //    111, 116, 45,  115, 101, 114, 118, 101, 114, 115, 3,   110, 101, 116,
    //    0,   5,   110, 115, 116, 108, 100, 12,  118, 101, 114, 105, 115, 105,
    //    103, 110, 45,  103, 114, 115, 3,   99,  111, 109, 0,   120, 179, 132,
    //    44,  0,   0,   7,   8,   0,   0,   3,   132, 0,   9,   58,  128, 0,
    //    1,   81,  128,
    //};
}

test "Message.1" {
    // TODO fix packing
    if (true) return error.SkipZigTest;

    const source_bytes = [_]u8{
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

    var msg1 = try Message.fromBytes(&source_bytes);
    var w_b: [source_bytes.len]u8 = undefined;
    try msg1.parse(std.testing.allocator);
    defer msg1.questions.?.deinit(std.testing.allocator);
    defer msg1.answers.?.deinit(std.testing.allocator);
    defer for (msg1.questions.?.items) |itm| std.testing.allocator.free(itm.name);
    defer for (msg1.answers.?.items) |itm| std.testing.allocator.free(itm.name);

    var fixed: Writer = .fixed(&w_b);
    _ = try msg1.write(&fixed);

    try std.testing.expectEqualSlices(u8, &source_bytes, &w_b);
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const log = std.log;
const Writer = std.Io.Writer;
const ArrayList = std.ArrayList;
