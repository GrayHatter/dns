pub const Peer = struct {
    addr: std.net.Address,
    sock: std.posix.socket_t,

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

    pub fn connect(addr_ip: [4]u8, port: u16) !Peer {
        const up: Peer = try .init(addr_ip, port);
        try std.posix.connect(up.sock, &up.addr.any, up.addr.getOsSockLen());
        return up;
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
};

pub const Message = struct {
    header: Header,
    bytes: []const u8,

    pub const Header = packed struct(u96) {
        arcount: u16,
        nscount: u16,
        ancount: u16,
        qdcount: u16,
        rcode: RCode,
        z: u3 = 0,
        ra: bool,
        rd: bool,
        tc: bool,
        aa: bool,
        opcode: u4,
        qr: bool,
        id: u16,

        pub const RCode = enum(u4) {
            success = 0,
            format,
            server,
            name,
            not_implemented,
            refused,
            _, // Reserved for future use
        };

        pub fn fromBytes(bytes: [12]u8) Header {
            const id: u16 = @byteSwap(@as(u16, @bitCast(bytes[0..2].*)));
            const hbits: u8 = bytes[2];
            const lbits: u8 = bytes[3];

            return .{
                .id = id,
                .qr = 0x80 & hbits != 0,
                .opcode = @truncate((0x70 & hbits) >> 3),
                .aa = 0x4 & hbits != 0,
                .tc = 0x2 & hbits != 0,
                .rd = 0x1 & hbits != 0,
                .ra = 0x80 & lbits != 0,
                .rcode = @enumFromInt(0xf & (lbits)),
                .qdcount = @byteSwap(@as(u16, @bitCast(bytes[4..6].*))),
                .ancount = @byteSwap(@as(u16, @bitCast(bytes[6..8].*))),
                .nscount = @byteSwap(@as(u16, @bitCast(bytes[8..10].*))),
                .arcount = @byteSwap(@as(u16, @bitCast(bytes[10..12].*))),
            };
        }

        pub fn write(h: Header, w: *std.io.AnyWriter) !usize {
            try w.writeInt(u96, @bitCast(h), .big);
            std.debug.assert(@sizeOf(Header) == 16);
            std.debug.assert(@divExact(@typeInfo(u96).int.bits, 8) == 12);
            return 12;
        }
    };

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
            .rcode = .success,
            .qdcount = @intCast(fqdns.len),
            .ancount = @intCast(fqdns.len),
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

        for (fqdns, ips, pointers) |fqdn, ip, p| {
            const r: Resource = .init(fqdn, ip, 300);
            idx += try r.write(&w, p);
        }

        return .{
            .header = h,
            .bytes = bytes[0..idx],
        };
    }

    pub fn answerDrop(id: u16, fqdn: []const u8, bytes: []u8) !Message {
        const addrs: [16]Resource.RData = @splat(Resource.RData{ .a = @splat(0) });
        return try answer(id, &[1][]const u8{fqdn}, addrs[0..1], bytes);
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
};

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

    pub fn getName(buffer: []u8, bytes: []const u8, index: *usize) ![]u8 {
        var name: std.ArrayListUnmanaged(u8) = .{
            .items = buffer,
            .capacity = buffer.len,
        };
        name.items.len = 0;
        var idx: usize = index.*;
        var pointered: bool = false;
        sw: switch (bytes[idx]) {
            0 => {
                if (!pointered) index.* = idx + 1;
                return name.items;
            },
            1...63 => |b| {
                idx += b + 1;
                if (idx >= bytes.len) return error.InvalidLabel;
                name.appendSliceAssumeCapacity(bytes[idx - b .. idx]);
                name.appendAssumeCapacity('.');
                continue :sw bytes[idx];
            },
            192...255 => |b| {
                if (!pointered) index.* = idx + 2;
                pointered = true;
                idx += 2;
                if (idx >= bytes.len) return error.InvalidLabel;
                const offset: u16 = @as(u16, b & 0b111111) << 8 | bytes[idx - 1];
                if (offset < 12 or offset >= bytes.len) return error.InvalidLabel;
                idx = offset;
                continue :sw bytes[idx];
            },
            else => return error.InvalidLabel,
        }
        @panic("unreachable");
    }

    pub fn writeName(name: []const u8, w: *std.io.AnyWriter) !usize {
        var itr = std.mem.splitScalar(u8, name, '.');
        var len: usize = 0;
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
        var fbs = std.io.fixedBufferStream(&buffer);
        var writer = fbs.writer();
        var w = writer.any();

        try std.testing.expectEqual(try writeName("gr.ht", &w), 7);
        try std.testing.expectEqual(try writeName("gr.ht.", &w), 7);
    }

    pub fn write(l: Label, w: *std.io.AnyWriter) !void {
        try w.writeByte(l.len);
        try w.writeAll(l.name);
    }
};

test "Message.Header" {
    const thing: Message.Header = .{
        .id = 16,
        .qr = false,
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
        &[1][]const u8{"gr.ht."},
        &[1]Message.Resource.RData{.{ .a = .{ 127, 4, 20, 69 } }},
        &buffer,
    );

    try std.testing.expectEqualSlices(u8, &[_]u8{
        122, 105, 133, 128, 0,   1,   0, 1, 0,  0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0, 1,  0, 1, 192,
        12,  0,   1,   0,   1,   0,   0, 1, 44, 0, 4, 127,
        4,   20,  69,
    }, &buffer);
    try std.testing.expectEqual(msg0.header.qdcount, 1);
    try std.testing.expectEqual(msg0.header.ancount, 1);

    const msg1 = try Message.answer(
        31337,
        &[1][]const u8{"gr.ht"},
        &[1]Message.Resource.RData{.{ .a = .{ 127, 4, 20, 69 } }},
        &buffer,
    );

    try std.testing.expectEqualSlices(u8, &[_]u8{
        122, 105, 133, 128, 0,   1,   0, 1, 0,  0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0, 1,  0, 1, 192,
        12,  0,   1,   0,   1,   0,   0, 1, 44, 0, 4, 127,
        4,   20,  69,
    }, &buffer);
    try std.testing.expectEqual(msg1.header.qdcount, 1);
    try std.testing.expectEqual(msg1.header.ancount, 1);

    var big_buffer: [100]u8 = undefined;

    const msg2 = try Message.answer(
        31337,
        &[1][]const u8{"gr.ht."},
        &[1]Message.Resource.RData{.{ .a = .{ 127, 4, 20, 69 } }},
        &big_buffer,
    );
    try std.testing.expectEqualSlices(u8, &[_]u8{
        122, 105, 133, 128, 0,   1,   0, 1, 0,  0, 0, 0,
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
}

test "build answerDrop" {
    var buffer: [39]u8 = @splat(0xff);
    const msg0 = try Message.answerDrop(31337, "gr.ht.", &buffer);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        122, 105, 133, 128, 0,   1,   0, 1, 0,  0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0, 1,  0, 1, 192,
        12,  0,   1,   0,   1,   0,   0, 1, 44, 0, 4, 0,
        0,   0,   0,
    }, &buffer);
    try std.testing.expectEqual(msg0.header.qdcount, 1);
    try std.testing.expectEqual(msg0.header.ancount, 1);
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

test "fuzz example" {
    //const global = struct {
    //    fn testOne(input: []const u8) anyerror!void {
    //        try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
    //    }
    //};
    //try std.testing.fuzz(global.testOne, .{});
}

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
const nativeToBig = std.mem.nativeToBig;
const bytesToValue = std.mem.bytesToValue;
