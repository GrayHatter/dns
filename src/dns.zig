pub const Domains = struct {
    strings: std.ArrayListUnmanaged(u8),
    loc_table: std.HashMapUnmanaged(
        u32,
        void,
        std.hash_map.StringIndexContext,
        std.hash_map.default_max_load_percentage,
    ),
};

pub const Upstream = struct {
    addr: std.net.Address,
    sock: std.posix.socket_t,

    /// TODO ipv6
    pub fn init(addr_ip: [4]u8, port: u16) !Upstream {
        const up: Upstream = .{
            .addr = .{ .in = .{ .sa = .{
                .port = nativeToBig(u16, port),
                .addr = bytesToValue(u32, &addr_ip),
            } } },
            .sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0),
        };
        return up;
    }

    pub fn connect(addr_ip: [4]u8, port: u16) !Upstream {
        const up: Upstream = try .init(addr_ip, port);
        try std.posix.connect(up.sock, &up.addr.any, up.addr.getOsSockLen());
        return up;
    }

    pub fn listen(addr_ip: [4]u8, port: u16) !Upstream {
        const up: Upstream = try .init(addr_ip, port);
        try std.posix.bind(up.sock, &up.addr.any, up.addr.getOsSockLen());
        return up;
    }

    pub fn send(upstrm: Upstream, data: []const u8) !void {
        const cnt = try std.posix.send(upstrm.sock, data, 0);
        if (cnt != data.len) return error.TxFailed;
    }

    pub fn recv(upstrm: Upstream, buffer: []u8) !usize {
        if (buffer.len < 512) return error.BufferTooSmall;
        const icnt = try std.posix.recv(upstrm.sock, buffer, 0);
        return icnt;
    }

    pub fn recvFrom(upstrm: Upstream, buffer: []u8, addr: *std.net.Address) !usize {
        if (buffer.len < 512) return error.BufferTooSmall;
        var src_len: u32 = undefined;
        const cnt = try std.posix.recvfrom(upstrm.sock, buffer, 0, &addr.any, &src_len);
        if (cnt >= 512) {
            @panic("packet too large");
        }
        return cnt;
    }
};

pub const Message = struct {
    header: Header,
    questions: ?[]Question = null,
    answers: ?[]Resource = null,
    authorities: ?[]Resource = null,
    additionals: ?[]Resource = null,

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
    };

    pub const Question = struct {
        name: []const u8,
        qtype: Type,
        class: Class,

        pub fn init(name: []const u8) !Question {
            return .{
                .name = name,
                .qtype = .a,
                .class = .in,
            };
        }

        pub fn write(q: Question, w: *std.io.AnyWriter) !void {
            try Label.writeName(q.name, w);
            if (q.name[q.name.len - 1] != '.') try w.writeByte(0);
            try w.writeInt(u16, @intFromEnum(q.qtype), .big);
            try w.writeInt(u16, @intFromEnum(q.class), .big);
        }
    };

    pub const Resource = struct {
        name: []const u8,
        rtype: Type,
        class: Class,
        ttl: u32,
        rdlength: u16,
        rdata: []const u8,

        pub fn write(_: Resource) void {}
    };

    pub const Type = enum(u16) {
        a = 1,
        ns,
        md, // obsolote -> mx
        mf, // obsolote -> mx
        cname,
        sao,
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

    pub fn fromBytes(a: Allocator, bytes: []const u8) !Message {
        if (bytes.len < 12) return error.MessageTooSmall;
        const header: Header = .fromBytes(bytes[0..12].*);
        std.debug.print("{}\n", .{header});

        var idx: usize = 12;

        const questions = try a.alloc(Question, header.qdcount);
        for (questions) |*q| {
            const name = try Label.getName(a, bytes, &idx);
            defer a.free(name);
            std.debug.print("{s}\n", .{name});
            q.* = .{
                .name = name,
                .qtype = @enumFromInt(@byteSwap(@as(u16, @bitCast(bytes[idx..][0..2].*)))),
                .class = @enumFromInt(@byteSwap(@as(u16, @bitCast(bytes[idx..][2..4].*)))),
            };
            std.debug.print("{any}\n", .{q.*});
            idx += 4;
        }

        const resources = try a.alloc(Resource, header.ancount);
        for (resources) |*r| {
            std.debug.print("{} {}\n", .{ idx, bytes[idx] });
            const name = try Label.getName(a, bytes, &idx);
            defer a.free(name);
            std.debug.print("{s}\n", .{name});
            const rdlen: u16 = @byteSwap(@as(u16, @bitCast(bytes[idx..][8..10].*)));
            r.* = .{
                .name = name,
                .rtype = @enumFromInt(@byteSwap(@as(u16, @bitCast(bytes[idx..][0..2].*)))),
                .class = @enumFromInt(@byteSwap(@as(u16, @bitCast(bytes[idx..][2..4].*)))),
                .ttl = @byteSwap(@as(u32, @bitCast(bytes[idx..][4..8].*))),
                .rdlength = rdlen,
                .rdata = bytes[idx..][10..][0..rdlen],
            };
            std.debug.print("{any}\n", .{r.*});
            if (r.*.rtype != .a) @panic("not implemented");
        }

        return .{
            .header = header,
            .questions = questions,
            .answers = resources,
        };
    }

    pub fn query(a: Allocator, fqdn: []const []const u8) !Message {
        const queries = try a.alloc(Question, fqdn.len);
        for (queries, fqdn) |*q, dn| {
            q.* = try .init(dn);
        }

        // TODO only byteswap when endian changes
        return .{
            .header = .{
                .id = @as(u16, 31337),
                .qr = false,
                .opcode = 0,
                .aa = false,
                .tc = false,
                .rd = true,
                .ra = false,
                .rcode = .success,
                .qdcount = @as(u16, @truncate(queries.len)),
                .ancount = 0,
                .nscount = 0,
                .arcount = 0,
            },
            .questions = queries,
        };
    }

    pub fn answer(domain: []const u8, ip: Address) !Message {
        _ = domain;
        _ = ip;
    }

    pub fn write(m: Message, buffer: []u8) !usize {
        var fbs = std.io.fixedBufferStream(buffer);
        var writer = fbs.writer();
        var w = writer.any();
        try w.writeInt(u96, @bitCast(m.header), .big);
        if (m.questions) |quest| for (quest) |q| {
            try q.write(&w);
        };

        if (m.answers) |ans| for (ans) |a| {
            a.write();
        };

        if (m.authorities) |authort| for (authort) |a| {
            a.write();
        };

        if (m.additionals) |addit| for (addit) |a| {
            a.write();
        };

        return fbs.pos;
    }

    test query {
        const q = try query(std.testing.allocator, &[1][]const u8{"gr.ht."});
        try std.testing.expectEqual(
            @as(u96, 37884113131630398792389361664),
            @as(u96, @bitCast(q.header)),
        );
        for (q.questions.?) |qst| {
            _ = qst;
            //std.testing.allocator.free(qst.name);
        }
        std.testing.allocator.free(q.questions.?);
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

    pub fn getName(a: Allocator, bytes: []const u8, index: *usize) ![]u8 {
        var name = try std.ArrayListUnmanaged(u8).initCapacity(a, 285);
        var idx: usize = index.*;
        var pointered: bool = false;
        sw: switch (bytes[idx]) {
            0 => {
                if (!pointered) index.* = idx + 1;
                return try name.toOwnedSlice(a);
            },
            1...63 => |b| {
                idx += b + 1;
                if (idx >= bytes.len) return error.InvalidLabel;
                name.appendSliceAssumeCapacity(bytes[idx - b .. idx]);
                name.appendAssumeCapacity('.');
                continue :sw bytes[idx];
            },
            192...255 => |b| {
                pointered = true;
                idx += 2;
                if (idx >= bytes.len) return error.InvalidLabel;
                index.* = idx;
                const offset: u16 = @as(u16, b & 0b111111) << 8 | bytes[idx - 1];
                if (offset < 12 or offset >= bytes.len) return error.InvalidLabel;
                idx = offset;
                continue :sw bytes[idx];
            },
            else => return error.InvalidLabel,
        }
        @panic("unreachable");
    }

    pub fn writeName(name: []const u8, w: *std.io.AnyWriter) !void {
        var itr = std.mem.splitScalar(u8, name, '.');
        while (itr.next()) |n| {
            std.debug.assert(n.len <= 63);
            try w.writeByte(@intCast(n.len));
            try w.writeAll(n);
        }
    }

    pub fn write(l: Label, w: *std.io.AnyWriter) !void {
        try w.writeByte(l.len);
        try w.writeAll(l.name);
    }
};

pub const Address = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,
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

fn testVector(a: Allocator, vect: []const u8) !void {
    const msg = try Message.fromBytes(a, vect);
    try std.testing.expectEqual(1, msg.questions.?.len);
    try std.testing.expectEqual(1, msg.answers.?.len);
    a.free(msg.questions.?);
    a.free(msg.answers.?);
}

test "build pkt" {
    const a = std.testing.allocator;
    const msg = try Message.query(a, &[1][]const u8{"gr.ht."});
    var buffer: [23]u8 = undefined;
    const used = try msg.write(&buffer);
    a.free(msg.questions.?);

    try std.testing.expect(used == 23);

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
    const a = std.testing.allocator;
    const msg = try Message.query(a, &[1][]const u8{"gr.ht"});
    var buffer: [23]u8 = undefined;
    const used = try msg.write(&buffer);
    a.free(msg.questions.?);

    try std.testing.expect(used == 23);

    try std.testing.expectEqualSlices(
        u8,
        &[23]u8{
            122, 105, 1,   0, 0,   1,   0, 0, 0, 0, 0, 0,
            2,   103, 114, 2, 104, 116, 0, 0, 1, 0, 1,
        },
        buffer[0..23],
    );
}

test "grht vectors" {
    const a = std.testing.allocator;
    try testVector(a, &[_]u8{
        122, 105, 129, 128, 0,   1,   0, 1,  0,  0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0,  1,  0, 1, 192,
        12,  0,   1,   0,   1,   0,   0, 14, 16, 0, 4, 127,
        4,   20,  69,
    });

    //try testVector(a, &[_]u8{
    //    122, 105, 129, 131, 0,   1,   0,   0,   0,   1,   0,   0,   2,   64,
    //    49,  1,   49,  1,   49,  1,   49,  0,   0,   1,   0,   1,   0,   0,
    //    6,   0,   1,   0,   1,   81,  128, 0,   64,  1,   97,  12,  114, 111,
    //    111, 116, 45,  115, 101, 114, 118, 101, 114, 115, 3,   110, 101, 116,
    //    0,   5,   110, 115, 116, 108, 100, 12,  118, 101, 114, 105, 115, 105,
    //    103, 110, 45,  103, 114, 115, 3,   99,  111, 109, 0,   120, 179, 132,
    //    44,  0,   0,   7,   8,   0,   0,   3,   132, 0,   9,   58,  128, 0,
    //    1,   81,  128,
    //});
}

test "simple test" {}

test "fuzz example" {
    const global = struct {
        fn testOne(input: []const u8) anyerror!void {
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(global.testOne, .{});
}

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
const nativeToBig = std.mem.nativeToBig;
const bytesToValue = std.mem.bytesToValue;
