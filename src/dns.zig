pub const Domains = struct {
    strings: std.ArrayListUnmanaged(u8),
};

pub const Message = struct {
    header: Header,
    question: ?[]Question = null,
    answer: ?[]Resource = null,
    authority: ?[]Resource = null,
    additional: ?[]Resource = null,

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
        name: Name,
        qtype: Type,
        class: Class,

        pub const Name = []Label;

        pub fn init(a: Allocator, name: []const u8) !Question {
            const label = try a.alloc(Label, std.mem.count(u8, name, "."));
            var itr = std.mem.splitScalar(u8, name, '.');
            for (label) |*l| {
                const n = itr.next().?;
                l.* = .{
                    .len = @intCast(n.len),
                    .name = n,
                };
            }
            return .{
                .name = label,
                .qtype = .a,
                .class = .in,
            };
        }

        pub fn write(q: Question, w: *std.io.AnyWriter) !void {
            for (q.name) |l| try l.write(w);
            try w.writeByte(0);
            try w.writeInt(u16, @intFromEnum(q.qtype), .big);
            try w.writeInt(u16, @intFromEnum(q.class), .big);
        }

        pub fn fromBytes(a: Allocator, bytes: []const u8) !Question {
            const end = indexOfScalar(u8, bytes, 0) orelse return error.InvalidQuestion;
            if (bytes.len < end + 4) return error.InvalidQuestion;
            const qtype: Type = @enumFromInt(@byteSwap(@as(u16, bytes[end + 1 .. end + 3].*)));
            const class: Class = @enumFromInt(@byteSwap(@as(u16, bytes[end + 3 .. end + 5].*)));

            var idx: usize = 0;
            var count: usize = 0;
            sw: switch (bytes[idx]) {
                0...63 => |b| {
                    count += 1;
                    idx += b + 1;
                    if (idx >= bytes.len) return error.InvalidLabel;
                    continue :sw bytes[idx];
                },
                192...255 => |b| {
                    count += 1;
                    idx += 2;
                    if (idx >= bytes.len) return error.InvalidLabel;
                    const offset: u16 = b & 0b111111 << 8 | bytes[idx - 1];
                    if (offset >= bytes.len) return error.InvalidLabel;
                    count += 1;
                    continue :sw bytes[idx];
                },
                else => return error.InvalidLabel,
            }

            const labels = try a.alloc(Label, count);

            return .{
                .name = labels,
                .qtype = qtype,
                .class = class,
            };
        }
    };

    pub const Resource = struct {
        name: void,
        rtype: Type,
        class: u16,
        ttl: u32,
        rdlength: u16,
        data: void,

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
        _ = a;
        return .{
            .header = header,
        };
    }

    pub fn query(a: Allocator, fqdn: []const []const u8) !Message {
        const queries = try a.alloc(Question, fqdn.len);
        for (queries, fqdn) |*q, dn| {
            q.* = try .init(a, dn);
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
            .question = queries,
        };
    }

    pub fn write(m: Message, buffer: []u8) !usize {
        var fbs = std.io.fixedBufferStream(buffer);
        var writer = fbs.writer();
        var w = writer.any();
        try w.writeInt(u96, @bitCast(m.header), .big);
        if (m.question) |quest| for (quest) |q| {
            try q.write(&w);
        };

        if (m.answer) |answer| for (answer) |a| {
            a.write();
        };

        if (m.authority) |authort| for (authort) |a| {
            a.write();
        };

        if (m.additional) |addit| for (addit) |a| {
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
        for (q.question.?) |qst| {
            std.testing.allocator.free(qst.name);
        }
        std.testing.allocator.free(q.question.?);
    }
};

pub const Label = struct {
    len: u6,
    name: []const u8,

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

pub fn main() !void {
    const a = std.heap.page_allocator;
    std.debug.print("started\n", .{});

    const addr: std.net.Address = .{ .in = .{ .sa = .{
        .port = std.mem.nativeToBig(u16, 53),
        .addr = std.mem.bytesToValue(u32, &[4]u8{ 0, 0, 0, 0 }),
    } } };

    const msg = try Message.query(a, &[1][]const u8{"gr.ht."});
    var request: [1024]u8 = undefined;
    const msgsize = try msg.write(&request);

    std.debug.print("msg {}\n", .{msgsize});
    std.debug.print("data {any}\n", .{request[0..msgsize]});
    std.debug.print("data {s}\n", .{request[0..msgsize]});

    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    try std.posix.connect(sock, &addr.any, addr.getOsSockLen());
    const ocnt = try std.posix.send(sock, request[0..msgsize], 0);
    std.debug.print("sent {}\n", .{ocnt});

    var buffer: [1024]u8 = undefined;
    const icnt = try std.posix.recv(sock, &buffer, 0);
    std.debug.print("received {}\n", .{icnt});
    std.debug.print("data {any}\n", .{buffer[0..icnt]});
    std.debug.print("data {s}\n", .{buffer[0..icnt]});

    std.debug.print("done\n", .{});
}

pub fn server() !void {
    const sock = try std.posix.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, std.posix.SOCK.NONBLOCK);

    const addr: std.net.Address = .{ .in = .{ .sa = .{
        .port = 53,
        .addr = 0,
    } } };
    const bind = try std.posix.bind(sock, &addr.any, addr.getOsSockLen());
    _ = bind;

    const buffer: [1024]u8 = undefined;
    const icnt = try std.posix.recv(sock, &buffer, 0);
    std.debug.print("sent {}\n", .{icnt});
}

test "grht vectors" {
    const a = std.testing.allocator;
    const vector = [_]u8{
        122, 105, 129, 128, 0,   1,   0, 1,  0,  0, 0, 0,
        2,   103, 114, 2,   104, 116, 0, 0,  1,  0, 1, 192,
        12,  0,   1,   0,   1,   0,   0, 14, 16, 0, 4, 144,
        126, 209, 12,
    };
    const msg = try Message.fromBytes(a, &vector);

    _ = msg;
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
