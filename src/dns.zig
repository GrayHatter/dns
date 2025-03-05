pub const Message = struct {
    header: Header,
    question: ?[]Question = null,
    answer: ?[]Resource = null,
    authority: ?[]Authority = null,
    additional: ?[]Additional = null,

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

    pub const Authority = struct {
        pub fn write(_: Authority) void {}
    };

    pub const Additional = struct {
        pub fn write(_: Additional) void {}
    };

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
