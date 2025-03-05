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
    };

    pub const Resource = struct {
        name: void,
        rtype: Type,
        class: u16,
        ttl: u32,
        rdlength: u16,
        data: void,
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

    pub const Authority = struct {};

    pub const Additional = struct {};

    pub fn query(a: Allocator, fqdn: []const []const u8) !Message {
        const queries = try a.alloc(Question, fqdn.len);
        for (queries, fqdn) |*q, dn| {
            const label = try a.alloc(Label, std.mem.count(u8, dn, "."));
            var itr = std.mem.splitScalar(u8, dn, '.');
            for (label) |*l| {
                const n = itr.next().?;
                l.* = .{
                    .len = @intCast(n.len),
                    .name = n,
                };
            }
            q.* = .{
                .name = label,
                .qtype = .a,
                .class = .in,
            };
        }

        // TODO only byteswap when endian changes
        return .{
            .header = .{
                .id = @byteSwap(@as(u16, 31337)),
                .qr = false,
                .opcode = 0,
                .aa = false,
                .tc = false,
                .rd = true,
                .ra = false,
                .rcode = .success,
                .qdcount = @byteSwap(@as(u16, @truncate(queries.len))),
                .ancount = 0,
                .nscount = 0,
                .arcount = 0,
            },
            .question = queries,
        };
    }

    test query {
        const q = try query(std.testing.allocator, &[1][]const u8{"gr.ht."});
        try std.testing.expectEqual(
            @as(u96, 32643419703672757439099305984),
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
    std.debug.print("All your {s} are belong to us.\n", .{"codebase"});

    const stdout_file = std.io.getStdOut().writer();
    var bw = std.io.bufferedWriter(stdout_file);
    const stdout = bw.writer();

    try stdout.print("Run `zig build test` to run the tests.\n", .{});

    try bw.flush();
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
