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
        z: u3,
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

        pub const Type = u16;

        pub const Class = u16;
    };

    pub const Resource = struct {
        name: void,
        rtype: u16,
        class: u16,
        ttl: u32,
        rdlength: u16,
        data: void,
    };

    pub const Authority = struct {};

    pub const Additional = struct {};
};

pub const Label = struct {};

test "Message.Header" {
    const thing: Message.Header = .{
        .id = 16,
        .qr = false,
        .opcode = 0,
        .aa = true,
        .tc = false,
        .rd = false,
        .ra = false,
        .z = 0,
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
