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

    pub fn write(h: Header, w: *Writer) !usize {
        try w.writeInt(u96, @bitCast(h), .big);
        std.debug.assert(@sizeOf(Header) == 16);
        std.debug.assert(@divExact(@typeInfo(u96).int.bits, 8) == 12);
        return 12;
    }

    pub const answer: Header = .{
        .id = 0,
        .qr = true,
        .opcode = 0,
        .aa = true,
        .tc = false,
        .rd = true,
        .ra = true,
        .rcode = .name,
        .qdcount = 0,
        .ancount = 0,
        .nscount = 0,
        .arcount = 0,
    };
};

const std = @import("std");
const Writer = std.Io.Writer;
