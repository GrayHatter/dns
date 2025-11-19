const ZoneCache = @This();

alloc: Allocator,
tld: std.StringHashMapUnmanaged(Zone) = .{},
strings: std.ArrayListUnmanaged(u8) = .{},
loc_table: std.HashMapUnmanaged(
    u32,
    void,
    std.hash_map.StringIndexContext,
    std.hash_map.default_max_load_percentage,
) = .{},

pub fn store(zc: *ZoneCache, str: []const u8) !Zone.String {
    try zc.strings.ensureUnusedCapacity(zc.alloc, str.len + 1);
    zc.strings.appendSliceAssumeCapacity(str);
    zc.strings.appendAssumeCapacity(0);

    const str_index: u32 = @intCast(zc.strings.items.len - str.len - 1);
    const key: []const u8 = zc.strings.items[str_index..][0..str.len :0];
    const gop = try zc.loc_table.getOrPutContextAdapted(
        zc.alloc,
        key,
        std.hash_map.StringIndexAdapter{ .bytes = &zc.strings },
        std.hash_map.StringIndexContext{ .bytes = &zc.strings },
    );

    if (gop.found_existing) {
        zc.strings.shrinkRetainingCapacity(str_index);
        return @enumFromInt(gop.key_ptr.*);
    } else {
        gop.key_ptr.* = str_index;
        return @enumFromInt(str_index);
    }
}

pub const Zone = struct {
    name: String,
    zones: std.ArrayHashMapUnmanaged(Zone, void, Hasher, false) = .{},
    behavior: Behavior = .new,
    hits: u32 = 0,

    pub const String = enum(u32) {
        empty,
        _,

        pub fn slice(str: String, zc: *const ZoneCache) [:0]const u8 {
            const s = zc.strings.items[@intFromEnum(str)..];
            const end = std.mem.indexOfScalar(u8, s, 0).?;
            return s[0..end :0];
        }
    };

    pub const Hasher = struct {
        pub fn hash(_: Hasher, a: Zone) u32 {
            return @truncate(std.hash.int(@intFromEnum(a.name)));
        }

        pub fn eql(_: Hasher, a: Zone, b: Zone, _: usize) bool {
            return a.name == b.name;
        }
    };
};

pub const Behavior = union(enum) {
    new: void,
    nxdomain: u32,
    cached: Behavior.Result,

    pub const Result = struct {
        expires: Io.Timestamp = .zero,
        a: ArrayList(Ip4) = .{},
        aaaa: ArrayList(Ip6) = .{},
        cname: ArrayList(u8) = .{},
    };
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const ArrayList = std.ArrayList;
const Ip4 = Io.net.Ip4Address;
const Ip6 = Io.net.Ip6Address;
