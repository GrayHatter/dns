alloc: Allocator,
tld: std.StringHashMapUnmanaged(Zone) = .empty,
strings: ArrayList(u8) = .empty,
loc_table: std.HashMapUnmanaged(u32, void, Context, 80) = .empty,

const ZoneCache = @This();
pub var mutex: std.Io.Mutex = .init;

const Adapter = std.hash_map.StringIndexAdapter;
const Context = std.hash_map.StringIndexContext;

pub fn store(zc: *ZoneCache, str: []const u8, io: Io) !Zone.String {
    try mutex.lock(io);
    defer mutex.unlock(io);
    try zc.strings.ensureUnusedCapacity(zc.alloc, str.len + 1);
    zc.strings.appendSliceAssumeCapacity(str);
    zc.strings.appendAssumeCapacity(0);

    const str_index: u32 = @intCast(zc.strings.items.len - str.len - 1);
    const key: []const u8 = zc.strings.items[str_index..][0..str.len :0];
    const gop = try zc.loc_table.getOrPutContextAdapted(
        zc.alloc,
        key,
        Adapter{ .bytes = &zc.strings },
        Context{ .bytes = &zc.strings },
    );

    if (gop.found_existing) {
        zc.strings.shrinkRetainingCapacity(str_index);
        return @fromBackingInt(@intCast(gop.key_ptr.*));
    } else {
        gop.key_ptr.* = str_index;
        return @fromBackingInt(@intCast(str_index));
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
            const idx = @backingInt(str);
            const end = findScalarPos(u8, zc.strings, idx, 0).?;
            return zc.strings[idx..end :0];
        }
    };

    pub const Hasher = struct {
        pub fn hash(_: Hasher, a: Zone) u32 {
            return @truncate(std.hash.int(@backingInt(a.name)));
        }

        pub fn eql(_: Hasher, a: Zone, b: Zone, _: usize) bool {
            return a.name == b.name;
        }
    };
};

pub const Behavior = union(enum) {
    new: void,
    nxdomain: u32,
    cached: Result,

    pub const Result = struct {
        expires: Io.Timestamp = .zero,

        a: ArrayList(Ip4) = .empty,
        aaaa: ArrayList(Ip6) = .empty,
        cname: ArrayList(u8) = .empty,
    };
};

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const findScalarPos = std.mem.findScalarPos;
const ArrayList = std.ArrayList;
const Ip4 = Io.net.Ip4Address;
const Ip6 = Io.net.Ip6Address;
