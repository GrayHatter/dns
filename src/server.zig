fn usage(arg0: []const u8, err: ?[]const u8) noreturn {
    if (err) |e| {
        std.debug.print("Error: {s}\n\n", .{e});
    }

    std.debug.print(
        \\Usage: {s} [options]
        \\
        \\Config Options: 
        \\  -c, --config             - [ ] TODO document
        \\                           - [ ] add config support
        \\
        \\Custom Blocking Options:
        \\  --block <config_file>    TODO document
        \\  --drop-ip <ip address>   Rewrites any matching IP address to 0.0.0.0
        \\  --drop-domain <fqdn>     Returns NXDOMAIN for any queries for given fqdn
        \\
    , .{arg0});
    std.posix.exit(1);
}

fn core(
    a: Allocator,
    cache: *ZoneCache,
    in_msg: []const u8,
    downstream: network.Peer,
    addr: std.net.Address,
    upstream: network.Peer,
    blocked_ips: []const [4]u8,
) !void {
    const curr_time: u32 = @intCast(@as(i32, @truncate(std.time.timestamp())));
    const msg = try DNS.Message.fromBytes(in_msg);

    var qdomains: [16][255]u8 = undefined;
    var dbuf: [16][]const u8 = undefined;
    var domains: std.ArrayListUnmanaged([]const u8) = .{
        .items = &dbuf,
        .capacity = dbuf.len,
    };
    domains.items.len = 0;

    if (msg.header.qdcount >= 16) {
        log.err("dropping invalid msg", .{});
        log.debug("that message {any}", .{in_msg});
        return;
    }

    var iter = msg.iterator();
    while (iter.next() catch |err| e: {
        log.err("question iter error {}", .{err});
        log.debug("qdata {any}", .{in_msg});
        break :e null;
    }) |pay| switch (pay) {
        .question => |q| {
            log.err("name {s}", .{q.name});
            @memcpy(qdomains[iter.index][0..q.name.len], q.name);
            domains.appendAssumeCapacity(qdomains[iter.index][0..q.name.len]);

            const domain: Domain = .init(q.name);
            const tld: *Zone = f: {
                if (cache.tld.getOrPut(a, domain.tld)) |goptr| {
                    if (!goptr.found_existing) {
                        goptr.key_ptr.* = try a.dupe(u8, domain.tld);
                        goptr.value_ptr.* = .{
                            .name = try cache.store(domain.zone),
                        };
                    }
                    goptr.value_ptr.hits += 1;
                    break :f goptr.value_ptr;
                } else |err| {
                    log.err("hash error {}", .{err});
                    break;
                }
            };

            const lzone: Zone = .{ .name = try cache.store(domain.zone) };
            if (tld.zones.getOrPut(a, lzone)) |zone| {
                if (zone.found_existing) {
                    log.err("{} hits on {s}", .{ zone.key_ptr.hits, domain.zone });
                    zone.key_ptr.hits += 1;
                    var ans_bytes: [512]u8 = undefined;
                    switch (zone.key_ptr.behavior) {
                        .nxdomain => {
                            if (msg.header.qdcount == 1) {
                                const ans: DNS.Message = try .answerDrop(msg.header.id, q.name, &ans_bytes);
                                try downstream.sendTo(addr, ans.bytes);
                                return;
                            }
                        },
                        .cached => |c_result| {
                            log.err("cached {s}", .{domain.zone});
                            if (c_result.ttl > curr_time) {
                                const ans: DNS.Message = try .answer(
                                    msg.header.id,
                                    &[1][]const u8{q.name},
                                    &[1]DNS.Message.Resource.RData{c_result.addr},
                                    &ans_bytes,
                                );
                                try downstream.sendTo(addr, ans.bytes);
                                return;
                            } else log.err("cached {s} ttl expired {}", .{ domain.zone, c_result.ttl });
                        },
                        else => log.err("zone {s}", .{domain.zone}),
                    }
                } else {
                    std.debug.print("cache missing \n", .{});
                }
            } else |e| return e;
        },
        .answer => break,
    };

    log.err("hitting upstream {any}", .{upstream.addr});
    //log.info("bounce", .{});
    try upstream.send(in_msg);
    var relay_buf: [1024]u8 = undefined;
    const b_cnt = try upstream.recv(&relay_buf);
    const relayed = relay_buf[0..b_cnt];
    //log.info("bounce received {}", .{b_cnt});
    //log.debug("bounce data {any}", .{relayed});

    for (blocked_ips) |banned| {
        if (std.mem.eql(u8, relayed[relayed.len - 4 .. relayed.len], &banned)) {
            @memset(relayed[relayed.len - 4 .. relayed.len], 0);
        }
    }

    try downstream.sendTo(addr, relay_buf[0..b_cnt]);

    const rmsg: DNS.Message = try .fromBytes(relayed);
    if (rmsg.header.qdcount != 1) return;

    var lzone: Zone = undefined;
    var tld: *Zone = undefined;
    var min_ttl: u32 = 0;
    min_ttl = ~min_ttl;

    var rit = rmsg.iterator();
    while (rit.next() catch |err| e: {
        log.err("relayed iter error {}", .{err});
        log.debug("rdata {any}", .{relayed});
        break :e null;
    }) |pay| switch (pay) {
        .question => |q| {
            const domain: Domain = .init(q.name);
            tld = f: {
                if (cache.tld.getOrPut(a, domain.tld)) |goptr| {
                    if (!goptr.found_existing) {
                        goptr.key_ptr.* = try a.dupe(u8, domain.tld);
                        goptr.value_ptr.* = .{
                            .name = try cache.store(domain.zone),
                        };
                    }
                    goptr.value_ptr.hits += 1;
                    break :f goptr.value_ptr;
                } else |err| {
                    log.err("hash error {}", .{err});
                    break;
                }
            };
            lzone = .{ .name = try cache.store(domain.zone) };
            //log.err("r question = {s}", .{q.name});
            //log.debug("r question = {}", .{q});
        },
        .answer => |r| {
            min_ttl = @min(min_ttl, r.ttl);
            log.err("r answer      = {s} ", .{r.name});
            log.err("r     rtype   = {}", .{r.rtype});
            log.err("r               {}", .{r.data});
            log.debug("r question = {}", .{r});
            switch (r.rtype) {
                .a => {
                    if (tld.zones.getKeyPtr(lzone)) |zone| {
                        switch (zone.behavior) {
                            .new, .cached => {
                                zone.behavior = .{ .cached = .{
                                    .ttl = @intCast(curr_time + min_ttl),
                                    .addr = r.data,
                                } };
                            },
                            .nxdomain => {},
                        }
                    }
                },
                .aaaa => {},
                .cname => {},
                else => {},
            }
        },
    };
}

pub fn main() !void {
    const a = std.heap.smp_allocator;

    var blocks: std.ArrayListUnmanaged([]const u8) = .{};
    var blocked_ips: std.ArrayListUnmanaged([4]u8) = .{};
    var blocked_domains: std.ArrayListUnmanaged([]const u8) = .{};

    var argv = std.process.args();
    const arg0 = argv.next().?;
    while (argv.next()) |arg| {
        if (std.mem.eql(u8, arg, "--block")) {
            try blocks.append(a, argv.next() orelse usage(arg0, "<config file> missing for --block"));
        } else if (std.mem.eql(u8, arg, "--drop-ip")) {
            const ip_str = argv.next() orelse usage(arg0, "<ip address> missing for --drop-ip");
            var ip: [4]u8 = undefined;
            var itr = std.mem.splitScalar(u8, ip_str, '.');
            for (&ip) |*oct| {
                oct.* = std.fmt.parseInt(u8, itr.next() orelse "0", 10) catch 0;
            }
            try blocked_ips.append(a, ip);
        } else if (std.mem.eql(u8, arg, "--drop-domain")) {
            const domain_str = argv.next() orelse usage(arg0, "<fqdn> missing for --drop-domain");
            try blocked_domains.append(a, try a.dupe(u8, domain_str));
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            usage(arg0, null);
        } else {
            usage(arg0, "invalid arg given");
        }
    }

    const downstream: network.Peer = try .listen(.{ 0, 0, 0, 0 }, 53);

    // nobody on my machine
    if (std.os.linux.getuid() == 0) {
        log.err("dropping root", .{});
        _ = try std.posix.setgid(99);
        _ = try std.posix.setuid(99);
    }

    log.err("started", .{});

    var cache: ZoneCache = .{
        .alloc = a,
    };

    const preload_tlds = [_][]const u8{ "com", "net", "org", "tv", "ht" };
    for (preload_tlds) |ptld| {
        try cache.tld.put(a, ptld, .{
            .name = try cache.store(ptld),
        });
    }

    for (blocks.items) |b| {
        a.free(try parse(a, b));
    }

    for (blocked_domains.items) |dd| {
        const domain: Domain = .init(dd);
        log.err("tld {s}", .{domain.tld});
        var tld = cache.tld.getPtr(domain.tld).?;
        log.err("zone {s}", .{domain.zone});
        const str = try cache.store(domain.zone);
        _ = try tld.zones.getOrPut(a, .{
            .name = str,
            .behavior = .{ .nxdomain = 300 },
        });
    }

    var upconns: [4]network.Peer = undefined;
    for (&upconns, upstreams) |*dst, ip| {
        dst.* = try .connect(ip, 53);
    }
    var up_idx: u2 = 0;

    //const msg = try DNS.Message.query(a, &[1][]const u8{domain orelse "gr.ht."});
    //var request: [1024]u8 = undefined;
    //const msgsize = try msg.write(&request);

    var timer: std.time.Timer = try .start();
    while (true) {
        var addr: std.net.Address = .{ .in = .{ .sa = .{ .port = 0, .addr = 0 } } };
        var buffer: [1024]u8 = undefined;
        const icnt = try downstream.recvFrom(&buffer, &addr);
        timer.reset();
        log.info("received {}", .{icnt});
        //log.err("data {any}", .{buffer[0..icnt]});
        log.warn("received from {any}", .{addr.in});
        //const current_time = std.time.timestamp();
        try core(
            a,
            &cache,
            buffer[0..icnt],
            downstream,
            addr,
            upconns[up_idx],
            blocked_ips.items,
        );

        log.err("responded {d}", .{@as(f64, @floatFromInt(timer.lap())) / 1000});

        up_idx +%= 1;
    }

    log.err("done", .{});
}

pub const Behavior = union(enum) {
    new: void,
    nxdomain: u32,
    cached: Result,

    pub const Result = struct {
        ttl: u32,
        addr: DNS.Message.Resource.RData,
    };
};

const Zone = struct {
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
            return @truncate(std.hash.uint32(@intFromEnum(a.name)));
        }

        pub fn eql(_: Hasher, a: Zone, b: Zone, _: usize) bool {
            return a.name == b.name;
        }
    };
};

const ZoneCache = struct {
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
};

pub const Domain = struct {
    tld: []const u8,
    zone: []const u8,

    pub fn init(dn: []const u8) Domain {
        if (dn.len < 3) return .{ .tld = dn, .zone = "" };
        var bit = std.mem.splitBackwardsScalar(
            u8,
            if (dn[dn.len - 1] == '.') dn[0 .. dn.len - 1] else dn,
            '.',
        );

        return .{
            .tld = bit.first(),
            .zone = bit.rest(),
        };
    }
};

const upstreams: [4][4]u8 = .{
    .{ 1, 1, 1, 1 },
    .{ 1, 0, 0, 1 },
    .{ 8, 8, 8, 8 },
    .{ 8, 8, 4, 4 },
};

fn parseLine(line: []const u8) ![]const u8 {
    if (line[0] == '#') return error.Skip;
    return line;
}

fn parse(a: Allocator, filename: []const u8) ![][]const u8 {
    var file = try std.fs.cwd().openFile(filename, .{});
    defer file.close();
    const fsize = try file.getEndPos();
    // 21 bytes per line for the test file
    const base_count = fsize / 21;
    var reader = file.reader();
    var list = try std.ArrayListUnmanaged([]const u8).initCapacity(a, base_count);
    errdefer list.clearAndFree(a);
    var lbuf: [1024]u8 = undefined;

    while (try reader.readUntilDelimiterOrEof(&lbuf, '\n')) |line| {
        try list.append(a, parseLine(line) catch continue);
    }

    return try list.toOwnedSlice(a);
}

test main {
    _ = &main;
}

const DNS = @import("dns.zig");
const network = @import("network.zig");

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
