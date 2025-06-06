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
) !void {
    const curr_time: u32 = @intCast(@as(i32, @truncate(std.time.timestamp())));
    const msg = try DNS.Message.fromBytes(in_msg);

    if (msg.header.qdcount >= 16) {
        log.err("dropping invalid msg", .{});
        log.debug("that message {any}", .{in_msg});
        return;
    }

    var iter = msg.iterator();
    while (iter.next() catch |err| e: {
        log.err("question iter error {}", .{err});
        log.err("qdata {any}", .{in_msg});
        break :e null;
    }) |pay| switch (pay) {
        .question => |q| {
            log.err("name {s}", .{q.name});

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
                            log.info("cached {s}", .{domain.zone});
                            if (c_result.ttl > curr_time) {
                                const rdata = [1]DNS.Message.Resource.RData{switch (q.qtype) {
                                    .a => .{ .a = c_result.a orelse continue },
                                    .aaaa => .{ .aaaa = c_result.aaaa orelse continue },
                                    else => continue,
                                }};

                                const ans: DNS.Message = try .answer(
                                    msg.header.id,
                                    &[1][]const u8{q.name},
                                    &rdata,
                                    &ans_bytes,
                                );
                                log.debug("cached answer {any}", .{ans.bytes});
                                //std.time.sleep(100_000);
                                try downstream.sendTo(addr, ans.bytes);
                                return;
                            } else log.err("cached {s} ttl expired {}", .{ domain.zone, c_result.ttl });
                        },
                        else => log.err("zone {s}", .{domain.zone}),
                    }
                } else {
                    log.err("cache missing", .{});
                }
            } else |e| return e;
        },
        .answer => break,
    };

    log.err("hitting upstream {any}", .{upstream.addr});
    //log.info("bounce", .{});
    try upstream.send(in_msg);
    var relay_buf: [1024]u8 = undefined;
    const b_cnt = upstream.recv(&relay_buf) catch |err| again: switch (err) {
        error.WouldBlock => {
            //try upstream.send(in_msg);
            break :again upstream.recv(&relay_buf) catch |err2| {
                log.err("unable to communicate with upstream {} timed out twice", .{upstream.addr});
                return err2;
            };
        },
        else => return err,
    };
    const relayed = relay_buf[0..b_cnt];
    log.info("bounce received {}", .{b_cnt});
    log.debug("bounce data {any}", .{relayed});
    if (!std.mem.eql(u8, relay_buf[0..2], in_msg[0..2])) {
        // drop 2 messages or 2 timeouts
        _ = upstream.recv(&relay_buf) catch 0;
        _ = upstream.recv(&relay_buf) catch 0;
        log.err("out of order messages with upstream {} resetting", .{upstream.addr});
        return error.OutOfOrderMessages;
    }

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
        log.err("rdata {any}", .{relayed});
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
            log.debug("r               {}", .{r.data});
            log.debug("r question = {}", .{r});
            if (tld.zones.getKeyPtr(lzone)) |zone| {
                switch (zone.behavior) {
                    .new, .cached => {
                        zone.behavior = .{ .cached = .{
                            .ttl = @intCast(curr_time + min_ttl),
                        } };
                        switch (r.rtype) {
                            .a => zone.behavior.cached.a = r.data.a,
                            .aaaa => zone.behavior.cached.aaaa = r.data.aaaa,
                            else => continue,
                        }
                        break;
                    },
                    .nxdomain => {},
                }
            }
        },
    };
}

fn managedCore(
    a: Allocator,
    cache: *ZoneCache,
    in_msg: []const u8,
    downstream: network.Peer,
    addr: std.net.Address,
    upstream: network.Peer,
) void {
    core(a, cache, in_msg, downstream, addr, upstream) catch |err| switch (err) {
        error.WouldBlock => return,
        error.OutOfOrderMessages => return,
        else => {
            log.err("core error: {}", .{err});
            @panic("unreachable");
        },
    };
}

var blocked_ips: []const [4]u8 = &[0][4]u8{};

pub fn main() !void {
    const a = std.heap.smp_allocator;

    var blocks: std.ArrayListUnmanaged([]const u8) = .{};
    var blocked_ips_: std.ArrayListUnmanaged([4]u8) = .{};
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
            try blocked_ips_.append(a, ip);
        } else if (std.mem.eql(u8, arg, "--drop-domain")) {
            const domain_str = argv.next() orelse usage(arg0, "<fqdn> missing for --drop-domain");
            try blocked_domains.append(a, try a.dupe(u8, domain_str));
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            usage(arg0, null);
        } else {
            usage(arg0, "invalid arg given");
        }
    }
    blocked_ips = blocked_ips_.items;

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

    const file_hosts = try readFile("/etc/hosts");
    std.debug.print("file \n{s}\n", .{file_hosts});
    const host_lines = try parse(a, file_hosts);
    for (host_lines) |line| std.debug.print("host line {any}\n", .{line});
    a.free(host_lines);

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

    var tpool: std.Thread.Pool = undefined;
    try tpool.init(.{ .allocator = a, .n_jobs = 4 });

    var timer: std.time.Timer = try .start();
    while (true) {
        defer up_idx +%= 1;
        var addr: std.net.Address = .{ .in = .{ .sa = .{ .port = 0, .addr = 0 } } };
        var buffer: [1024]u8 = undefined;
        const icnt = try downstream.recvFrom(&buffer, &addr);
        timer.reset();
        log.info("received {}", .{icnt});
        log.debug("data {any}", .{buffer[0..icnt]});
        log.warn("received from {any}", .{addr.in});
        //const current_time = std.time.timestamp();
        //try tpool.spawn(managedCore, .{ a, &cache, buffer[0..icnt], downstream, addr, upconns[up_idx] });

        core(
            a,
            &cache,
            buffer[0..icnt],
            downstream,
            addr,
            upconns[up_idx],
        ) catch |err| switch (err) {
            error.WouldBlock => continue,
            error.OutOfOrderMessages => continue,
            else => {
                log.err("core error: {}", .{err});
                return err;
            },
        };

        log.err("responded {d}", .{@as(f64, @floatFromInt(timer.lap())) / 1000});
    }

    log.err("done", .{});
}

fn readFile(name: []const u8) ![]const u8 {
    var file = try std.fs.cwd().openFile(name, .{ .mode = .read_only });
    defer file.close();
    return try mmap(file);
}

fn mmap(fd: std.fs.File) ![]const u8 {
    const stat = try fd.stat();

    const ptr: [*]u8 = @ptrFromInt(std.os.linux.mmap(
        null,
        stat.size,
        std.os.linux.PROT.READ,
        std.os.linux.MAP{ .TYPE = .PRIVATE },
        fd.handle,
        0,
    ));
    return ptr[0..stat.size];
}

fn munmap(ptr: []const u8) !void {
    std.os.linux.munmap(ptr.ptr, ptr.len);
}

pub const Behavior = union(enum) {
    new: void,
    nxdomain: u32,
    cached: Behavior.Result,

    pub const Result = struct {
        ttl: u32 = 0,
        a: ?[4]u8 = null,
        aaaa: ?[16]u8 = null,
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

pub const std_options: std.Options = .{
    .log_level = .warn,
};

const Result = struct {
    fqdn: []const u8,
    addr: union(enum) {
        a: [4]u8,
        aaaa: [16]u8,
    },
};

fn parseA() void {}

fn parseAAAA() void {}

fn parseFQDN(in: []const u8) ![]const u8 {
    const trimmed = std.mem.trim(u8, in, &std.ascii.whitespace);
    if (trimmed.len == 0) return error.NoFQDN;
    var end: usize = 0;
    for (trimmed) |char| {
        switch (char) {
            'a'...'z',
            'A'...'Z',
            '0'...'9',
            '-',
            '.',
            => {},
            ' ', '\t', '\n' => break,
            else => return error.InvalidChar,
        }
        end += 1;
    }

    if (end == 0) return error.NoFQDN;
    return trimmed[0..end];
}

fn parseLine(line: []const u8) !Result {
    const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
    if (trimmed.len == 0) return error.Skip;
    if (trimmed[0] == '#') {
        log.debug("skip '{s}'", .{line});
        return error.Skip;
    }

    const name = if (indexOfAny(u8, trimmed, &std.ascii.whitespace)) |i| parseFQDN(trimmed[i..]) catch |err| {
        log.debug("fqdn error {}", .{err});
        return error.Skip;
    } else return error.Skip;

    if (indexOfScalar(u8, trimmed, ':')) |_| {
        return .{ .fqdn = name, .addr = .{ .aaaa = @splat(0) } };
    } else {
        return .{ .fqdn = name, .addr = .{ .a = @splat(0) } };
    }
}

fn parse(a: Allocator, blob: []const u8) ![]Result {
    // 21 bytes per line for the test file
    const base_count = blob.len / 21;

    var fbs = std.io.fixedBufferStream(blob);
    var reader = fbs.reader();

    var list = try std.ArrayListUnmanaged(Result).initCapacity(a, base_count);
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
const indexOfAny = std.mem.indexOfAny;
const indexOfScalar = std.mem.indexOfScalar;
