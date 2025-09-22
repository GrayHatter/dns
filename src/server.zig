var blocked_ips: []const [4]u8 = &[0][4]u8{};

const upstreams: [4]DaemonPeer = .{
    .cloudflare_0,
    .cloudflare_1,
    .google_0,
    .google_1,
};

pub const std_options: std.Options = .{
    .log_level = .warn,
    .logFn = logFunc,
};

var log_target_level: log.Level = .warn;

pub fn logFunc(
    comptime message_level: log.Level,
    comptime _: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) > @intFromEnum(log_target_level)) return;

    var buffer: [64]u8 = undefined;
    const stderr = std.debug.lockStderrWriter(&buffer);
    defer std.debug.unlockStderrWriter();
    nosuspend stderr.print(format ++ "\n", args) catch return;
}

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

fn cachedAnswer(
    qid: u16,
    name: []const u8,
    qdcount: u16,
    qtype: DNS.Message.Type,
    domain: *const Domain,
    zone: *Zone,
    downstream: network.Peer,
    addr: std.net.Address,
) !bool {
    var res_buff: [20]RData = undefined;
    const now: Timestamp = .init(std.time.timestamp());
    zone.hits += 1;
    log.err("{} hits for domain {s}", .{ zone.hits, name });
    var ans_bytes: [512]u8 = undefined;
    switch (zone.behavior) {
        .nxdomain => {
            if (qdcount == 1) {
                const ans: DNS.Message = try .answerDrop(qid, name, &ans_bytes);
                try downstream.sendTo(addr, ans.bytes);
                log.err("dropping request for {s}", .{name});
                return true;
            }
            log.err("unable to drop complex record for {s}", .{name});
            return false;
        },
        .cached => |c_result| {
            if (c_result.expires.expired(now)) {
                log.err(
                    "cached {s} ttl expired {} ({})",
                    .{ domain.zone, @intFromEnum(now) - @intFromEnum(c_result.expires), c_result.expires },
                );
                return false;
            }
            switch (qtype) {
                .a => {
                    if (c_result.a.items.len == 0) {
                        log.err("a request is null {s}", .{domain.zone});
                        return false;
                    }
                    const res_list: []RData = res_buff[0..c_result.a.items.len];
                    for (c_result.a.items, res_list) |src, *dst| {
                        dst.* = .{ .a = src };
                    }
                    const ans: DNS.Message = try .answer(qid, &[1]DNS.Message.AnswerData{
                        .{ .fqdn = name, .ips = res_list },
                    }, &ans_bytes);
                    log.info("cached answer {any}", .{ans.bytes});
                    //std.time.sleep(100_000);
                    try downstream.sendTo(addr, ans.bytes);
                    return true;
                },

                .aaaa => {
                    log.info("cached {s}", .{domain.zone});
                    if (c_result.aaaa.items.len == 0) {
                        log.err("aaaa request is null {s}", .{domain.zone});
                        return false;
                    }
                    const res_list: []RData = res_buff[0..c_result.aaaa.items.len];
                    for (c_result.aaaa.items, res_list) |src, *dst| {
                        dst.* = .{ .aaaa = src };
                    }
                    const ans: DNS.Message = try .answer(qid, &[1]DNS.Message.AnswerData{
                        .{ .fqdn = name, .ips = res_list },
                    }, &ans_bytes);
                    try downstream.sendTo(addr, ans.bytes);
                    std.debug.print("{f}\n", .{ans.header});
                    return true;
                },
                else => return false,
            }
        },

        else => log.err("zone {s}", .{domain.zone}),
    }
    return false;
}

fn core(
    a: Allocator,
    cache: *ZoneCache,
    in_msg: []const u8,
    downstream: network.Peer,
    addr: std.net.Address,
    upstream: network.Peer,
) !bool {
    const now: Timestamp = .init(std.time.timestamp());
    const msg = try DNS.Message.fromBytes(in_msg);

    log.err("incoming packet\n{f}", .{msg.header});

    if (msg.header.qdcount >= 16) {
        log.err("dropping invalid msg", .{});
        log.debug("that message {any}", .{in_msg});
        return true;
    }

    var iter = msg.iterator();
    while (iter.next() catch |err| e: {
        log.err("question iter error {}", .{err});
        log.err("qdata {any}", .{in_msg});
        break :e null;
    }) |pay| switch (pay) {
        .question => |q| {
            log.debug("name {s}", .{q.name});

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
            if (tld.zones.getKeyPtr(lzone)) |zone| {
                if (try cachedAnswer(
                    msg.header.id,
                    q.name,
                    msg.header.qdcount,
                    q.qtype,
                    &domain,
                    zone,
                    downstream,
                    addr,
                )) {
                    return true;
                }
            } else {
                log.err("cache missing going to upstream", .{});
            }
        },
        .answer => break,
    };

    log.err("hitting upstream {any}", .{@as(*const [4]u8, @ptrCast(&upstream.addr.in.sa.addr))});
    //log.info("bounce", .{});
    try upstream.send(in_msg);
    var relay_buf: [1024]u8 = undefined;
    const b_cnt = upstream.recv(&relay_buf) catch |err| again: switch (err) {
        error.WouldBlock => {
            //try upstream.send(in_msg);
            break :again upstream.recv(&relay_buf) catch |err2| {
                log.err("unable to communicate with upstream {f} timed out twice", .{upstream.addr});
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
        log.err("out of order messages with upstream {f} resetting", .{upstream.addr});
        return error.OutOfOrderMessages;
    }

    for (blocked_ips) |banned| {
        if (std.mem.eql(u8, relayed[relayed.len - 4 .. relayed.len], &banned)) {
            @memset(relayed[relayed.len - 4 .. relayed.len], 0);
        }
    }

    //std.debug.print("{x}\n", .{relay_buf[0..b_cnt]});

    try downstream.sendTo(addr, relay_buf[0..b_cnt]);

    const rmsg: DNS.Message = try .fromBytes(relayed);
    if (rmsg.header.qdcount != 1) return false;

    log.err("answer from upstream:\n{f}", .{rmsg.header});

    var lzone: Zone = undefined;
    var tld: *Zone = undefined;
    var suggested: DNS.Message.TTL = .@"5min";

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
            log.debug("r question = {s}", .{q.name});
            log.debug("r question = \n{f}", .{q});
            log.err("{f}", .{q});
        },
        .answer => |r| {
            suggested = suggested.min(r.ttl);
            log.debug("r answer      = {s: <6} -> {s} ", .{ @tagName(r.rtype), r.name });
            log.debug("r               {}", .{r.data});
            log.debug("r question = \n{f}", .{r});
            log.err("{f}", .{r});
            if (tld.zones.getOrPut(a, lzone)) |gop| {
                const zone = gop.key_ptr;
                if (!gop.found_existing) {
                    zone.behavior = .new;
                }
                switch (zone.behavior) {
                    .new => {
                        zone.behavior = .{
                            .cached = .{ .expires = now, .a = .{}, .aaaa = .{} },
                        };
                    },
                    .cached => {
                        if (zone.behavior.cached.expires.expired(now)) {
                            zone.behavior.cached.a.clearRetainingCapacity();
                            zone.behavior.cached.aaaa.clearRetainingCapacity();
                        }
                        zone.behavior.cached.expires = now.ttl(suggested);
                    },
                    .nxdomain => {},
                }

                switch (r.rtype) {
                    .a => try zone.behavior.cached.a.append(a, r.data.a),
                    .aaaa => try zone.behavior.cached.aaaa.append(a, r.data.aaaa),
                    .soa => {
                        log.err("r               {s}", .{r.data.soa.mname});
                        log.err("r               {s}", .{r.data.soa.rname});
                    },
                    else => {},
                }
                continue;
            } else |err| return err;
        },
    };
    return false;
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

    var cache: ZoneCache = .{ .alloc = a };

    const preload_tlds = [_][]const u8{ "com", "net", "org", "tv", "ht", "rs" };
    for (preload_tlds) |ptld| {
        try cache.tld.put(a, ptld, .{
            .name = try cache.store(ptld),
        });
    }

    for (blocks.items) |b| {
        a.free(try parse(a, b));
    }

    const file_hosts = try readFile("/etc/hosts");
    log.debug("file\n {s}", .{file_hosts});
    const host_lines = try parse(a, file_hosts);
    for (host_lines) |line| {
        std.debug.print("host line {s} {f}\n", .{ line.fqdn, line.addr });
    }
    a.free(host_lines);

    for (blocked_domains.items) |dd| {
        const domain: Domain = .init(dd);
        log.err("tld {s}", .{domain.tld});
        const tldgop = try cache.tld.getOrPut(a, domain.tld);
        if (!tldgop.found_existing) {
            tldgop.value_ptr.* = .{
                .name = try cache.store(domain.tld),
            };
        }
        var tld = tldgop.value_ptr;
        log.err("zone {s}", .{domain.zone});
        const str = try cache.store(domain.zone);
        _ = try tld.zones.getOrPut(a, .{
            .name = str,
            .behavior = .{ .nxdomain = 300 },
        });
    }

    var upconns: [4]network.Peer = undefined;
    for (&upconns, upstreams) |*dst, ip| {
        dst.* = try .connect(ip.addr.v4, 53);
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
        log.debug("received from {any}", .{@as(*const [4]u8, @ptrCast(&addr.in.sa.addr))});
        //const current_time = std.time.timestamp();
        //try tpool.spawn(managedCore, .{ a, &cache, buffer[0..icnt], downstream, addr, upconns[up_idx] });

        const cached = core(a, &cache, buffer[0..icnt], downstream, addr, upconns[up_idx]) catch |err| switch (err) {
            error.WouldBlock => continue,
            error.OutOfOrderMessages => continue,
            else => {
                log.err("core error: {}", .{err});
                return err;
            },
        };
        if (cached) {
            log.err("cached response {d}us", .{timer.lap() / 1000});
        } else {
            log.err("{f} responded {d}us", .{ upconns[up_idx], timer.lap() / 1000 });
        }
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

pub const Timestamp = enum(i64) {
    zero = 0,
    _,

    pub fn init(now: i64) Timestamp {
        return @enumFromInt(now);
    }

    pub fn expired(ts: Timestamp, now: Timestamp) bool {
        const ts_s: i64 = @intFromEnum(ts);
        const now_s: i64 = @intFromEnum(now);
        return ts_s < now_s;
    }

    pub fn ttl(ts: Timestamp, ttl_: DNS.Message.TTL) Timestamp {
        return @enumFromInt(@intFromEnum(ts) +| @intFromEnum(ttl_));
    }
};

pub const Behavior = union(enum) {
    new: void,
    nxdomain: u32,
    cached: Behavior.Result,

    pub const Result = struct {
        expires: Timestamp = .zero,
        a: ArrayList(IPv4) = .{},
        aaaa: ArrayList(IPv6) = .{},
        cname: ArrayList(u8) = .{},
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
            return @truncate(std.hash.int(@intFromEnum(a.name)));
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

pub const IPv4 = [4]u8;
pub const IPv6 = [16]u8;

const NetAddress = union(enum) {
    v4: IPv4,
    v6: IPv6,
};

const DaemonPeer = struct {
    addr: NetAddress,

    pub const cloudflare_0: DaemonPeer = .{ .addr = .{ .v4 = .{ 1, 1, 1, 1 } } };
    pub const cloudflare_1: DaemonPeer = .{ .addr = .{ .v4 = .{ 1, 0, 0, 1 } } };
    pub const google_0: DaemonPeer = .{ .addr = .{ .v4 = .{ 8, 8, 8, 8 } } };
    pub const google_1: DaemonPeer = .{ .addr = .{ .v4 = .{ 8, 8, 4, 4 } } };
};

const RecordAddress = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,

    pub fn format(addr: RecordAddress, w: *std.Io.Writer) !void {
        switch (addr) {
            .a => |a| try w.print("{d}.{d}.{d}.{d}", .{ a[0], a[1], a[2], a[3] }),
            .aaaa => |aaaa| try w.print("{x}", .{aaaa}),
        }
    }
};

const Result = struct {
    fqdn: []const u8,
    addr: RecordAddress,
};

fn parseA(str: []const u8) !RecordAddress {
    switch (std.mem.count(u8, str, ".")) {
        else => return error.InvalidAddress,
        1...2 => return error.NotImplemented,
        3 => {},
    }
    var addr: RecordAddress = .{ .a = @splat(0) };
    var itr = std.mem.tokenizeScalar(u8, str, '.');
    var i: u8 = 0;
    while (itr.next()) |oct| {
        addr.a[i] = try std.fmt.parseInt(u8, oct, 10);
        i += 1;
    }
    return addr;
}

fn parseAAAA(_: []const u8) !RecordAddress {
    return .{ .aaaa = @splat(0) };
}

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

fn parseLine(a: Allocator, line: []const u8, list: *ArrayList(Result)) !void {
    const trimmed = std.mem.trim(u8, line, &std.ascii.whitespace);
    if (trimmed.len == 0) return error.Skip;
    if (trimmed[0] == '#') {
        log.debug("skip '{s}'", .{line});
        return error.Skip;
    }

    if (indexOfAny(u8, trimmed, &std.ascii.whitespace)) |i| {
        const addr = trimmed[0..i];
        const names = std.mem.trim(u8, trimmed[i..], &std.ascii.whitespace);

        const r_addr = if (indexOfScalar(u8, addr, ':')) |_|
            try parseAAAA(std.mem.trim(u8, addr, &std.ascii.whitespace))
        else
            try parseA(std.mem.trim(u8, addr, &std.ascii.whitespace));

        var names_itr = std.mem.tokenizeAny(u8, names, &std.ascii.whitespace);
        while (names_itr.next()) |name| {
            const parsed = parseFQDN(name) catch |err| {
                log.err("fqdn error {}", .{err});
                continue;
            };
            try list.append(a, .{ .fqdn = parsed, .addr = r_addr });
        }
    }
}

test parseLine {
    const a = std.testing.allocator;
    var list: ArrayList(Result) = .{};
    defer list.clearAndFree(a);

    try parseLine(a, "127.0.0.1 blerg", &list);

    try std.testing.expectEqual(@as(usize, 1), list.items.len);
    try std.testing.expectEqualDeep(Result{ .fqdn = "blerg", .addr = .{ .a = .{ 127, 0, 0, 1 } } }, list.items[0]);
    try parseLine(a, "127.0.0.1 blerg blerg blerg", &list);
    try std.testing.expectEqual(@as(usize, 4), list.items.len);
    try std.testing.expectEqualDeep(Result{ .fqdn = "blerg", .addr = .{ .a = .{ 127, 0, 0, 1 } } }, list.items[1]);
    try std.testing.expectEqualDeep(Result{ .fqdn = "blerg", .addr = .{ .a = .{ 127, 0, 0, 1 } } }, list.items[2]);
    try std.testing.expectEqualDeep(Result{ .fqdn = "blerg", .addr = .{ .a = .{ 127, 0, 0, 1 } } }, list.items[3]);
}

fn parse(a: Allocator, blob: []const u8) ![]Result {
    // 21 bytes per line for the test file
    const base_count = blob.len / 21;
    var list: ArrayList(Result) = try .initCapacity(a, base_count);
    errdefer list.clearAndFree(a);

    var lines_itr = std.mem.tokenizeScalar(u8, blob, '\n');
    while (lines_itr.next()) |line| {
        parseLine(a, line, &list) catch continue;
    }

    return try list.toOwnedSlice(a);
}

test main {
    _ = &main;
}

const DNS = @import("dns.zig");
const network = @import("network.zig");
const RData = DNS.Message.Resource.RData;

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const indexOfAny = std.mem.indexOfAny;
const indexOfScalar = std.mem.indexOfScalar;
