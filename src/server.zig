var upstreams: Upstream = .{ .conns = undefined };

pub const std_options: std.Options = .{
    .log_level = .debug,
    .logFn = logFunc,
};

var log_level_target: log.Level = .warn;

pub fn logFunc(
    comptime message_level: log.Level,
    comptime _: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) > @intFromEnum(log_level_target)) return;

    var buffer: [512]u8 = undefined;
    const stderr, const errcfg = std.debug.lockStderrWriter(&buffer);
    _ = errcfg;
    defer std.debug.unlockStderrWriter();
    stderr.print(format ++ "\n", args) catch return;
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
        \\  --debug                 enable debugging output
        \\  --debug-extra           enable verbose debugging output
        \\
        \\Custom Blocking Options:
        \\  --block <config_file>    TODO document
        \\  --drop-ip <ip address>   Rewrites any matching IP address to 0.0.0.0
        \\  --drop-domain <fqdn>     Returns NXDOMAIN for any queries for given fqdn
        \\
    , .{arg0});
    std.posix.exit(1);
}

fn sendCachedAnswer(
    mheader: DNS.Message.Header,
    q: DNS.Message.Question,
    domain: *const Domain,
    zone: *Zone,
    downstream: net.Socket,
    addr: net.IpAddress,
    io: Io,
) !bool {
    var res_buff: [20]RData = undefined;
    var addr_list: ArrayList(RData) = .initBuffer(&res_buff);
    const now: Io.Timestamp = try Io.Clock.real.now(io);
    const duration: Io.Duration = if (zone.behavior == .cached) now.durationTo(zone.behavior.cached.expires) else .zero;
    zone.hits += 1;
    log.err("    {} hits ({}ms remain)", .{ zone.hits, duration.toMilliseconds() });
    var ans_bytes: [512]u8 = undefined;
    switch (zone.behavior) {
        .nxdomain => {
            if (mheader.qdcount == 1) {
                const ans: DNS.Message = try .answerDrop(mheader.id, q.name, &ans_bytes);
                try downstream.send(io, &addr, ans.bytes);
                log.err("dropping request for {s}", .{q.name});
                return true;
            }
            log.err("unable to drop complex record for {s}", .{q.name});
            return false;
        },
        .cached => |c_result| {
            if (c_result.expires.nanoseconds < now.nanoseconds) {
                log.debug(
                    "cached {s} ttl expired {} ({})",
                    .{ domain.zone, now.toSeconds() - c_result.expires.toSeconds(), c_result.expires },
                );
                return false;
            }
            switch (q.qtype) {
                .a => {
                    if (c_result.a.items.len == 0) {
                        log.err("    a request is null", .{});
                        return false;
                    }
                    for (c_result.a.items) |src| {
                        try addr_list.appendBounded(.{ .a = src.bytes });
                    }
                    const ans: DNS.Message = try .answer(
                        mheader.id,
                        &[1]DNS.Message.AnswerData{.{ .fqdn = q.name, .ips = addr_list.items }},
                        &ans_bytes,
                    );
                    log.info("cached answer {any}", .{ans.bytes});
                    //std.time.sleep(100_000);
                    try downstream.send(io, &addr, ans.bytes);
                    return true;
                },

                .aaaa => {
                    log.info("cached {s}", .{domain.zone});
                    if (c_result.aaaa.items.len == 0) {
                        log.err("    aaaa request is null", .{});
                        return false;
                    }
                    for (c_result.aaaa.items) |src| {
                        try addr_list.appendBounded(.{ .aaaa = src.bytes });
                    }
                    const ans: DNS.Message = try .answer(
                        mheader.id,
                        &[1]DNS.Message.AnswerData{.{ .fqdn = q.name, .ips = addr_list.items }},
                        &ans_bytes,
                    );
                    try downstream.send(io, &addr, ans.bytes);
                    log.info("{f}\n", .{ans.header});
                    return true;
                },
                else => return false,
            }
        },

        else => log.err("zone {s}", .{domain.zone}),
    }
    return false;
}

fn hitUpstream(
    net_msg: net.IncomingMessage,
    downstream: net.Socket,
    relay_buf: *[1024]u8,
    io: Io,
) !DNS.Message {
    const peer, const upstream = upstreams.get();
    var w = upstream.writer(io, &.{});
    var r = upstream.reader(io, relay_buf);
    log.warn("    hitting upstream {f}", .{peer.addr});
    var pollfds: [1]linux.pollfd = .{.{
        .fd = upstream.socket.handle,
        .events = std.math.maxInt(i16),
        .revents = 0,
    }};
    var timeout: linux.timespec = .{ .sec = 0, .nsec = 65 * ns_per_ms };
    var recv_msg: []u8 = &.{};
    while (true) : (pollfds[0].revents = 0) {
        try w.interface.writeAll(net_msg.data);
        try w.interface.flush();
        const ready = linux.ppoll(&pollfds, pollfds.len, &timeout, &sigset);
        if (ready == 0) continue;
        r.interface.fillMore() catch @panic("fixme");
        recv_msg = r.interface.buffered();
        if (std.mem.eql(u8, relay_buf[0..2], net_msg.data[0..2]))
            break;
        r.interface.tossBuffered();
    }
    log.info("bounce received {}", .{recv_msg.len});
    log.debug("bounce data {any}", .{recv_msg});

    for (blocked_ips) |banned| {
        if (eql(u8, recv_msg[recv_msg.len - 4 .. recv_msg.len], &banned)) {
            @memset(recv_msg[recv_msg.len - 4 .. recv_msg.len], 0);
        }
    }
    //std.debug.print("{x}\n", .{relay_buf[0..b_cnt]});
    try downstream.send(io, &net_msg.from, recv_msg);
    return try .fromBytes(recv_msg);
}

fn core(
    cache: *ZoneCache,
    net_msg: net.IncomingMessage,
    downstream: net.Socket,
    a: Allocator,
    io: Io,
) !bool {
    const msg: DNS.Message = try .fromBytes(net_msg.data);

    log.info("incoming packet\n{f}", .{msg.header});

    if (msg.header.qdcount >= 16) {
        log.err("dropping invalid msg", .{});
        log.debug("that message {any}", .{net_msg.data});
        return true;
    }

    var iter = msg.iterator();
    while (iter.next() catch |err| e: {
        log.err("question iter error {}", .{err});
        log.err("qdata {any}", .{net_msg.data});
        break :e null;
    }) |pay| switch (pay) {
        .question => |q| {
            log.err("query {}:  [ {s} ]", .{ q.qtype, q.name });
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
                if (sendCachedAnswer(msg.header, q, &domain, zone, downstream, net_msg.from, io)) |sent| {
                    if (sent) return true;
                } else |err| return err;
            } else {
                log.err("    cache missing going to upstream", .{});
            }
        },
        .answer => break,
    };

    var relay_buf: [1024]u8 = undefined;
    const rmsg: DNS.Message = try hitUpstream(net_msg, downstream, &relay_buf, io);
    if (rmsg.header.qdcount != 1) return false;

    log.debug("answer from upstream:\n{f}", .{rmsg.header});
    cacheAnswer(cache, rmsg, a, io) catch |err| {
        log.err("rdata {any}", .{relay_buf});
        return err;
    };

    return false;
}

fn cacheAnswer(cache: *ZoneCache, rmsg: DNS.Message, a: Allocator, io: Io) !void {
    const now: Io.Timestamp = try Io.Clock.real.now(io);

    var lzone: Zone = undefined;
    var tld: *Zone = undefined;
    var suggested: DNS.Message.TTL = .@"5min";

    var rit = rmsg.iterator();
    while (rit.next() catch |err| {
        log.err("relayed iter error {}", .{err});
        return err;
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
            log.info("{f}", .{q});
        },
        .answer => |r| {
            suggested.duration.nanoseconds = @min(r.ttl.duration.nanoseconds, suggested.duration.nanoseconds);
            log.debug("r answer      = {s: <6} -> {s} ", .{ @tagName(r.rtype), r.name });
            log.debug("r               {}", .{r.data});
            log.debug("r question = \n{f}", .{r});
            log.info("{f}", .{r});
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
                        if (zone.behavior.cached.expires.nanoseconds < now.nanoseconds) {
                            zone.behavior.cached.a.clearRetainingCapacity();
                            zone.behavior.cached.aaaa.clearRetainingCapacity();
                        }
                        zone.behavior.cached.expires = now.addDuration(suggested.duration);
                    },
                    .nxdomain => {},
                }

                switch (r.rtype) {
                    .a => try zone.behavior.cached.a.append(a, .{ .bytes = r.data.a, .port = 0 }),
                    .aaaa => try zone.behavior.cached.aaaa.append(a, .{ .bytes = r.data.aaaa, .port = 0 }),
                    .soa => {
                        log.debug("r               {s}", .{r.data.soa.mname});
                        log.debug("r               {s}", .{r.data.soa.rname});
                    },
                    else => {},
                }
                continue;
            } else |err| return err;
        },
    };
}

var blocked_ips: []const [4]u8 = &.{};
var downstream_pool: []?MsgPtr = &.{};
const MsgPtr = [1024]u8;

pub fn main() !void {
    const a = std.heap.smp_allocator;
    var threaded: std.Io.Threaded = .init(a);
    defer threaded.deinit();
    const io = threaded.io();

    downstream_pool = try a.alloc(?MsgPtr, 20);
    defer a.free(downstream_pool);
    for (downstream_pool) |*p| p.* = null;

    var blocks: ArrayList([]const u8) = .{};
    var blocked_ips_: ArrayList([4]u8) = .{};
    var blocked_domains: ArrayList([]const u8) = .{};

    var argv = std.process.args();
    const arg0 = argv.next().?;
    while (argv.next()) |arg| {
        if (eql(u8, arg, "--block")) {
            try blocks.append(a, argv.next() orelse usage(arg0, "<config file> missing for --block"));
        } else if (eql(u8, arg, "--drop-ip")) {
            const ip_str = argv.next() orelse usage(arg0, "<ip address> missing for --drop-ip");
            var ip: [4]u8 = undefined;
            var itr = std.mem.splitScalar(u8, ip_str, '.');
            for (&ip) |*oct| {
                oct.* = std.fmt.parseInt(u8, itr.next() orelse "0", 10) catch 0;
            }
            try blocked_ips_.append(a, ip);
        } else if (eql(u8, arg, "--drop-domain")) {
            const domain_str = argv.next() orelse usage(arg0, "<fqdn> missing for --drop-domain");
            try blocked_domains.append(a, try a.dupe(u8, domain_str));
        } else if (eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            usage(arg0, null);
        } else if (eql(u8, arg, "--debug")) {
            log_level_target = .info;
        } else if (eql(u8, arg, "--debug-extra")) {
            log_level_target = .debug;
        } else {
            usage(arg0, "invalid arg given");
        }
    }

    blocked_ips = blocked_ips_.items;

    const host: net.IpAddress = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 53 } };
    const downstream: net.Socket = try host.bind(io, .{ .mode = .dgram, .protocol = .udp });

    // nobody on my machine
    if (std.os.linux.getuid() == 0) {
        log.err("dropping root", .{});
        _ = try std.posix.setgid(99);
        _ = try std.posix.setuid(99);
    }

    log.err("started", .{});

    var cache: ZoneCache = .{ .alloc = a };

    const preload_tlds = [_][]const u8{
        "com",
        "net",
        "org",
        "tv",
        "ht",
        "rs",
    };
    for (preload_tlds) |ptld| {
        try cache.tld.put(a, ptld, .{
            .name = try cache.store(ptld),
        });
    }

    var blocked_results: ArrayList(Result) = .{};
    defer blocked_results.clearAndFree(a);
    const cwd = std.fs.cwd();
    for (blocks.items) |b| {
        const file = cwd.openFile(b, .{}) catch continue;
        defer file.close();
        var r_b: [2048]u8 = undefined;
        var r = file.reader(io, &r_b);
        try parseHostFile(&blocked_results, &r.interface, a);
    }

    var local_results: ArrayList(Result) = .{};
    defer local_results.clearAndFree(a);
    try parseHosts(&local_results, a, io);
    for (local_results.items) |line| {
        log.debug("host line {s} {f}", .{ line.fqdn, line.addr });
    }

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
    var q_b: [20]Message = undefined;
    var queue: Queue(Message) = .init(&q_b);

    var consume = io.async(answer, .{ &queue, a, io });
    defer _ = consume.cancel(io);

    try upstreams.init(io);
    const sigfd: Io.File = .{ .handle = @intCast(linux.signalfd(-1, &sigset, @bitCast(linux.O{ .NONBLOCK = false }))) };
    if (sigfd.handle < 0) @panic("signal fd failed");
    var pollfds: [2]linux.pollfd = .{
        .{ .fd = sigfd.handle, .events = std.math.maxInt(i16), .revents = 0 },
        .{ .fd = downstream.handle, .events = std.math.maxInt(i16), .revents = 0 },
    };
    var timeout: linux.timespec = .{ .sec = 0, .nsec = 250 * ns_per_ms };
    while (true) : ({
        for (&pollfds) |*fd| fd.revents = 0;
    }) {
        const ready = linux.ppoll(&pollfds, pollfds.len, &timeout, &sigset);

        if (ready < 0) {
            log.warn("signaled, cleaning up", .{});
        } else if (ready == 0) continue;

        if (pollfds[0].revents != 0) {
            log.err("signal", .{});
            var r_b: [@sizeOf(linux.signalfd_siginfo)]u8 = undefined;
            var r = sigfd.reader(io, &r_b);
            const siginfo: linux.signalfd_siginfo = r.interface.takeStruct(linux.signalfd_siginfo, sys_endian) catch unreachable;
            std.debug.print("siginfo {}\n\n\n", .{siginfo});
            break;
        }
        if (pollfds[1].revents != 0) {
            try accept(&cache, downstream, io, &queue);
            continue;
        }
    }

    log.err("done", .{});
}

const sigset: linux.sigset_t = defaultSigSet();
fn defaultSigSet() linux.sigset_t {
    var ss: linux.sigset_t = linux.sigemptyset();
    linux.sigaddset(&ss, .INT);
    linux.sigaddset(&ss, .HUP);
    linux.sigaddset(&ss, .QUIT);
    return ss;
}

const Message = struct {
    msg: net.IncomingMessage,
    ptr: *?MsgPtr,
    cache: *ZoneCache,
    downstream: net.Socket,
    timer: std.time.Timer,
};

fn answer(q: *Queue(Message), a: Allocator, io: Io) void {
    while (q.getOne(io)) |msg_| {
        var msg = msg_;
        if (core(msg.cache, msg.msg, msg.downstream, a, io) catch @panic("bah!")) {
            log.err("    **    cached response {d}us", .{msg.timer.lap() / 1000});
        } else {
            log.err("    ->    upstream responded {d}us", .{msg.timer.lap() / 1000});
        }
        msg.ptr.* = null;
    } else |_| {}
}

fn accept(cache: *ZoneCache, downstream: net.Socket, io: Io, q: *Queue(Message)) !void {
    var mp: *?MsgPtr = undefined;
    for (downstream_pool) |*pool| {
        if (pool.* == null) {
            pool.* = undefined;
            mp = pool;
            break;
        } else continue;
    } else {
        log.err("buffer full", .{});
        return;
    }

    const msg = try downstream.receive(io, &mp.*.?);
    log.info("received {}", .{msg.data.len});
    log.debug("data {any}", .{msg.data});
    log.debug("received from {any}", .{@as(*const [4]u8, @ptrCast(&msg.from.ip4))});

    try q.putOne(io, .{
        .msg = msg,
        .ptr = mp,
        .cache = cache,
        .downstream = downstream,
        .timer = try .start(),
    });
}

const Queue = Io.Queue;
const Behavior = ZoneCache.Behavior;
const ZoneCache = @import("Cache.zig");
const Zone = ZoneCache.Zone;

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

const RecordAddress = union(enum) {
    a: [4]u8,
    aaaa: [16]u8,

    pub fn format(addr: RecordAddress, w: *Writer) !void {
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
    const trimmed = trim(u8, line, &std.ascii.whitespace);
    if (trimmed.len == 0) return error.Skip;
    if (trimmed[0] == '#') {
        log.debug("skip '{s}'", .{line});
        return error.Skip;
    }

    if (indexOfAny(u8, trimmed, &std.ascii.whitespace)) |i| {
        const addr = trimmed[0..i];
        const names = trim(u8, trimmed[i..], &std.ascii.whitespace);

        const r_addr = if (indexOfScalar(u8, addr, ':')) |_|
            try parseAAAA(trim(u8, addr, &std.ascii.whitespace))
        else
            try parseA(trim(u8, addr, &std.ascii.whitespace));

        var names_itr = tokenizeAny(u8, names, &std.ascii.whitespace);
        while (names_itr.next()) |name| {
            const parsed = parseFQDN(name) catch |err| {
                log.err("fqdn error {}", .{err});
                continue;
            };
            try list.append(a, .{ .fqdn = try a.dupe(u8, parsed), .addr = r_addr });
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
    try parseLine(a, "127.0.0.1 blerg blerg2 blerg.4", &list);
    try std.testing.expectEqual(@as(usize, 4), list.items.len);
    try std.testing.expectEqualDeep(Result{ .fqdn = "blerg", .addr = .{ .a = .{ 127, 0, 0, 1 } } }, list.items[1]);
    try std.testing.expectEqualDeep(Result{ .fqdn = "blerg2", .addr = .{ .a = .{ 127, 0, 0, 1 } } }, list.items[2]);
    try std.testing.expectEqualDeep(Result{ .fqdn = "blerg.4", .addr = .{ .a = .{ 127, 0, 0, 1 } } }, list.items[3]);
    for (list.items) |line| {
        a.free(line.fqdn);
    }
}

fn parseHosts(list: *ArrayList(Result), a: Allocator, io: Io) !void {
    const file = std.fs.openFileAbsolute("/etc/hosts", .{}) catch return;
    defer file.close();
    var r_b: [2048]u8 = undefined;
    var r = file.reader(io, &r_b);

    return parseHostFile(list, &r.interface, a);
}

/// callers can prefill the buffer to get some performance on huge files
fn parseHostFile(list: *ArrayList(Result), r: *Reader, a: Allocator) !void {
    // 21 bytes per line for the test file
    try list.ensureUnusedCapacity(a, r.bufferedLen() / 21);

    while (r.takeDelimiterInclusive('\n')) |line| {
        parseLine(a, line, list) catch continue;
    } else |err| switch (err) {
        error.EndOfStream => return,
        else => return err,
    }
}

test parseHostFile {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var local_results: ArrayList(Result) = .{};
    defer local_results.clearAndFree(a);
    try parseHosts(&local_results, a, io);
    for (local_results.items) |line| {
        log.debug("host line {s} {f}", .{ line.fqdn, line.addr });
        a.free(line.fqdn);
    }
}

test main {
    _ = &main;
}

const Upstream = @import("Upstream.zig");

const DNS = @import("dns.zig");
const RData = DNS.Message.Resource.RData;

const std = @import("std");
const sys_endian = @import("builtin").target.cpu.arch.endian();
const Io = std.Io;
const Reader = Io.Reader;
const Writer = Io.Writer;
const net = Io.net;
const log = std.log;
const Allocator = std.mem.Allocator;
const ArrayList = std.ArrayList;
const eql = std.mem.eql;
const trim = std.mem.trim;
const indexOfAny = std.mem.indexOfAny;
const indexOfScalar = std.mem.indexOfScalar;
const tokenizeAny = std.mem.tokenizeAny;
const linux = std.os.linux;
const ns_per_ms = 1000 * 1000;
