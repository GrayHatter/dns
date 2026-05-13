var upstreams: Upstream = .{ .conns = undefined };

pub const std_options: std.Options = .{
    .log_level = .warn,
    //.logFn = logFunc,
};

var log_level_target: log.Level = .warn;

const default_wait: std.Io.Clock.Duration = .{ .raw = .fromMilliseconds(95), .clock = .awake };

pub fn logFunc(
    comptime message_level: log.Level,
    comptime _: @EnumLiteral(),
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
    std.os.linux.exit(1);
}

fn sendCachedAnswer(
    mheader: Message.Header,
    q: Message.Question,
    domain: *const Domain,
    zone: *Zone,
    downstream: net.Socket,
    addr: net.IpAddress,
    io: Io,
) !bool {
    // 40 seems large here, but I've seen 20 exhaust the buffer
    var res_buff: [40]RData = undefined;
    var addr_list: ArrayList(RData) = .initBuffer(&res_buff);
    const now: Io.Timestamp = Io.Clock.awake.now(io);
    const duration: Io.Duration = if (zone.behavior == .cached)
        now.durationTo(zone.behavior.cached.expires)
    else
        .zero;
    zone.hits += 1;
    log.warn("      {} hits (TTL: {}ms)", .{ zone.hits, duration.toMilliseconds() });
    switch (zone.behavior) {
        .nxdomain => {
            if (mheader.qdcount == 1) {
                const ans: Message = try .answerDrop(mheader.id, q.name);
                try downstream.send(io, &addr, ans.slice());
                log.err("dropping request for {s}", .{q.name});
                return true;
            }
            log.err("unable to drop complex record for {s}", .{q.name});
            return false;
        },
        .cached => |c_result| {
            if (c_result.expires.nanoseconds < now.nanoseconds) {
                const expired = now.toMilliseconds() - c_result.expires.toMilliseconds();
                log.warn("      cached {s} expired {}s ago", .{ domain.zone, expired });
                return false;
            }
            switch (q.qtype) {
                .a => {
                    if (c_result.a.items.len == 0) {
                        log.err("    a request is null", .{});
                        return false;
                    }
                    for (c_result.a.items) |src| {
                        addr_list.appendBounded(.{ .a = src.bytes }) catch |err| {
                            log.err("address list exhausted", .{});
                            log.err("cresult\n{}", .{c_result});
                            return err;
                        };
                    }
                    const ans: Message = try .answer(
                        mheader.id,
                        &[1]Message.AnswerData{.{ .fqdn = q.name, .ips = addr_list.items }},
                    );
                    log.debug("cached answer {any}", .{ans.slice()});
                    //std.time.sleep(100_000);
                    try downstream.send(io, &addr, ans.slice());
                    return true;
                },

                .aaaa => {
                    log.info("cached {s}", .{domain.zone});
                    if (c_result.aaaa.items.len == 0) {
                        log.warn("      aaaa request is null", .{});
                        return false;
                    }
                    for (c_result.aaaa.items) |src| {
                        try addr_list.appendBounded(.{ .aaaa = src.bytes });
                    }
                    const ans: Message = try .answer(
                        mheader.id,
                        &[1]Message.AnswerData{.{ .fqdn = q.name, .ips = addr_list.items }},
                    );
                    try downstream.send(io, &addr, ans.slice());
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

fn hitUpstream(net_msg: net.IncomingMessage, downstream: net.Socket, io: Io) !Message {
    const peer, const upstream = upstreams.get();
    var w = &upstream.writer.interface;
    var r = &upstream.reader.interface;
    try r.rebase(2048);
    log.warn("      asking upstream {f}", .{peer.addr});
    var pollfds: [1]linux.pollfd = .{.{
        .fd = upstream.stream.socket.handle,
        .events = std.math.maxInt(i16),
        .revents = 0,
    }};
    var timeout: linux.timespec = .{ .sec = 0, .nsec = 200 * ns_per_ms };
    var attempt: u8 = 0;
    try w.writeAll(net_msg.data);
    try w.flush();
    while (true) : ({
        pollfds[0].revents = 0;
        attempt +|= 1;
        try default_wait.sleep(io);
    }) {
        if (attempt > 20) {
            defer r.tossBuffered();
            return error.UpstreamFailure;
        }

        if (attempt > 8 and attempt & 1 == 0) {
            log.err("***    retrying upstream {f} on {X}", .{ peer.addr, net_msg.data[0..2] });
            try w.writeAll(net_msg.data);
            try w.flush();
        }

        if (r.bufferedLen() < Message.min_size) {
            if (linux.ppoll(&pollfds, pollfds.len, &timeout, &sigset) == 0) continue;
        }

        const peek = r.peek(2) catch continue;
        if (eql(u8, peek[0..2], net_msg.data[0..2])) break;
        log.warn("      expected {X} got {X} [from {f}]", .{ net_msg.data[0..2], peek[0..2], peer.addr });
        if (r.bufferedLen() > 60 and attempt > 4) {
            const save = r.seek;
            errdefer r.seek = save;
            _ = try Message.init(r);
            if (eql(u8, (r.peek(2) catch continue)[0..2], net_msg.data[0..2]))
                break;
            r.seek = save;
            if (upstreams.next % 32 == 0) r.tossBuffered();
        }
        continue;
    }
    const start = r.seek;
    var dns_data = r.buffered();
    const dns_answer = try Message.init(r);
    dns_data.len = r.seek - start;

    log.info("bounce received {}", .{dns_data.len});
    log.debug("bounce data {any}", .{dns_data});

    for (blocked_ips) |banned| {
        if (eql(u8, dns_data[dns_data.len - 4 ..], &banned)) {
            @memset(dns_data[dns_data.len - 4 ..], 0);
        }
    }
    try downstream.send(io, &net_msg.from, dns_data);
    return dns_answer;
}

fn core(
    cache: *ZoneCache,
    net_msg: net.IncomingMessage,
    downstream: net.Socket,
    a: Allocator,
    io: Io,
) !bool {
    var reader: Reader = .fixed(net_msg.data);
    const msg: Message = try .init(&reader);

    log.info("incoming packet\n{f}", .{msg.header});

    if (msg.header.qdcount >= 16) {
        log.err("dropping invalid msg", .{});
        log.debug("that message {any}", .{net_msg.data});
        return true;
    }

    var iter: Message.Iterator = .init(&msg);
    while (iter.next() catch |err| e: {
        log.err("question iter error {}", .{err});
        log.err("qdata {any}", .{net_msg.data});
        break :e null;
    }) |pay| switch (pay) {
        .question => |q| {
            try ZoneCache.mutex.lock(io);
            defer ZoneCache.mutex.unlock(io);
            log.err(" {s: >5}: [ {s} ]", .{ @tagName(q.qtype), q.name });
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
                log.warn("      cache missing going to upstream", .{});
            }
        },
        .answer => break,
    };

    const rmsg: Message = hitUpstream(net_msg, downstream, io) catch return false;
    if (rmsg.header.qdcount != 1) return false;

    log.debug("answer from upstream:\n{f}", .{rmsg.header});
    cacheAnswer(cache, rmsg, a, io) catch |err| {
        log.err("rdata {any}", .{rmsg.slice()});
        return err;
    };

    return false;
}

fn cacheAnswer(cache: *ZoneCache, rmsg: Message, a: Allocator, io: Io) !void {
    const now: Io.Timestamp = Io.Clock.awake.now(io);

    var lzone: Zone = undefined;
    var tld: *Zone = undefined;

    try ZoneCache.mutex.lock(io);
    defer ZoneCache.mutex.unlock(io);

    var rit = Message.Iterator.init(&rmsg);
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
                        goptr.value_ptr.* = .{ .name = try cache.store(domain.zone) };
                    }
                    goptr.value_ptr.hits += 1;
                    break :f goptr.value_ptr;
                } else |err| {
                    log.err("hash error {}", .{err});
                    break;
                }
            };
            lzone = .{ .name = try cache.store(domain.zone) };
            log.info("r question = {s}", .{q.name});
            log.info("r question = \n{f}", .{q});
            log.info("{f}", .{q});
        },
        .answer => |r| {
            log.debug("r answer      = {s: <6} -> {s} ", .{ @tagName(r.rtype), r.name });
            log.debug("r               {}", .{r.data});
            log.debug("r answer = \n{f}", .{r});

            if (tld.zones.getOrPut(a, lzone)) |gop| {
                const zone = gop.key_ptr;
                if (!gop.found_existing) zone.behavior = .new;
                switch (zone.behavior) {
                    .new => zone.behavior = .{ .cached = .{ .expires = now, .a = .empty, .aaaa = .empty } },
                    .cached => {
                        if (zone.behavior.cached.expires.nanoseconds < now.nanoseconds) {
                            zone.behavior.cached.a.clearRetainingCapacity();
                            zone.behavior.cached.aaaa.clearRetainingCapacity();
                        }
                        zone.behavior.cached.expires = now.addDuration(.{
                            .nanoseconds = @max(
                                r.ttl.duration.nanoseconds,
                                Message.TTL.seconds(90).duration.nanoseconds,
                            ),
                        });
                    },
                    .nxdomain => {},
                }

                switch (r.rtype) {
                    .a => try zone.behavior.cached.a.append(a, .{ .bytes = r.data.a, .port = 0 }),
                    .aaaa => try zone.behavior.cached.aaaa.append(a, .{ .bytes = r.data.aaaa, .port = 0 }),
                    .soa => {
                        log.debug("r soa m         {s}", .{r.data.soa.mname});
                        log.debug("r soa r         {s}", .{r.data.soa.rname});
                    },
                    else => {},
                }
                continue;
            } else |err| return err;
        },
    };
}

var blocked_ips: []const [4]u8 = &.{};
const MsgPtr = [1024]u8;

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;

    var blocks: ArrayList([]const u8) = .empty;
    var blocked_ips_: ArrayList([4]u8) = .empty;
    var blocked_domains: ArrayList([]const u8) = .empty;

    var argv = init.minimal.args.iterate();
    const arg0 = argv.next().?;
    while (argv.next()) |arg| {
        if (eql(u8, arg, "--block")) {
            try blocks.append(a, argv.next() orelse usage(arg0, "<config file> missing for --block"));
        } else if (eql(u8, arg, "--drop-ip")) {
            const ip_str = argv.next() orelse usage(arg0, "<ip address> missing for --drop-ip");
            var ip: [4]u8 = undefined;
            var itr = std.mem.splitScalar(u8, ip_str, '.');
            for (&ip) |*oct| oct.* = std.fmt.parseInt(u8, itr.next() orelse "0", 10) catch 0;
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
        _ = std.os.linux.setgid(99);
        _ = std.os.linux.setuid(99);
    }

    log.err("started", .{});
    var cache: ZoneCache = .{ .alloc = a };
    const preload_tlds = [_][]const u8{ "com", "net", "org", "tv", "ht", "rs" };
    for (preload_tlds) |ptld| try cache.tld.put(a, ptld, .{ .name = try cache.store(ptld) });

    var blocked_results: ArrayList(Result) = .empty;
    defer blocked_results.clearAndFree(a);
    const cwd = std.Io.Dir.cwd();
    for (blocks.items) |b| {
        const file = cwd.openFile(io, b, .{}) catch continue;
        defer file.close(io);
        var r_b: [2048]u8 = undefined;
        var r = file.reader(io, &r_b);
        try parseHostFile(&blocked_results, &r.interface, a);
    }

    var local_results: ArrayList(Result) = .empty;
    defer local_results.clearAndFree(a);
    try parseHosts(&local_results, a, io);
    for (local_results.items) |line| {
        log.debug("host line {s} {f}", .{ line.fqdn, line.addr });
    }

    for (blocked_domains.items) |dd| {
        const domain: Domain = .init(dd);
        log.err("tld {s}", .{domain.tld});
        const tldgop = try cache.tld.getOrPut(a, domain.tld);
        if (!tldgop.found_existing) tldgop.value_ptr.* = .{ .name = try cache.store(domain.tld) };
        var tld = tldgop.value_ptr;
        log.err("zone {s}", .{domain.zone});
        const str = try cache.store(domain.zone);
        _ = try tld.zones.getOrPut(a, .{ .name = str, .behavior = .{ .nxdomain = 300 } });
    }
    var q_b: [20]Request = undefined;
    var queue: Queue(Request) = .init(&q_b);

    var consume0 = io.async(answer, .{ &queue, a, io });
    defer _ = consume0.cancel(io);
    var consume1 = io.async(answer, .{ &queue, a, io });
    defer _ = consume1.cancel(io);
    var consume2 = io.async(answer, .{ &queue, a, io });
    defer _ = consume2.cancel(io);
    var consume3 = io.async(answer, .{ &queue, a, io });
    defer _ = consume3.cancel(io);

    try upstreams.init(io);
    const sigfd: Io.File = .{
        .handle = @intCast(linux.signalfd(-1, &sigset, @bitCast(linux.O{ .NONBLOCK = false }))),
        .flags = .{ .nonblocking = false },
    };
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
            try accept(&cache, downstream, a, io, &queue);
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

const Request = struct {
    msg: net.IncomingMessage,
    ptr: *MsgPtr,
    cache: *ZoneCache,
    downstream: net.Socket,
    start: std.Io.Timestamp,
};

fn answer(q: *Queue(Request), a: Allocator, io: Io) void {
    while (q.getOne(io)) |msg_| {
        defer a.destroy(msg_.ptr);
        var msg = msg_;
        const lap = msg.start.untilNow(io, .awake);
        if (core(msg.cache, msg.msg, msg.downstream, a, io) catch @panic("bah!")) {
            log.warn("      **    cached response {f}", .{lap});
        } else {
            log.warn("      ->    upstream responded {f}", .{lap});
        }
    } else |_| {}
}

fn accept(cache: *ZoneCache, downstream: net.Socket, a: Allocator, io: Io, q: *Queue(Request)) !void {
    const mp: *MsgPtr = try a.create(MsgPtr);
    const msg = try downstream.receive(io, mp);
    log.info("received {}", .{msg.data.len});
    log.info("data {any}", .{msg.data});
    log.info("received from {any}", .{@as(*const [4]u8, @ptrCast(&msg.from.ip4))});

    try q.putOne(io, .{
        .msg = msg,
        .ptr = mp,
        .cache = cache,
        .downstream = downstream,
        .start = std.Io.Clock.awake.now(io),
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

        return .{ .tld = bit.first(), .zone = bit.rest() };
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
    var list: ArrayList(Result) = .empty;
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
    const file = std.Io.Dir.openFileAbsolute(io, "/etc/hosts", .{}) catch return;
    defer file.close(io);
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
    var local_results: ArrayList(Result) = .empty;
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
const Message = DNS.Message;
const RData = Message.Resource.RData;

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
