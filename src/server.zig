fn usage() !void {}

pub fn main() !void {
    const a = std.heap.smp_allocator;

    var blocks: ?[]const u8 = null;
    var blocked_ips: std.ArrayListUnmanaged([4]u8) = .{};
    var blocked_domains: std.ArrayListUnmanaged([]const u8) = .{};

    var argv = std.process.args();
    while (argv.next()) |arg| {
        if (std.mem.eql(u8, arg, "--block")) {
            blocks = argv.next() orelse @panic("invalid argv --block");
        } else if (std.mem.eql(u8, arg, "--drop-ip")) {
            const ip_str = argv.next() orelse @panic("invalid argv --drop-ip");
            var ip: [4]u8 = undefined;
            var itr = std.mem.splitScalar(u8, ip_str, '.');
            for (&ip) |*oct| {
                oct.* = std.fmt.parseInt(u8, itr.next() orelse "0", 10) catch 0;
            }
            try blocked_ips.append(a, ip);
        } else if (std.mem.eql(u8, arg, "--drop-domain")) {
            const domain_str = argv.next() orelse @panic("invalid argv --drop-domain");
            try blocked_domains.append(a, try a.dupe(u8, domain_str));
        }
    }

    const downstream: DNS.Peer = try .listen(.{ 0, 0, 0, 0 }, 53);

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

    try cache.tld.put(a, "com", .{});
    try cache.tld.put(a, "net", .{});
    try cache.tld.put(a, "org", .{});
    try cache.tld.put(a, "ht", .{});

    if (blocks) |b| {
        a.free(try parse(a, b));
    }

    for (blocked_domains.items) |dd| {
        const domain: Domain = .init(dd);
        log.err("tld {s}", .{domain.tld});
        var tld = cache.tld.getPtr(domain.tld).?;
        log.err("zone {s}", .{domain.zone});
        try tld.zones.put(a, domain.zone, .{ .behavior = .drop });
    }

    var upconns: [4]DNS.Peer = undefined;
    for (&upconns, upstreams) |*dst, ip| {
        dst.* = try .connect(ip, 53);
    }
    var up_idx: u2 = 0;

    //const msg = try DNS.Message.query(a, &[1][]const u8{domain orelse "gr.ht."});
    //var request: [1024]u8 = undefined;
    //const msgsize = try msg.write(&request);

    var timer: std.time.Timer = try .start();
    root: while (true) {
        var addr: std.net.Address = .{ .in = .{ .sa = .{ .port = 0, .addr = 0 } } };
        var buffer: [1024]u8 = undefined;
        const icnt = try downstream.recvFrom(&buffer, &addr);
        timer.reset();
        log.info("received {}", .{icnt});
        //log.err("data {any}", .{buffer[0..icnt]});
        log.warn("received from {any}", .{addr.in});
        //const current_time = std.time.timestamp();

        const msg = try DNS.Message.fromBytes(buffer[0..icnt]);
        var address_bufs: [16]DNS.Message.Resource.RData = undefined;
        var addresses: std.ArrayListUnmanaged(DNS.Message.Resource.RData) = .{
            .items = &address_bufs,
            .capacity = address_bufs.len,
        };
        addresses.items.len = 0;

        var qdomains: [16][255]u8 = undefined;
        var dbuf: [16][]const u8 = undefined;
        var domains: std.ArrayListUnmanaged([]const u8) = .{
            .items = &dbuf,
            .capacity = dbuf.len,
        };
        domains.items.len = 0;

        if (msg.header.qdcount >= 16) {
            log.err("dropping invalid msg", .{});
            log.debug("that message {any}", .{buffer[0..icnt]});
            continue;
        }

        var iter = msg.iterator();
        while (iter.next() catch |err| e: {
            log.err("question iter error {}", .{err});
            log.debug("qdata {any}", .{buffer[0..icnt]});
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
                            goptr.value_ptr.* = .{};
                        }
                        goptr.value_ptr.hits += 1;
                        break :f goptr.value_ptr;
                    } else |err| {
                        log.err("hash error {}", .{err});
                        break;
                    }
                };

                if (tld.zones.getPtr(domain.zone)) |zone| {
                    log.err("{} hits on {s}", .{ zone.hits, domain.zone });
                    switch (zone.behavior) {
                        .drop => {
                            var ans_bytes: [512]u8 = undefined;
                            if (msg.header.qdcount == 1) {
                                const ans: DNS.Message = try .answerDrop(
                                    msg.header.id,
                                    q.name,
                                    &ans_bytes,
                                );
                                try downstream.sendTo(addr, ans.bytes);
                                log.err("responded {d}", .{@as(f64, @floatFromInt(timer.lap())) / 1000});
                                continue :root;
                            }
                        },
                        else => log.err("zone {}", .{zone}),
                    }
                }

                addresses.appendAssumeCapacity(.{ .a = .{ 127, 0, 0, 1 } });
            },
            .answer => break,
        };

        var answer_bytes: [512]u8 = undefined;
        const answer = try DNS.Message.answer(
            msg.header.id,
            domains.items,
            addresses.items,
            &answer_bytes,
        );
        _ = answer;
        //log.err("answer = {}", .{answer});

        //log.info("bounce", .{});
        up_idx +%= 1;
        try upconns[up_idx].send(buffer[0..icnt]);
        var relay_buf: [1024]u8 = undefined;
        const b_cnt = try upconns[up_idx].recv(&relay_buf);
        const relayed = relay_buf[0..b_cnt];
        //log.info("bounce received {}", .{b_cnt});
        //log.debug("bounce data {any}", .{relayed});

        for (blocked_ips.items) |banned| {
            if (std.mem.eql(u8, relayed[relayed.len - 4 .. relayed.len], &banned)) {
                @memset(relayed[relayed.len - 4 .. relayed.len], 0);
            }
        }

        try downstream.sendTo(addr, relay_buf[0..b_cnt]);
        log.err("responded {d}", .{@as(f64, @floatFromInt(timer.lap())) / 1000});

        const rmsg: DNS.Message = try .fromBytes(relayed);
        var rit = rmsg.iterator();

        while (rit.next() catch |err| e: {
            log.err("relayed iter error {}", .{err});
            log.debug("rdata {any}", .{relayed});
            break :e null;
        }) |pay| switch (pay) {
            .question => |q| {
                _ = q;
                //log.err("r question = {s}", .{q.name});
                //log.debug("r question = {}", .{q});
            },
            .answer => |r| {
                _ = r;
                //log.err("r question = {s}", .{r.name});
                //log.debug("r question = {}", .{r});
            },
        };
    }

    log.err("done", .{});
}

pub const Behavior = union(enum) {
    new: void,
    drop: void,
    cached: Result,

    pub const Result = struct {
        drop: bool = true,
        ttl: u32,
        addr: union(enum) {
            a: [4]u8,
            aaaa: [16]u8,
        },
    };
};

const Zone = struct {
    zones: std.StringHashMapUnmanaged(Zone) = .{},
    behavior: Behavior = .new,
    hits: u32 = 0,
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

    pub fn store(zc: *ZoneCache, str: []const u8) !Zone.Index {
        try zc.strings.ensureUnusedCapacityp(zc.alloc, str.len + 1);
        zc.strings.appendSliceAssumeCapacity(str);
        zc.strings.appendAssumeCapacity(0);

        const str_index: u32 = @intCast(zc.strings.items.len - str.len - 1);
        const key: []const u8 = zc.strings.items[str_index..][0..str.len :0];
        const gop = try zc.loc_table.getOrPutContextAdapted(
            zc.alloc,
            key,
            std.hash_map.StringIndexAdapter{ .bytes = zc.strings },
            std.hash_map.StringIndexContext{ .bytes = zc.strings },
        );

        if (gop.found_existing) {
            zc.strings.shrinkRetainingCapacity(str_index);
        } else {
            gop.key_ptr.* = str_index;
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

const std = @import("std");
const log = std.log;
const Allocator = std.mem.Allocator;
const indexOfScalar = std.mem.indexOfScalar;
