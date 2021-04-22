const std = @import("std");
const sqlite = @import("sqlite");
const BloomFilter = @import("./bloom_filter.zig").BloomFilter;
const assert = std.debug.assert;
const testing = std.testing;

usingnamespace @import("./message.zig");

fn hash(out: []u8, Ki: usize, in: []const u8) void {
    var st = std.crypto.hash.Gimli.init(.{});
    st.update(&std.mem.toBytes(@intCast(u8, Ki)));
    st.update(in);
    st.final(out);
}

pub const Subscription = packed struct {
    filter: BloomFilter(2048, 3, bool, std.builtin.endian, hash) = .{},

    const Self = @This();
};

comptime {
    assert(@sizeOf(Subscription) == 256);
}

test " " {
    var s = Subscription{};
    s.filter.add("foo");
    testing.expect(s.filter.contains("foo"));
    testing.expect(!s.filter.contains("bar"));
}

const MessageStore = struct {
    // primary store keyed by Message

    // pub fn lookupBySubscription(s: Subscription) void {

    // }
};

test "sqlite" {
    var db: sqlite.Db = undefined;
    try db.init(.{
        .open_flags = .{
            .write = true,
            .create = true,
        },
        .threading_mode = .MultiThread,
    });

    {
        // Takes a Message (as a BLOB) and returns the message id hash (as an integer)
        const result = sqlite.c.sqlite3_create_function(
            db.db,
            "Message.id_hash",
            1,
            sqlite.c.SQLITE_UTF8 | sqlite.c.SQLITE_DETERMINISTIC,
            null,
            struct {
                fn xFunc(context: ?*sqlite.c.sqlite3_context, argc: c_int, argv: ?[*]?*sqlite.c.sqlite3_value) callconv(.C) void {
                    assert(argc == 1);
                    const arg = argv.?[0];

                    const message_len = sqlite.c.sqlite3_value_bytes(arg);
                    if (message_len != @sizeOf(Message)) {
                        sqlite.c.sqlite3_result_error(context, "incorrect Message size", sqlite.c.SQLITE_CONSTRAINT_FUNCTION);
                        return;
                    }
                    const message_ptr = @ptrCast([*]const u8, sqlite.c.sqlite3_value_blob(arg));
                    const message = std.mem.bytesToValue(Message, message_ptr[0..@sizeOf(Message)]);

                    sqlite.c.sqlite3_result_int64(context, message.id_hash.asInteger());
                }
            }.xFunc,
            null,
            null,
        );
        if (result != sqlite.c.SQLITE_OK) {
            return sqlite.errorFromResultCode(result);
        }
    }

    {
        const result = sqlite.c.sqlite3_create_function(
            db.db,
            "MessageHash.calculate",
            1,
            sqlite.c.SQLITE_UTF8 | sqlite.c.SQLITE_DETERMINISTIC,
            null,
            struct {
                fn xFunc(context: ?*sqlite.c.sqlite3_context, argc: c_int, argv: ?[*]?*sqlite.c.sqlite3_value) callconv(.C) void {
                    assert(argc == 1);
                    const arg = argv.?[0];

                    const message_len = sqlite.c.sqlite3_value_bytes(arg);
                    if (message_len != @sizeOf(Message)) {
                        sqlite.c.sqlite3_result_error(context, "incorrect Message size", sqlite.c.SQLITE_CONSTRAINT_FUNCTION);
                        return;
                    }
                    const message_ptr = @ptrCast([*]const u8, sqlite.c.sqlite3_value_blob(arg));
                    const message = std.mem.bytesToValue(Message, message_ptr[0..@sizeOf(Message)]);

                    const msg_hash = MessageHash.calculate(message);

                    // https://github.com/ziglang/zig/issues/8595
                    const SQLITE_TRANSIENT = @intToPtr(sqlite.c.sqlite3_destructor_type, @bitCast(usize, @as(isize, -1)));
                    sqlite.c.sqlite3_result_blob(context, &msg_hash.hash, MessageHash.len, SQLITE_TRANSIENT);
                }
            }.xFunc,
            null,
            null,
        );
        if (result != sqlite.c.SQLITE_OK) {
            return sqlite.errorFromResultCode(result);
        }
    }

    try db.exec(
        \\ create table packets(
        \\    message blob not null check(length(message) == 504),
        \\    id_hash integer not null generated always as ("Message.id_hash"(message)) stored,
        \\    hash blob not null unique generated always as ("MessageHash.calculate"(message))
        \\ );
    , .{});
    try db.exec(
        \\ insert into packets(message) values(?);
    , .{
        "b" ** 504,
    });
    const result = try db.one(
        struct { hash: [16]u8 },
        \\ select hash from packets;
    ,
        .{},
        .{},
    );
    std.debug.print("{}\n", .{result});
}
