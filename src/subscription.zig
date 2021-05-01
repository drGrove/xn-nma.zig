const std = @import("std");
const sqlite = @import("sqlite");
const BloomFilter = @import("./bloom_filter.zig").BloomFilter;
const assert = std.debug.assert;
const testing = std.testing;

usingnamespace @import("./channel.zig");
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

const sqlite_helpers = struct {
    // https://github.com/ziglang/zig/issues/8595
    const SQLITE_TRANSIENT = @intToPtr(sqlite.c.sqlite3_destructor_type, @bitCast(usize, @as(isize, -1)));

    pub fn fromBlob(comptime T: type, value: ?*sqlite.c.sqlite3_value) !*const T {
        if (comptime std.meta.containerLayout(T) == .Auto) {
            @compileError("must be extern or packed struct to have defined layout");
        }

        const len = sqlite.c.sqlite3_value_bytes(value);
        if (len != @sizeOf(T)) return error.SQLiteConstraintFunction;

        const ptr = @ptrCast([*]const u8, sqlite.c.sqlite3_value_blob(value));
        return std.mem.bytesAsValue(T, ptr[0..@sizeOf(T)]);
    }

    const Determinism = enum(c_int) { NonDeterministic = 0, Deterministic = sqlite.c.SQLITE_DETERMINISTIC };

    pub fn createFunction(db: sqlite.Db, func_name: [*:0]const u8, comptime func: anytype, det: Determinism) !void {
        const func_info = @typeInfo(@TypeOf(func)).Fn;
        assert(func_info.is_generic == false);
        assert(func_info.is_var_args == false);
        const ArgTuple = std.meta.ArgsTuple(@TypeOf(func));

        const result = sqlite.c.sqlite3_create_function(
            db.db,
            func_name,
            func_info.args.len,
            sqlite.c.SQLITE_UTF8 | @enumToInt(det),
            null,
            struct {
                fn xFunc(context: ?*sqlite.c.sqlite3_context, argc: c_int, argv: ?[*]?*sqlite.c.sqlite3_value) callconv(.C) void {
                    assert(argc == func_info.args.len);
                    const sqlite_args = argv.?[0..func_info.args.len];

                    var func_args: ArgTuple = undefined;
                    inline for (func_info.args) |arg, i| {
                        const arg_type = arg.arg_type.?;
                        func_args[i] = switch (@typeInfo(arg_type)) {
                            .Struct => (sqlite_helpers.fromBlob(arg_type, sqlite_args[i]) catch |e| {
                                sqlite.c.sqlite3_result_error(context, "invalid argument", switch (e) {
                                    error.SQLiteConstraintFunction => sqlite.c.SQLITE_CONSTRAINT_FUNCTION,
                                });
                                return;
                            }).*,
                            else => @compileError("unhandled auto coercion"),
                        };
                    }

                    const result = @call(.{}, func, func_args);

                    switch (@typeInfo(@TypeOf(result))) {
                        .Int => |intInfo| {
                            if ((intInfo.bits + if (intInfo.signedness == .unsigned) 1 else 0) <= 32) {
                                sqlite.c.sqlite3_result_int(context, result);
                            } else if ((intInfo.bits + if (intInfo.signedness == .unsigned) 1 else 0) <= 64) {
                                sqlite.c.sqlite3_result_int64(context, result);
                            } else {
                                @compileError("integer not always representable");
                            }
                        },
                        .Struct => {
                            // TODO: check result type has no pointer fields
                            sqlite.c.sqlite3_result_blob(context, &result, @sizeOf(@TypeOf(result)), sqlite_helpers.SQLITE_TRANSIENT);
                        },
                        else => @compileError("unhandled auto coercion"),
                    }
                }
            }.xFunc,
            null,
            null,
        );
        if (result != sqlite.c.SQLITE_OK) {
            return sqlite.errorFromResultCode(result);
        }
    }
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

    // Takes a Message (as a BLOB) and returns the message id hash (as an integer)
    try sqlite_helpers.createFunction(db, "ȱ.Message.id_hash", struct {
        fn Message_id_hash(message: Message) u48 {
            return message.id_hash.asInteger();
        }
    }.Message_id_hash, .Deterministic);

    try sqlite_helpers.createFunction(db, "ȱ.Message.hash", Message.hash, .Deterministic);

    try sqlite_helpers.createFunction(db, "ȱ.MessageIdHash.calculate", struct {
        fn MessageIdHash_calculate(channel_id: ChannelId, message_id: MessageId) u48 {
            return MessageIdHash.calculate(channel_id, message_id).asInteger();
        }
    }.MessageIdHash_calculate, .Deterministic);

    try db.exec(
        \\PRAGMA foreign_keys = ON;
    , .{});

    try db.exec(
        \\create table message_packet(
        \\  message blob not null check(length(message) == 504),
        \\  id_hash integer not null generated always as ("ȱ.Message.id_hash"(message)),
        \\  hash blob not null generated always as ("ȱ.Message.hash"(message))
        \\);
    , .{});

    try db.exec(
        \\create unique index message_packet_hashes on message_packet(hash, id_hash);
    , .{});

    try db.exec(
        \\create table wanted_message(
        \\  channel_id blob not null check(length(channel_id) == 16),
        \\  message_id blob not null check(length(message_id) == 6),
        \\  message_id_hash integer not null generated always as ("ȱ.MessageIdHash.calculate"(channel_id, message_id)),
        \\  message_hash blob unique not null check(length(message_hash) == 16)
        \\);
    , .{});

    try db.exec(
        \\create table known_message(
        \\  channel_id blob not null check(length(channel_id) == 16),
        \\  message_id blob not null check(length(message_id) == 6),
        \\  message_id_hash integer not null generated always as ("ȱ.MessageIdHash.calculate"(channel_id, message_id)),
        \\  message_hash blob check(length(message_hash) == 16),
        \\  verified integer not null check(verified == 0 or verified == 1) default 0 -- has the message hash been verified back to a master-key message
        \\);
    , .{});

    try db.exec(
        \\create unique index known_message_by_channel_and_message on known_message(channel_id, message_id, message_hash);
    , .{});

    try db.exec(
        \\create table channel(
        \\  channel_id blob primary key check(length(channel_id) == 16),
        \\  want_tail integer check(want_tail == 0 or want_tail == 1) -- do we want to follow this channel
        \\) without rowid;
    , .{});

    // try db.exec(
    //     \\create table channel_participant(
    //     \\  channel_id blob references channel(channel_id) check(length(channel_id) == 16),
    //     \\  authorization_message_id blob not null check(length(authorization_message_id) == 6),
    //     \\  authorization_message_hash blob check(length(authorization_message_hash) == 16),
    //     \\  foreign key(channel_id, authorization_message_id, authorization_message_hash) references known_message(channel_id, message_id, message_hash)
    //     \\);
    // , .{});

    {
        const channel_id = ChannelId{ .id = [_]u8{1} ** ChannelId.len };
        const message_id = MessageId.initInt(1);

        // construct message
        const m = blk: {
            const first_in_reply_to = MessageHash{ .hash = "abcdef1234567890".* };
            const key_pair = try std.crypto.sign.Ed25519.KeyPair.create(null);
            const payload = [_]u8{0} ** 379;

            var e = Envelope.init(undefined, first_in_reply_to);
            std.mem.copy(u8, e.getPayloadSlice(), &payload);
            try e.sign(key_pair);
            break :blk Message.init(channel_id, message_id, e);
        };

        // XXX: if I don't store this in a temporary I get a segfault at runtime
        const tmp = sqlite.Blob{ .data = std.mem.asBytes(&m) };
        try db.exec(
            \\ insert into message_packet(message) values(?);
        , .{
            tmp,
        });

        std.debug.print("{}\n", .{
            try db.one(
                MessageHash,
                \\ select hash from message_packet;
            ,
                .{},
                .{},
            ),
        });
        std.debug.print("LOCAL:{} SQLITE:{}\n", .{
            m.id_hash.asInteger(),
            try db.one(
                struct { id_hash: u48 },
                \\ select id_hash from message_packet;
            ,
                .{},
                .{},
            ),
        });

        const a1 = sqlite.Blob{ .data = std.mem.asBytes(&channel_id) };
        const a2 = sqlite.Blob{ .data = std.mem.asBytes(&message_id) };
        const a3 = sqlite.Blob{ .data = std.mem.asBytes(&m.hash()) };
        try db.exec(
            \\ insert into known_message(channel_id, message_id, message_hash) values
            //\\   ('0123456789abcdef','123456','abcdef'),
            \\   (?, ?, ?);
        , .{
            a1, a2, a3,
        });

        std.debug.print("LOCAL:{} SQLITE:{}\n", .{
            m.id_hash.asInteger(),
            try db.one(
                struct { id_hash: u48 },
                \\ select message_id_hash from known_message;
            ,
                .{},
                .{},
            ),
        });
    }
}
