const std = @import("std");
const assert = std.debug.assert;
const Ed25519 = std.crypto.sign.Ed25519;
const testing = std.testing;
const ChannelId = @import("./channel.zig").ChannelId;
const Hash = std.crypto.hash.Gimli;

const message_hash_length = 16;
const message_id_hash_length = 6;
const message_id_length = 6;

const MessageId = extern struct {
    id: [message_id_length]u8,

    pub fn initInt(n: u48) MessageId {
        var self: MessageId = undefined;
        std.mem.writeIntBig(u48, &self.id, n);
        return self;
    }
};

pub const InReplyTo = packed struct {
    id: MessageId,
    hash: [message_hash_length]u8,
};

pub const Envelope = extern struct {
    const Workaround = packed struct {
        continuation: bool,
        padding: u3 = 0,
        /// This is offset by 1 as a message can never have 0 in_reply_tos
        n_in_reply_to: u4,
    };
    workaround: Workaround,
    first_in_reply_to: [message_hash_length]u8,
    in_reply_to_and_payload: [504 - message_id_hash_length - 1 - message_hash_length - 16 - 64]u8,
    nonce: [16]u8,
    signature: [64]u8,

    const Self = @This();

    pub fn init(inReplyToHash: [message_hash_length]u8) Self {
        var nonce: [16]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        return Self{
            .workaround = .{
                .continuation = false,
                .n_in_reply_to = 0,
            },
            .first_in_reply_to = inReplyToHash,
            .in_reply_to_and_payload = undefined,
            .nonce = nonce,
            .signature = undefined,
        };
    }

    fn getInReplyToSlice(self: *Self) []InReplyTo {
        // 22 is @sizeOf(InReplyTo) but for some reason is not working...
        //const slice = self.in_reply_to_and_payload[0 .. @as(u9, self.workaround.n_in_reply_to) * 22];
        //return std.mem.bytesAsSlice(InReplyTo, slice);
        return @ptrCast([*]InReplyTo, &self.in_reply_to_and_payload)[0..self.workaround.n_in_reply_to];
    }

    pub fn addInReplyTo(self: *Self, inReplyTo: InReplyTo) void {
        self.workaround.n_in_reply_to += 1;
        const slice = self.getInReplyToSlice();
        slice[self.workaround.n_in_reply_to - 1] = inReplyTo;
    }

    pub fn getPayloadSlice(self: *Self) []u8 {
        // 22 is @sizeOf(InReplyTo) but for some reason is not working...
        return self.in_reply_to_and_payload[@as(u9, self.workaround.n_in_reply_to) * 22 ..];
    }

    fn sign(self: *Self, key: Ed25519.KeyPair) !void {
        var noise: [32]u8 = undefined;
        std.crypto.random.bytes(&noise);
        self.signature = try Ed25519.sign(std.mem.asBytes(self)[0 .. @sizeOf(Envelope) - 64], key, noise);
    }

    fn verify(self: Self, pubkey: [32]u8) !void {
        try Ed25519.verify(self.signature, std.mem.asBytes(&self)[0 .. @sizeOf(Envelope) - 64], pubkey);
    }
};

test "envelope" {
    var e = Envelope.init("abcdef1234567890".*);
    e.addInReplyTo(.{
        .id = MessageId.initInt(1),
        .hash = "abcdef1234567891".*,
    });
    const payloadSlice = e.getPayloadSlice();
    std.mem.set(u8, payloadSlice, 0);
    const key_pair = try Ed25519.KeyPair.create(null);
    try e.sign(key_pair);
    try e.verify(key_pair.public_key);
}

pub const Message = packed struct {
    id_hash: [message_id_hash_length]u8,
    envelope: Envelope,

    const Self = @This();

    pub fn init(channel_id: ChannelId, message_id: MessageId, envelope: Envelope) Self {
        var hash = Hash.init(.{});
        hash.update(channel_id);
        return Self{
            .id_hash = undefined,
            .envelope = envelope,
        };
    }

    pub fn hash(self: Self) [16]u8 {
        var output: [32]u8 = undefined;
        // TODO: take the hash of the data (envelope) + id
        return output;
    }
};

comptime {
    assert(@sizeOf(Envelope) == 504 - 6);
    assert(@sizeOf(Message) == 504);
}
// pub const Payload = struct {
//     chatstate: ChatState = null,
//     body: []u8 = null,
//     const Self = @This();

//     pub fn init(message: []u8, payloadType: PayloadType) Self {
//         return Self{ .payloadType = payloadType, .message = message };
//     }

//     pub fn setPayloadType(self: *Self, payloadType: PayloadTye) void {
//         self.payloadType = payloadType;
//     }
// };
