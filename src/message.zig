const std = @import("std");
const assert = std.debug.assert;
const Ed25519 = std.crypto.sign.Ed25519;
const testing = std.testing;
const ChannelId = @import("./channel.zig").ChannelId;
const Hash = std.crypto.hash.Gimli;

/// All ȱ packets are the same size
///
/// This number is based on max UDP over IPv4 packet size:
/// - IPv4 mandates a path MTU of at least 576 bytes
/// - IPv4 header is at maximum 60 bytes
/// - UDP header is 8 bytes
/// => 576 - 60 - 8 = 504
const packet_size = 504;

/// Hash size is selected to be as small as possible while cryptographically collision resistant
const message_hash_length = 16;

const message_id_hash_length = 6;
const message_id_length = 6;
const nonce_length = 16;

const MessageId = extern struct {
    id: [message_id_length]u8,

    pub fn initInt(n: u48) MessageId {
        var self: MessageId = undefined;
        std.mem.writeIntBig(u48, &self.id, n);
        return self;
    }
};

pub const InReplyTo = extern struct {
    id: MessageId,
    hash: [message_hash_length]u8,
};

pub const Envelope = extern struct {
    /// Workaround Zig packed struct bugs
    workaround: packed struct {
        continuation: bool,
        padding: u3 = 0,
        /// This is offset by 1 as a message can never have 0 in_reply_tos
        n_in_reply_to: u4,
    },
    first_in_reply_to: [message_hash_length]u8,
    in_reply_to_and_payload: [packet_size - message_id_hash_length - 1 - message_hash_length - nonce_length - Ed25519.signature_length]u8,
    nonce: [nonce_length]u8,
    signature: [Ed25519.signature_length]u8,

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
        const slice = self.in_reply_to_and_payload[0 .. @as(u9, self.workaround.n_in_reply_to) * @sizeOf(InReplyTo)];
        return std.mem.bytesAsSlice(InReplyTo, slice);
    }

    pub fn addInReplyTo(self: *Self, inReplyTo: InReplyTo) void {
        self.workaround.n_in_reply_to += 1;
        const slice = self.getInReplyToSlice();
        slice[self.workaround.n_in_reply_to - 1] = inReplyTo;
    }

    pub fn getPayloadSlice(self: *Self) []u8 {
        return self.in_reply_to_and_payload[@as(u9, self.workaround.n_in_reply_to) * @sizeOf(InReplyTo) ..];
    }

    fn sign(self: *Self, key: Ed25519.KeyPair) !void {
        var noise: [Ed25519.noise_length]u8 = undefined;
        std.crypto.random.bytes(&noise);
        self.signature = try Ed25519.sign(
            std.mem.asBytes(self)[0 .. @sizeOf(Envelope) - Ed25519.signature_length],
            key,
            noise,
        );
    }

    fn verify(self: Self, pubkey: [Ed25519.public_length]u8) !void {
        try Ed25519.verify(
            self.signature,
            std.mem.asBytes(&self)[0 .. @sizeOf(Envelope) - Ed25519.signature_length],
            pubkey,
        );
    }
};

test "Envelope" {
    const first_in_reply_to = "abcdef1234567890".*;
    const id = MessageId.initInt(1); // https://github.com/ziglang/zig/issues/8435
    const second_in_reply_to = InReplyTo{
        .id = id,
        .hash = "abcdef1234567891".*,
    };
    const key_pair = try Ed25519.KeyPair.create(null);
    const payload = [_]u8{0} ** 379;

    // construct message
    var e = Envelope.init(first_in_reply_to);
    e.addInReplyTo(second_in_reply_to);
    std.mem.copy(u8, e.getPayloadSlice(), &payload);
    try e.sign(key_pair);

    // verify construction is as intended
    testing.expectEqual(first_in_reply_to, e.first_in_reply_to);
    testing.expectEqualSlices(
        InReplyTo,
        &[_]InReplyTo{second_in_reply_to},
        e.getInReplyToSlice(),
    );
    testing.expectEqualSlices(u8, &payload, e.getPayloadSlice());
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
    assert(@sizeOf(MessageId) == 6);
    assert(@sizeOf(InReplyTo) == 22);
    assert(@sizeOf(Envelope) == packet_size - message_id_hash_length);
    assert(@sizeOf(Message) == packet_size);
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
