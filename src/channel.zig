const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

pub const ChannelId = extern struct {
    pub const len = 16;

    id: [len]u8,
};

pub const Channel = struct {
    id: ChannelId,

    const Self = @This();

    pub fn init(id: ChannelId) Self {
        return Self{ .id = id };
    }
};
