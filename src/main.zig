const std = @import("std");
const testing = std.testing;

const channel = @import("./channel.zig");
const message = @import("./message.zig");

test {
    testing.refAllDecls(@This());
}
