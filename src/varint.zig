//! varible size unsigned integers
//! non-redundant representation a-la git: https://github.com/git/git/blob/v2.31.1/varint.c

const std = @import("std");

/// Read a single unsigned value from the given reader as type T,
/// or error.Overflow if the value cannot fit.
pub fn read(comptime T: type, reader: anytype) !T {
    const U = if (@typeInfo(T).Int.bits < 8) u8 else T;
    const ShiftT = std.math.Log2Int(U);

    var value = @as(U, 0);

    while (true) {
        const byte = try reader.readByte();
        value += @truncate(u7, byte);
        if (byte & 0x80 == 0) break;

        // if any of top 7 bits are non-zero then adding or shifting could overflow
        if (value >= (~@as(T, 0) >> 7)) return error.Overflow;

        value += 1;
        value <<= 7;
    } else {
        return error.Overflow;
    }

    // only applies in the case that we extended to u8
    if (U != T) {
        if (value > std.math.maxInt(T)) return error.Overflow;
        return @truncate(T, value);
    } else {
        return value;
    }
}

test "read" {
    {
        var reader = std.io.fixedBufferStream("\x7f");
        std.testing.expectEqual(@as(u8, 0x7f), try read(u8, reader.reader()));
    }
    {
        var reader = std.io.fixedBufferStream("\x80\x00");
        std.testing.expectEqual(@as(u8, 0x80), try read(u8, reader.reader()));
    }
    {
        var reader = std.io.fixedBufferStream("\x80\x7f");
        std.testing.expectEqual(@as(u8, 0xff), try read(u8, reader.reader()));
    }
    {
        var reader = std.io.fixedBufferStream("\x81\x7f");
        std.testing.expectEqual(@as(u9, 0x17f), try read(u9, reader.reader()));
    }
    {
        var reader = std.io.fixedBufferStream("\xff\x7f");
        std.testing.expectEqual(@as(u15, 16511), try read(u15, reader.reader()));
    }
    {
        var reader = std.io.fixedBufferStream("\x80\x80\x00");
        std.testing.expectEqual(@as(u15, 16512), try read(u15, reader.reader()));
    }
    {
        var reader = std.io.fixedBufferStream("\xff\xff\x7f");
        std.testing.expectEqual(@as(u22, 2113663), try read(u22, reader.reader()));
    }
}

/// Write a single unsigned integer to the given writer
pub fn write(writer: anytype, uint_value: anytype) !void {
    const T = @TypeOf(uint_value);
    const max_length = (@typeInfo(T).Int.bits + 6) / 7;
    var buf: [max_length]u8 = undefined;
    var pos: usize = max_length - 1;
    var value = uint_value;
    buf[pos] = @truncate(u7, value);
    while (true) {
        value >>= 7;
        if (value == 0) break;
        value -= 1;
        pos -= 1;
        buf[pos] = 0x80 | @as(u8, @truncate(u7, value));
    }
    try writer.writeAll(buf[pos..]);
}

test "write" {
    {
        var buffer: [4]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try write(fbs.writer(), @as(u8, 0x7f));
        std.testing.expectEqualSlices(u8, "\x7f", fbs.getWritten());
    }
    {
        var buffer: [4]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try write(fbs.writer(), @as(u8, 0x80));
        std.testing.expectEqualSlices(u8, "\x80\x00", fbs.getWritten());
    }
    {
        var buffer: [4]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try write(fbs.writer(), @as(u8, 0xff));
        std.testing.expectEqualSlices(u8, "\x80\x7f", fbs.getWritten());
    }
    {
        var buffer: [4]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try write(fbs.writer(), @as(u9, 0x17f));
        std.testing.expectEqualSlices(u8, "\x81\x7f", fbs.getWritten());
    }
    {
        var buffer: [4]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try write(fbs.writer(), @as(u15, 16511));
        std.testing.expectEqualSlices(u8, "\xff\x7f", fbs.getWritten());
    }
    {
        var buffer: [4]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try write(fbs.writer(), @as(u15, 16512));
        std.testing.expectEqualSlices(u8, "\x80\x80\x00", fbs.getWritten());
    }
    {
        var buffer: [4]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buffer);

        try write(fbs.writer(), @as(u22, 2113663));
        std.testing.expectEqualSlices(u8, "\xff\xff\x7f", fbs.getWritten());
    }
}
