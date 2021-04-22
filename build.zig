const std = @import("std");

fn addSqlite(exe_step: *std.build.LibExeObjStep) void {
    exe_step.linkLibC();
    exe_step.linkSystemLibrary("sqlite3");
    exe_step.addPackage(.{ .name = "sqlite", .path = "vendor/zig-sqlite/sqlite.zig" });
}

pub fn build(b: *std.build.Builder) void {
    const mode = b.standardReleaseOptions();

    var main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);
    addSqlite(main_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&main_tests.step);
}
