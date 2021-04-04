const Builder = @import("std").build.Builder;

pub fn build(b: *Builder) void {
    const main = b.addTest("./src/main.zig");
    main.setBuildMode(b.standardReleaseOptions());
    main.addIncludeDir("./src");
}
