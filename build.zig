const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const bluezMod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .link_libcpp = false,
    });

    bluezMod.addCSourceFiles(.{
        .files = &.{
            "lib/bluez/libbluetooth/bluetooth.c",
            "lib/bluez/libbluetooth/hci.c",
            "lib/bluez/libbluetooth/uuid.c",
            "lib/bluez/libshared/att.c",
            "lib/bluez/libshared/crypto.c",
            "lib/bluez/libshared/gatt-client.c",
            "lib/bluez/libshared/gatt-db.c",
            "lib/bluez/libshared/gatt-helpers.c",
            "lib/bluez/libshared/gatt-server.c",
            "lib/bluez/libshared/mainloop.c",
            "lib/bluez/libshared/mainloop-notify.c",
            "lib/bluez/libshared/io-mainloop.c",
            "lib/bluez/libshared/timeout-mainloop.c",
            "lib/bluez/libshared/queue.c",
            "lib/bluez/libshared/util.c",
        },
        .flags = &.{},
    });
    bluezMod.addIncludePath(b.path("include/bluez"));
    bluezMod.addIncludePath(b.path("include/bluez/lib"));
    bluezMod.addIncludePath(b.path("include/bluez/src/shared"));

    // make libraryartifact, so it can be used in another build.zig
    const bluezLib = b.addLibrary(.{
        .name = "bluez",
        .linkage = .static,
        .root_module = bluezMod,
    });
    b.installArtifact(bluezLib);

    bluezLib.addCSourceFiles(.{
        .files = &.{
            "lib/ble-gatt-server-wrapper.c",
        },
        .flags = &.{},
    });

    const exe = b.addExecutable(.{
        .name = "gatt-bluez",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            // .imports = &.{
            //     .{ .name = "zig-bluez", .module = mod },
            // },
        }),
    });
    exe.linkLibrary(bluezLib);

    b.installArtifact(exe);
}
