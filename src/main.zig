const std = @import("std");

// C wrapper function to start server
extern "c" fn start_gatt_server() void;

// C calls this Zig function when characteristic is written
export fn zig_write_handler(data: [*]const u8, length: usize) void {
    std.debug.print("Zig received {d} bytes from GATT write: ", .{length});
    for (data[0..length]) |b| {
        std.debug.print("{x} ", .{b});
    }
    std.debug.print("\n", .{});
}

pub fn main() void {
    std.debug.print("Starting embedded BlueZ GATT server...\n", .{});
    start_gatt_server();
    std.debug.print("BlueZ GATT server has stopped.\n", .{});
}
