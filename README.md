# zig-bluez

Zig wrapper using plain c bluetooth.h header and sources from [bluez](https://www.bluez.org/) sources in Linux kernel.

## Why?

Alternatives are limited:

* zble using plain zig is stale and also still dependent on C cources for dtb
* SimpleBle is client only and dependent on Bluez for proper use.

Bluez is the official source included Linux kernel so it is well maintained.

included is an example of a GATT server with write characteristics that can be included in a zig project

## How?

Needed are the bluez headers and sources in the following structure:

    ./include/bluez/lib         : core bluez headers
    ./include/bluez/src/shared  : shared bluez headers
    ./lib/bluez/libbluetooth    : core bluez sources
    ./lib/bluez/libshared       : shared bluez sources

The wrapper is here:

    ./lib/ble-gatt-server.c         : c implementation of exaple gatt server
    ./lib/ble-gatt-server-wrapper.c : wrapper to be included in zig

The wrapper exposes an extern function: `zig_write_handler` that can be used in a zig project as a write callback

```zig
extern "c" fn start_gatt_server() void;

// C calls this Zig function when characteristic is written
export fn zig_write_handler(data: [*]const u8, length: usize) void {
    std.debug.print("Zig received {d} bytes from GATT write: ", .{length});
    for (data[0..length]) |b| {
        std.debug.print("{x} ", .{b});
    }
    std.debug.print("\n", .{});
}
```
