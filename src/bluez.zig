const std = @import("std");
pub const struct_bt_att_pdu_error_rsp = extern struct {
    opcode: u8 align(1) = @import("std").mem.zeroes(u8),
    handle: u16 align(1) = @import("std").mem.zeroes(u16),
    ecode: u8 align(1) = @import("std").mem.zeroes(u8),
};
const union_unnamed_45 = extern union {
    u16: u16,
    u32: u32,
    u128: u128,
};
pub const bt_uuid_t = extern struct {
    type: c_uint = @import("std").mem.zeroes(c_uint),
    value: union_unnamed_45 = @import("std").mem.zeroes(union_unnamed_45),
};
pub const bdaddr_t = extern struct {
    b: [6]u8 align(1) = @import("std").mem.zeroes([6]u8),
};
// TODO: put_le16 simply ensures cpu_to_le16 16bit little-endian
pub fn put_le16(arg_val: u16, arg_dst: ?*anyopaque) callconv(.c) void {
    var val = arg_val;
    _ = &val;
    var dst = arg_dst;
    _ = &dst;
    dst = val;
}
pub extern fn memcpy(__dest: ?*anyopaque, __src: ?*const anyopaque, __n: c_ulong) ?*anyopaque;
pub fn bacpy(arg_dst: [*c]bdaddr_t, arg_src: [*c]const bdaddr_t) callconv(.c) void {
    var dst = arg_dst;
    _ = &dst;
    var src = arg_src;
    _ = &src;
    _ = memcpy(@as(?*anyopaque, @ptrCast(dst)), @as(?*const anyopaque, @ptrCast(src)), @sizeOf(bdaddr_t));
}
pub extern fn bt_string_to_uuid(uuid: [*c]bt_uuid_t, string: [*c]const u8) c_int;
pub const struct_queue = opaque {};
pub const struct_bt_att = opaque {};
pub const struct_bt_att_chan = opaque {};
pub extern fn bt_att_new(fd: c_int, ext_signed: bool) ?*struct_bt_att;
pub extern fn bt_att_ref(att: ?*struct_bt_att) ?*struct_bt_att;
pub extern fn bt_att_unref(att: ?*struct_bt_att) void;
pub extern fn bt_att_set_close_on_unref(att: ?*struct_bt_att, do_close: bool) bool;
pub extern fn bt_att_get_fd(att: ?*struct_bt_att) c_int;
pub extern fn bt_att_attach_fd(att: ?*struct_bt_att, fd: c_int) c_int;
pub extern fn bt_att_get_channels(att: ?*struct_bt_att) c_int;
pub const bt_att_response_func_t = ?*const fn (u8, ?*const anyopaque, u16, ?*anyopaque) callconv(.c) void;
pub const bt_att_notify_func_t = ?*const fn (?*struct_bt_att_chan, u8, ?*const anyopaque, u16, ?*anyopaque) callconv(.c) void;
pub const bt_att_destroy_func_t = ?*const fn (?*anyopaque) callconv(.c) void;
pub const bt_att_debug_func_t = ?*const fn ([*c]const u8, ?*anyopaque) callconv(.c) void;
pub const bt_att_timeout_func_t = ?*const fn (c_uint, u8, ?*anyopaque) callconv(.c) void;
pub const bt_att_disconnect_func_t = ?*const fn (c_int, ?*anyopaque) callconv(.c) void;
pub const bt_att_exchange_func_t = ?*const fn (u16, ?*anyopaque) callconv(.c) void;
pub const bt_att_counter_func_t = ?*const fn ([*c]u32, ?*anyopaque) callconv(.c) bool;
pub extern fn bt_att_set_debug(att: ?*struct_bt_att, level: u8, callback: bt_att_debug_func_t, user_data: ?*anyopaque, destroy: bt_att_destroy_func_t) bool;
pub extern fn bt_att_get_mtu(att: ?*struct_bt_att) u16;
pub extern fn bt_att_set_mtu(att: ?*struct_bt_att, mtu: u16) bool;
pub extern fn bt_att_get_link_type(att: ?*struct_bt_att) u8;
pub extern fn bt_att_set_timeout_cb(att: ?*struct_bt_att, callback: bt_att_timeout_func_t, user_data: ?*anyopaque, destroy: bt_att_destroy_func_t) bool;
pub extern fn bt_att_send(att: ?*struct_bt_att, opcode: u8, pdu: ?*const anyopaque, length: u16, callback: bt_att_response_func_t, user_data: ?*anyopaque, destroy: bt_att_destroy_func_t) c_uint;
pub extern fn bt_att_resend(att: ?*struct_bt_att, id: c_uint, opcode: u8, pdu: ?*const anyopaque, length: u16, callback: bt_att_response_func_t, user_data: ?*anyopaque, destroy: bt_att_destroy_func_t) c_int;
pub extern fn bt_att_chan_send(chan: ?*struct_bt_att_chan, opcode: u8, pdu: ?*const anyopaque, len: u16, callback: bt_att_response_func_t, user_data: ?*anyopaque, destroy: bt_att_destroy_func_t) c_uint;
pub extern fn bt_att_chan_cancel(chan: ?*struct_bt_att_chan, id: c_uint) bool;
pub extern fn bt_att_cancel(att: ?*struct_bt_att, id: c_uint) bool;
pub extern fn bt_att_cancel_all(att: ?*struct_bt_att) bool;
pub extern fn bt_att_chan_send_error_rsp(chan: ?*struct_bt_att_chan, opcode: u8, handle: u16, @"error": c_int) c_int;
pub extern fn bt_att_register(att: ?*struct_bt_att, opcode: u8, callback: bt_att_notify_func_t, user_data: ?*anyopaque, destroy: bt_att_destroy_func_t) c_uint;
pub extern fn bt_att_unregister(att: ?*struct_bt_att, id: c_uint) bool;
pub extern fn bt_att_register_disconnect(att: ?*struct_bt_att, callback: bt_att_disconnect_func_t, user_data: ?*anyopaque, destroy: bt_att_destroy_func_t) c_uint;
pub extern fn bt_att_unregister_disconnect(att: ?*struct_bt_att, id: c_uint) bool;
pub extern fn bt_att_register_exchange(att: ?*struct_bt_att, callback: bt_att_exchange_func_t, user_data: ?*anyopaque, destroy: bt_att_destroy_func_t) c_uint;
pub extern fn bt_att_unregister_exchange(att: ?*struct_bt_att, id: c_uint) bool;
pub extern fn bt_att_unregister_all(att: ?*struct_bt_att) bool;
pub extern fn bt_att_get_security(att: ?*struct_bt_att, enc_size: [*c]u8) c_int;
pub extern fn bt_att_set_security(att: ?*struct_bt_att, level: c_int) bool;
pub extern fn bt_att_set_enc_key_size(att: ?*struct_bt_att, enc_size: u8) void;
pub extern fn bt_att_set_local_key(att: ?*struct_bt_att, sign_key: [*c]u8, func: bt_att_counter_func_t, user_data: ?*anyopaque) bool;
pub extern fn bt_att_set_remote_key(att: ?*struct_bt_att, sign_key: [*c]u8, func: bt_att_counter_func_t, user_data: ?*anyopaque) bool;
pub extern fn bt_att_has_crypto(att: ?*struct_bt_att) bool;

// GATT API
pub const struct_gatt_db = opaque {};
pub const struct_gatt_db_attribute = opaque {};
pub extern fn gatt_db_new() ?*struct_gatt_db;
pub extern fn gatt_db_ref(db: ?*struct_gatt_db) ?*struct_gatt_db;
pub extern fn gatt_db_unref(db: ?*struct_gatt_db) void;
pub extern fn gatt_db_isempty(db: ?*struct_gatt_db) bool;
pub extern fn gatt_db_add_service(db: ?*struct_gatt_db, uuid: [*c]const bt_uuid_t, primary: bool, num_handles: u16) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_remove_service(db: ?*struct_gatt_db, attrib: ?*struct_gatt_db_attribute) bool;
pub extern fn gatt_db_clear(db: ?*struct_gatt_db) bool;
pub extern fn gatt_db_clear_range(db: ?*struct_gatt_db, start_handle: u16, end_handle: u16) bool;
pub extern fn gatt_db_hash_support(db: ?*struct_gatt_db) bool;
pub extern fn gatt_db_get_hash(db: ?*struct_gatt_db) [*c]u8;
pub extern fn gatt_db_insert_service(db: ?*struct_gatt_db, handle: u16, uuid: [*c]const bt_uuid_t, primary: bool, num_handles: u16) ?*struct_gatt_db_attribute;
pub const gatt_db_read_t = ?*const fn (?*struct_gatt_db_attribute, c_uint, u16, u8, ?*struct_bt_att, ?*anyopaque) callconv(.c) void;
pub const gatt_db_write_t = ?*const fn (?*struct_gatt_db_attribute, c_uint, u16, [*c]const u8, usize, u8, ?*struct_bt_att, ?*anyopaque) callconv(.c) void;
pub const gatt_db_notify_t = ?*const fn (?*struct_gatt_db_attribute, ?*struct_gatt_db_attribute, [*c]const u8, usize, ?*struct_bt_att, ?*anyopaque) callconv(.c) void;
pub extern fn gatt_db_service_add_characteristic(attrib: ?*struct_gatt_db_attribute, uuid: [*c]const bt_uuid_t, permissions: u32, properties: u8, read_func: gatt_db_read_t, write_func: gatt_db_write_t, user_data: ?*anyopaque) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_service_insert_characteristic(attrib: ?*struct_gatt_db_attribute, handle: u16, uuid: [*c]const bt_uuid_t, permissions: u32, properties: u8, read_func: gatt_db_read_t, write_func: gatt_db_write_t, user_data: ?*anyopaque) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_insert_characteristic(db: ?*struct_gatt_db, handle: u16, uuid: [*c]const bt_uuid_t, permissions: u32, properties: u8, read_func: gatt_db_read_t, write_func: gatt_db_write_t, user_data: ?*anyopaque) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_insert_descriptor(db: ?*struct_gatt_db, handle: u16, uuid: [*c]const bt_uuid_t, permissions: u32, read_func: gatt_db_read_t, write_func: gatt_db_write_t, user_data: ?*anyopaque) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_service_add_descriptor(attrib: ?*struct_gatt_db_attribute, uuid: [*c]const bt_uuid_t, permissions: u32, read_func: gatt_db_read_t, write_func: gatt_db_write_t, user_data: ?*anyopaque) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_service_insert_descriptor(attrib: ?*struct_gatt_db_attribute, handle: u16, uuid: [*c]const bt_uuid_t, permissions: u32, read_func: gatt_db_read_t, write_func: gatt_db_write_t, user_data: ?*anyopaque) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_service_add_ccc(attrib: ?*struct_gatt_db_attribute, permissions: u32) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_insert_included(db: ?*struct_gatt_db, handle: u16, include: ?*struct_gatt_db_attribute) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_service_add_included(attrib: ?*struct_gatt_db_attribute, include: ?*struct_gatt_db_attribute) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_service_insert_included(attrib: ?*struct_gatt_db_attribute, handle: u16, include: ?*struct_gatt_db_attribute) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_service_set_active(attrib: ?*struct_gatt_db_attribute, active: bool) bool;
pub extern fn gatt_db_service_get_active(attrib: ?*struct_gatt_db_attribute) bool;
pub extern fn gatt_db_service_set_claimed(attrib: ?*struct_gatt_db_attribute, claimed: bool) bool;
pub extern fn gatt_db_service_get_claimed(attrib: ?*struct_gatt_db_attribute) bool;
pub const gatt_db_attribute_cb_t = ?*const fn (?*struct_gatt_db_attribute, ?*anyopaque) callconv(.c) void;
pub extern fn gatt_db_read_by_group_type(db: ?*struct_gatt_db, start_handle: u16, end_handle: u16, @"type": bt_uuid_t, queue: ?*struct_queue) void;
pub extern fn gatt_db_find_by_type(db: ?*struct_gatt_db, start_handle: u16, end_handle: u16, @"type": [*c]const bt_uuid_t, func: gatt_db_attribute_cb_t, user_data: ?*anyopaque) c_uint;
pub extern fn gatt_db_find_by_type_value(db: ?*struct_gatt_db, start_handle: u16, end_handle: u16, @"type": [*c]const bt_uuid_t, value: ?*const anyopaque, value_len: usize, func: gatt_db_attribute_cb_t, user_data: ?*anyopaque) c_uint;
pub extern fn gatt_db_read_by_type(db: ?*struct_gatt_db, start_handle: u16, end_handle: u16, @"type": bt_uuid_t, queue: ?*struct_queue) void;
pub extern fn gatt_db_find_information(db: ?*struct_gatt_db, start_handle: u16, end_handle: u16, queue: ?*struct_queue) void;
pub extern fn gatt_db_foreach_service(db: ?*struct_gatt_db, uuid: [*c]const bt_uuid_t, func: gatt_db_attribute_cb_t, user_data: ?*anyopaque) void;
pub extern fn gatt_db_foreach_in_range(db: ?*struct_gatt_db, uuid: [*c]const bt_uuid_t, func: gatt_db_attribute_cb_t, user_data: ?*anyopaque, start_handle: u16, end_handle: u16) void;
pub extern fn gatt_db_foreach_service_in_range(db: ?*struct_gatt_db, uuid: [*c]const bt_uuid_t, func: gatt_db_attribute_cb_t, user_data: ?*anyopaque, start_handle: u16, end_handle: u16) void;
pub extern fn gatt_db_service_foreach(attrib: ?*struct_gatt_db_attribute, uuid: [*c]const bt_uuid_t, func: gatt_db_attribute_cb_t, user_data: ?*anyopaque) void;
pub extern fn gatt_db_service_foreach_char(attrib: ?*struct_gatt_db_attribute, func: gatt_db_attribute_cb_t, user_data: ?*anyopaque) void;
pub extern fn gatt_db_service_foreach_desc(attrib: ?*struct_gatt_db_attribute, func: gatt_db_attribute_cb_t, user_data: ?*anyopaque) void;
pub extern fn gatt_db_service_foreach_incl(attrib: ?*struct_gatt_db_attribute, func: gatt_db_attribute_cb_t, user_data: ?*anyopaque) void;
pub const gatt_db_destroy_func_t = ?*const fn (?*anyopaque) callconv(.c) void;
pub extern fn gatt_db_register(db: ?*struct_gatt_db, service_added: gatt_db_attribute_cb_t, service_removed: gatt_db_attribute_cb_t, user_data: ?*anyopaque, destroy: gatt_db_destroy_func_t) c_uint;
pub extern fn gatt_db_unregister(db: ?*struct_gatt_db, id: c_uint) bool;
pub extern fn gatt_db_ccc_register(db: ?*struct_gatt_db, read_func: gatt_db_read_t, write_func: gatt_db_write_t, notify_func: gatt_db_notify_t, user_data: ?*anyopaque) void;
pub const gatt_db_authorize_cb_t = ?*const fn (?*struct_gatt_db_attribute, u8, ?*struct_bt_att, ?*anyopaque) callconv(.c) u8;
pub extern fn gatt_db_set_authorize(db: ?*struct_gatt_db, cb: gatt_db_authorize_cb_t, user_data: ?*anyopaque) bool;
pub extern fn gatt_db_get_service(db: ?*struct_gatt_db, handle: u16) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_get_attribute(db: ?*struct_gatt_db, handle: u16) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_get_service_with_uuid(db: ?*struct_gatt_db, uuid: [*c]const bt_uuid_t) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_attribute_get_type(attrib: ?*const struct_gatt_db_attribute) [*c]const bt_uuid_t;
pub extern fn gatt_db_attribute_get_handle(attrib: ?*const struct_gatt_db_attribute) u16;
pub extern fn gatt_db_attribute_get_service(attrib: ?*const struct_gatt_db_attribute) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_attribute_get_service_uuid(attrib: ?*const struct_gatt_db_attribute, uuid: [*c]bt_uuid_t) bool;
pub extern fn gatt_db_attribute_get_service_handles(attrib: ?*const struct_gatt_db_attribute, start_handle: [*c]u16, end_handle: [*c]u16) bool;
pub extern fn gatt_db_attribute_get_service_data(attrib: ?*const struct_gatt_db_attribute, start_handle: [*c]u16, end_handle: [*c]u16, primary: [*c]bool, uuid: [*c]bt_uuid_t) bool;
pub extern fn gatt_db_attribute_get_char_data(attrib: ?*const struct_gatt_db_attribute, handle: [*c]u16, value_handle: [*c]u16, properties: [*c]u8, ext_prop: [*c]u16, uuid: [*c]bt_uuid_t) bool;
pub extern fn gatt_db_attribute_get_incl_data(attrib: ?*const struct_gatt_db_attribute, handle: [*c]u16, start_handle: [*c]u16, end_handle: [*c]u16) bool;
pub extern fn gatt_db_attribute_get_permissions(attrib: ?*const struct_gatt_db_attribute) u32;
pub extern fn gatt_db_attribute_set_fixed_length(attrib: ?*struct_gatt_db_attribute, len: u16) bool;
pub const gatt_db_attribute_read_t = ?*const fn (?*struct_gatt_db_attribute, c_int, [*c]const u8, usize, ?*anyopaque) callconv(.c) void;
pub extern fn gatt_db_attribute_read(attrib: ?*struct_gatt_db_attribute, offset: u16, opcode: u8, att: ?*struct_bt_att, func: gatt_db_attribute_read_t, user_data: ?*anyopaque) bool;
pub extern fn gatt_db_attribute_read_result(attrib: ?*struct_gatt_db_attribute, id: c_uint, err: c_int, value: [*c]const u8, length: usize) bool;
pub const gatt_db_attribute_write_t = ?*const fn (?*struct_gatt_db_attribute, c_int, ?*anyopaque) callconv(.c) void;
pub extern fn gatt_db_attribute_write(attrib: ?*struct_gatt_db_attribute, offset: u16, value: [*c]const u8, len: usize, opcode: u8, att: ?*struct_bt_att, func: gatt_db_attribute_write_t, user_data: ?*anyopaque) bool;
pub extern fn gatt_db_attribute_write_result(attrib: ?*struct_gatt_db_attribute, id: c_uint, err: c_int) bool;
pub extern fn gatt_db_attribute_get_value(attrib: ?*struct_gatt_db_attribute) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_attribute_get_ccc(attrib: ?*struct_gatt_db_attribute) ?*struct_gatt_db_attribute;
pub extern fn gatt_db_attribute_notify(attrib: ?*struct_gatt_db_attribute, value: [*c]const u8, len: usize, att: ?*struct_bt_att) bool;
pub extern fn gatt_db_attribute_reset(attrib: ?*struct_gatt_db_attribute) bool;
pub extern fn gatt_db_attribute_get_user_data(attrib: ?*struct_gatt_db_attribute) ?*anyopaque;
pub extern fn gatt_db_attribute_register(attrib: ?*struct_gatt_db_attribute, removed: gatt_db_attribute_cb_t, user_data: ?*anyopaque, destroy: gatt_db_destroy_func_t) c_uint;
pub extern fn gatt_db_attribute_unregister(attrib: ?*struct_gatt_db_attribute, id: c_uint) bool;
pub const struct_bt_gatt_server = opaque {};
pub extern fn bt_gatt_server_new(db: ?*struct_gatt_db, att: ?*struct_bt_att, mtu: u16, min_enc_size: u8) ?*struct_bt_gatt_server;
pub extern fn bt_gatt_server_get_mtu(server: ?*struct_bt_gatt_server) u16;
pub extern fn bt_gatt_server_get_att(server: ?*struct_bt_gatt_server) ?*struct_bt_att;
pub extern fn bt_gatt_server_ref(server: ?*struct_bt_gatt_server) ?*struct_bt_gatt_server;
pub extern fn bt_gatt_server_unref(server: ?*struct_bt_gatt_server) void;
pub const bt_gatt_server_destroy_func_t = ?*const fn (?*anyopaque) callconv(.c) void;
pub const bt_gatt_server_debug_func_t = ?*const fn ([*c]const u8, ?*anyopaque) callconv(.c) void;
pub const bt_gatt_server_conf_func_t = ?*const fn (?*anyopaque) callconv(.c) void;
pub extern fn bt_gatt_server_set_debug(server: ?*struct_bt_gatt_server, callback: bt_gatt_server_debug_func_t, user_data: ?*anyopaque, destroy: bt_gatt_server_destroy_func_t) bool;
pub const bt_gatt_server_authorize_cb_t = ?*const fn (?*struct_bt_att, u8, u16, ?*anyopaque) callconv(.c) u8;
pub extern fn bt_gatt_server_set_authorize(server: ?*struct_bt_gatt_server, cb: bt_gatt_server_authorize_cb_t, user_data: ?*anyopaque) bool;
pub extern fn bt_gatt_server_send_notification(server: ?*struct_bt_gatt_server, handle: u16, value: [*c]const u8, length: u16, multiple: bool) bool;
pub extern fn bt_gatt_server_send_indication(server: ?*struct_bt_gatt_server, handle: u16, value: [*c]const u8, length: u16, callback: bt_gatt_server_conf_func_t, user_data: ?*anyopaque, destroy: bt_gatt_server_destroy_func_t) bool;
pub var verbose: bool = @as(c_int, 0) != 0;
pub extern fn strerror(__errnum: c_int) [*c]u8;
pub const struct_server = extern struct {
    fd: c_int = @import("std").mem.zeroes(c_int),
    att: ?*struct_bt_att = @import("std").mem.zeroes(?*struct_bt_att),
    db: ?*struct_gatt_db = @import("std").mem.zeroes(?*struct_gatt_db),
    gatt: ?*struct_bt_gatt_server = @import("std").mem.zeroes(?*struct_bt_gatt_server),
    device_name: [*c]u8 = @import("std").mem.zeroes([*c]u8),
    name_len: usize = @import("std").mem.zeroes(usize),
    gatt_svc_chngd_handle: u16 = @import("std").mem.zeroes(u16),
    svc_chngd_enabled: bool = @import("std").mem.zeroes(bool),
    custom_handle: u16 = @import("std").mem.zeroes(u16),
    msg_txt_char_handle: u16 = @import("std").mem.zeroes(u16),
    msg_txt_handle: u16 = @import("std").mem.zeroes(u16),
    custom_visible: bool = @import("std").mem.zeroes(bool),
    custom_enabled: bool = @import("std").mem.zeroes(bool),
    msg_timeout_id: c_uint = @import("std").mem.zeroes(c_uint),
};
pub fn att_disconnect_cb(arg_err: c_int, arg_user_data: ?*anyopaque) callconv(.c) void {
    var err = arg_err;
    _ = &err;
    var user_data = arg_user_data;
    _ = &user_data;
    std.debug.print("Device disconnected: {s}\n", strerror(err));
    // TODO: quit loop?
    //mainloop_quit();
}

// ble-test-server.c:99:13: warning: unable to translate function, demoted to extern
pub extern fn gap_device_name_read_cb(arg_attrib: ?*struct_gatt_db_attribute, arg_id: c_uint, arg_offset: u16, arg_opcode: u8, arg_att: ?*struct_bt_att, arg_user_data: ?*anyopaque) callconv(.c) void;
// ble-test-server.c:140:3: warning: TODO implement translation of stmt class GotoStmtClass

// ble-test-server.c:124:13: warning: unable to translate function, demoted to extern
pub extern fn gap_device_name_write_cb(arg_attrib: ?*struct_gatt_db_attribute, arg_id: c_uint, arg_offset: u16, arg_value: [*c]const u8, arg_len: usize, arg_opcode: u8, arg_att: ?*struct_bt_att, arg_user_data: ?*anyopaque) callconv(.c) void;
pub fn gap_device_name_ext_prop_read_cb(arg_attrib: ?*struct_gatt_db_attribute, arg_id: c_uint, arg_offset: u16, arg_opcode: u8, arg_att: ?*struct_bt_att, arg_user_data: ?*anyopaque) callconv(.c) void {
    var attrib = arg_attrib;
    _ = &attrib;
    var id = arg_id;
    _ = &id;
    var offset = arg_offset;
    _ = &offset;
    var opcode = arg_opcode;
    _ = &opcode;
    var att = arg_att;
    _ = &att;
    var user_data = arg_user_data;
    _ = &user_data;
    var value: [2]u8 = undefined;
    _ = &value;
    std.debug.print("Device Name Extended Properties Read called\n");
    std.debug.print("ID: {d}\n", id);
    value[@as(c_uint, @intCast(@as(c_int, 0)))] = 1;
    value[@as(c_uint, @intCast(@as(c_int, 1)))] = 0;
    _ = gatt_db_attribute_read_result(attrib, id, @as(c_int, 0), @as([*c]u8, @ptrCast(@alignCast(&value[@as(usize, @intCast(0))]))), @sizeOf([2]u8));
}
// ble-test-server.c:258:9: warning: TODO implement translation of stmt class GotoStmtClass

// ble-test-server.c:249:13: warning: unable to translate function, demoted to extern
pub extern fn msg_text_write(arg_attrib: ?*struct_gatt_db_attribute, arg_id: c_uint, arg_offset: u16, arg_value: [*c]const u8, arg_len: usize, arg_opcode: u8, arg_att: ?*struct_bt_att, arg_user_data: ?*anyopaque) callconv(.c) void;
pub fn confirm_write(arg_attr: ?*struct_gatt_db_attribute, arg_err: c_int, arg_user_data: ?*anyopaque) callconv(.c) void {
    var attr = arg_attr;
    _ = &attr;
    var err = arg_err;
    _ = &err;
    var user_data = arg_user_data;
    _ = &user_data;
    if (!(err != 0)) {
        return;
    }
    _ = std.debug.print("Error caching attribute {any} - err: {d}\n", attr, err);
    // TODO : return error
    //exit(@as(c_int, 1));
}
pub extern fn bt_uuid16_create(btuuid: [*c]bt_uuid_t, value: u16) c_int;
pub fn populate_gap_service(arg_server_1: [*c]struct_server) callconv(.c) void {
    var server_1 = arg_server_1;
    _ = &server_1;
    var uuid: bt_uuid_t = undefined;
    _ = &uuid;
    var service: ?*struct_gatt_db_attribute = undefined;
    _ = &service;
    var tmp: ?*struct_gatt_db_attribute = undefined;
    _ = &tmp;
    var appearance: u16 = undefined;
    _ = &appearance;
    _ = bt_uuid16_create(&uuid, @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 6144))))));
    service = gatt_db_add_service(server_1.*.db, &uuid, @as(c_int, 1) != 0, @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 6))))));
    _ = bt_uuid16_create(&uuid, @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 10752))))));
    _ = gatt_db_service_add_characteristic(service, &uuid, @as(u32, @bitCast(@as(c_int, 1) | @as(c_int, 2))), @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, 2) | @as(c_int, 128))))), &gap_device_name_read_cb, &gap_device_name_write_cb, @as(?*anyopaque, @ptrCast(server_1)));
    _ = bt_uuid16_create(&uuid, @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 10496))))));
    _ = gatt_db_service_add_descriptor(service, &uuid, @as(u32, @bitCast(@as(c_int, 1))), &gap_device_name_ext_prop_read_cb, null, @as(?*anyopaque, @ptrCast(server_1)));
    _ = bt_uuid16_create(&uuid, @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 10753))))));
    tmp = gatt_db_service_add_characteristic(service, &uuid, @as(u32, @bitCast(@as(c_int, 1))), @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, 2))))), null, null, @as(?*anyopaque, @ptrCast(server_1)));
    put_le16(@as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 128))))), @as(?*anyopaque, @ptrCast(&appearance)));
    _ = gatt_db_attribute_write(tmp, @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 0))))), @as([*c]const u8, @ptrCast(@alignCast(@as(?*anyopaque, @ptrCast(&appearance))))), @sizeOf(u16), @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, 18))))), null, &confirm_write, @as(?*anyopaque, @ptrFromInt(@as(c_int, 0))));
    _ = gatt_db_service_set_active(service, @as(c_int, 1) != 0);
}
pub fn populate_custom_service(arg_server_1: [*c]struct_server) callconv(.c) void {
    var server_1 = arg_server_1;
    _ = &server_1;
    var uuid: bt_uuid_t = undefined;
    _ = &uuid;
    var service: ?*struct_gatt_db_attribute = undefined;
    _ = &service;
    var msg_txt_char: ?*struct_gatt_db_attribute = undefined;
    _ = &msg_txt_char;
    _ = bt_string_to_uuid(&uuid, "3eb50001-a886-11f0-8ab1-a3bea93ac534");
    service = gatt_db_add_service(server_1.*.db, &uuid, @as(c_int, 1) != 0, @as(u16, @bitCast(@as(c_short, @truncate(@as(c_int, 8))))));
    server_1.*.custom_handle = gatt_db_attribute_get_handle(service);
    _ = bt_string_to_uuid(&uuid, "3eb50002-a886-11f0-8ab1-a3bea93ac534");
    std.debug.print("Custom characteristics UUID: {s}\n", "3eb50002-a886-11f0-8ab1-a3bea93ac534");
    msg_txt_char = gatt_db_service_add_characteristic(service, &uuid, @as(u32, @bitCast(@as(c_int, 1) | @as(c_int, 2))), @as(u8, @bitCast(@as(i8, @truncate(@as(c_int, 8) | @as(c_int, 2))))), null, &msg_text_write, @as(?*anyopaque, @ptrFromInt(@as(c_int, 0))));
    server_1.*.msg_txt_char_handle = gatt_db_attribute_get_handle(msg_txt_char);
    _ = gatt_db_service_set_active(service, @as(c_int, 1) != 0);
}
pub fn populate_db(arg_server_1: [*c]struct_server) callconv(.c) void {
    var server_1 = arg_server_1;
    _ = &server_1;
    std.debug.print("Populating BLE DB...\n");
    populate_gap_service(server_1);
    populate_custom_service(server_1);
}
// ble-test-server.c:421:3: warning: TODO implement translation of stmt class GotoStmtClass

// ble-test-server.c:408:23: warning: unable to translate function, demoted to extern
pub extern fn server_create(arg_fd: c_int, arg_mtu: u16, arg_custom_visible: bool) callconv(.c) [*c]struct_server;
pub fn server_destroy(arg_server_1: [*c]struct_server) callconv(.c) void {
    var server_1 = arg_server_1;
    _ = &server_1;
    // TODO : server destroy
    //timeout_remove(server_1.*.msg_timeout_id);
    bt_gatt_server_unref(server_1.*.gatt);
    gatt_db_unref(server_1.*.db);
}
// ble-test-server.c:510:3: warning: TODO implement translation of stmt class GotoStmtClass

// ble-test-server.c:488:12: warning: unable to translate function, demoted to extern
pub extern fn l2cap_le_att_listen_and_accept(arg_src: [*c]bdaddr_t, arg_sec: c_int, arg_src_type: u8) callconv(.c) c_int;
pub fn conf_cb(arg_user_data: ?*anyopaque) callconv(.c) void {
    var user_data = arg_user_data;
    _ = &user_data;
    std.debug.print("Received confirmation\n");
}
// BDADDR
pub const BDADDR_BREDR = @as(c_int, 0x00);
pub const BDADDR_LE_PUBLIC = @as(c_int, 0x01);
pub const BDADDR_LE_RANDOM = @as(c_int, 0x02);
// TODO: ANY/ALL/LOCAL
pub const BDADDR_ANY: [*c]const bdaddr_t = undefined;
//pub const BDADDR_ALL   (&(bdaddr_t) {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}})
//pub const BDADDR_LOCAL (&(bdaddr_t) {{0, 0, 0, 0xff, 0xff, 0xff}})

pub const BT_ATT_CID = @as(c_int, 4);
pub const BT_ATT_PSM = @as(c_int, 31);
pub const BT_ATT_EATT_PSM = @as(c_int, 0x27);
pub const BT_ATT_SECURITY_AUTO = @as(c_int, 0);
pub const BT_ATT_SECURITY_LOW = @as(c_int, 1);
pub const BT_ATT_SECURITY_MEDIUM = @as(c_int, 2);
pub const BT_ATT_SECURITY_HIGH = @as(c_int, 3);
pub const BT_ATT_SECURITY_FIPS = @as(c_int, 4);
pub const BT_ATT_DEFAULT_LE_MTU = @as(c_int, 23);
pub const BT_ATT_MAX_LE_MTU = @as(c_int, 517);
pub const BT_ATT_MAX_VALUE_LEN = @as(c_int, 512);
pub const BT_ATT_BREDR = @as(c_int, 0x00);
pub const BT_ATT_LE = @as(c_int, 0x01);
pub const BT_ATT_EATT = @as(c_int, 0x02);
pub const BT_ATT_LOCAL = @as(c_int, 0xff);
pub const BT_ATT_OP_ERROR_RSP = @as(c_int, 0x01);
pub const BT_ATT_OP_MTU_REQ = @as(c_int, 0x02);
pub const BT_ATT_OP_MTU_RSP = @as(c_int, 0x03);
pub const BT_ATT_OP_FIND_INFO_REQ = @as(c_int, 0x04);
pub const BT_ATT_OP_FIND_INFO_RSP = @as(c_int, 0x05);
pub const BT_ATT_OP_FIND_BY_TYPE_REQ = @as(c_int, 0x06);
pub const BT_ATT_OP_FIND_BY_TYPE_RSP = @as(c_int, 0x07);
pub const BT_ATT_OP_READ_BY_TYPE_REQ = @as(c_int, 0x08);
pub const BT_ATT_OP_READ_BY_TYPE_RSP = @as(c_int, 0x09);
pub const BT_ATT_OP_READ_REQ = @as(c_int, 0x0a);
pub const BT_ATT_OP_READ_RSP = @as(c_int, 0x0b);
pub const BT_ATT_OP_READ_BLOB_REQ = @as(c_int, 0x0c);
pub const BT_ATT_OP_READ_BLOB_RSP = @as(c_int, 0x0d);
pub const BT_ATT_OP_READ_MULT_REQ = @as(c_int, 0x0e);
pub const BT_ATT_OP_READ_MULT_RSP = @as(c_int, 0x0f);
pub const BT_ATT_OP_READ_BY_GRP_TYPE_REQ = @as(c_int, 0x10);
pub const BT_ATT_OP_READ_BY_GRP_TYPE_RSP = @as(c_int, 0x11);
pub const BT_ATT_OP_WRITE_REQ = @as(c_int, 0x12);
pub const BT_ATT_OP_WRITE_RSP = @as(c_int, 0x13);
pub const BT_ATT_OP_WRITE_CMD = @as(c_int, 0x52);
pub const BT_ATT_OP_SIGNED_WRITE_CMD = @as(c_int, 0xD2);
pub const BT_ATT_OP_PREP_WRITE_REQ = @as(c_int, 0x16);
pub const BT_ATT_OP_PREP_WRITE_RSP = @as(c_int, 0x17);
pub const BT_ATT_OP_EXEC_WRITE_REQ = @as(c_int, 0x18);
pub const BT_ATT_OP_EXEC_WRITE_RSP = @as(c_int, 0x19);
pub const BT_ATT_OP_HANDLE_NFY = @as(c_int, 0x1B);
pub const BT_ATT_OP_HANDLE_IND = @as(c_int, 0x1D);
pub const BT_ATT_OP_HANDLE_CONF = @as(c_int, 0x1E);
pub const BT_ATT_OP_READ_MULT_VL_REQ = @as(c_int, 0x20);
pub const BT_ATT_OP_READ_MULT_VL_RSP = @as(c_int, 0x21);
pub const BT_ATT_OP_HANDLE_NFY_MULT = @as(c_int, 0x23);
pub const BT_ATT_ALL_REQUESTS = @as(c_int, 0x00);
pub const BT_ATT_ERROR_INVALID_HANDLE = @as(c_int, 0x01);
pub const BT_ATT_ERROR_READ_NOT_PERMITTED = @as(c_int, 0x02);
pub const BT_ATT_ERROR_WRITE_NOT_PERMITTED = @as(c_int, 0x03);
pub const BT_ATT_ERROR_INVALID_PDU = @as(c_int, 0x04);
pub const BT_ATT_ERROR_AUTHENTICATION = @as(c_int, 0x05);
pub const BT_ATT_ERROR_REQUEST_NOT_SUPPORTED = @as(c_int, 0x06);
pub const BT_ATT_ERROR_INVALID_OFFSET = @as(c_int, 0x07);
pub const BT_ATT_ERROR_AUTHORIZATION = @as(c_int, 0x08);
pub const BT_ATT_ERROR_PREPARE_QUEUE_FULL = @as(c_int, 0x09);
pub const BT_ATT_ERROR_ATTRIBUTE_NOT_FOUND = @as(c_int, 0x0A);
pub const BT_ATT_ERROR_ATTRIBUTE_NOT_LONG = @as(c_int, 0x0B);
pub const BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION_KEY_SIZE = @as(c_int, 0x0C);
pub const BT_ATT_ERROR_INVALID_ATTRIBUTE_VALUE_LEN = @as(c_int, 0x0D);
pub const BT_ATT_ERROR_UNLIKELY = @as(c_int, 0x0E);
pub const BT_ATT_ERROR_INSUFFICIENT_ENCRYPTION = @as(c_int, 0x0F);
pub const BT_ATT_ERROR_UNSUPPORTED_GROUP_TYPE = @as(c_int, 0x10);
pub const BT_ATT_ERROR_INSUFFICIENT_RESOURCES = @as(c_int, 0x11);
pub const BT_ATT_ERROR_DB_OUT_OF_SYNC = @as(c_int, 0x12);
pub const BT_ATT_ERROR_VALUE_NOT_ALLOWED = @as(c_int, 0x13);
pub const BT_ERROR_WRITE_REQUEST_REJECTED = @as(c_int, 0xfc);
pub const BT_ERROR_CCC_IMPROPERLY_CONFIGURED = @as(c_int, 0xfd);
pub const BT_ERROR_ALREADY_IN_PROGRESS = @as(c_int, 0xfe);
pub const BT_ERROR_OUT_OF_RANGE = @as(c_int, 0xff);
pub const BT_ATT_PERM_READ = @as(c_int, 0x01);
pub const BT_ATT_PERM_WRITE = @as(c_int, 0x02);
pub const BT_ATT_PERM_READ_ENCRYPT = @as(c_int, 0x04);
pub const BT_ATT_PERM_WRITE_ENCRYPT = @as(c_int, 0x08);
pub const BT_ATT_PERM_ENCRYPT = BT_ATT_PERM_READ_ENCRYPT | BT_ATT_PERM_WRITE_ENCRYPT;
pub const BT_ATT_PERM_READ_AUTHEN = @as(c_int, 0x10);
pub const BT_ATT_PERM_WRITE_AUTHEN = @as(c_int, 0x20);
pub const BT_ATT_PERM_AUTHEN = BT_ATT_PERM_READ_AUTHEN | BT_ATT_PERM_WRITE_AUTHEN;
pub const BT_ATT_PERM_AUTHOR = @as(c_int, 0x40);
pub const BT_ATT_PERM_NONE = @as(c_int, 0x80);
pub const BT_ATT_PERM_READ_SECURE = @as(c_int, 0x0100);
pub const BT_ATT_PERM_WRITE_SECURE = @as(c_int, 0x0200);
pub const BT_ATT_PERM_SECURE = BT_ATT_PERM_READ_SECURE | BT_ATT_PERM_WRITE_SECURE;
pub const BT_ATT_PERM_READ_MASK = ((BT_ATT_PERM_READ | BT_ATT_PERM_READ_AUTHEN) | BT_ATT_PERM_READ_ENCRYPT) | BT_ATT_PERM_READ_SECURE;
pub const BT_ATT_PERM_WRITE_MASK = ((BT_ATT_PERM_WRITE | BT_ATT_PERM_WRITE_AUTHEN) | BT_ATT_PERM_WRITE_ENCRYPT) | BT_ATT_PERM_WRITE_SECURE;
pub const BT_GATT_CHRC_PROP_BROADCAST = @as(c_int, 0x01);
pub const BT_GATT_CHRC_PROP_READ = @as(c_int, 0x02);
pub const BT_GATT_CHRC_PROP_WRITE_WITHOUT_RESP = @as(c_int, 0x04);
pub const BT_GATT_CHRC_PROP_WRITE = @as(c_int, 0x08);
pub const BT_GATT_CHRC_PROP_NOTIFY = @as(c_int, 0x10);
pub const BT_GATT_CHRC_PROP_INDICATE = @as(c_int, 0x20);
pub const BT_GATT_CHRC_PROP_AUTH = @as(c_int, 0x40);
pub const BT_GATT_CHRC_PROP_EXT_PROP = @as(c_int, 0x80);
pub const BT_GATT_CHRC_EXT_PROP_RELIABLE_WRITE = @as(c_int, 0x01);
pub const BT_GATT_CHRC_EXT_PROP_WRITABLE_AUX = @as(c_int, 0x02);
pub const BT_GATT_CHRC_CLI_FEAT_ROBUST_CACHING = @as(c_int, 0x01);
pub const BT_GATT_CHRC_CLI_FEAT_EATT = @as(c_int, 0x02);
pub const BT_GATT_CHRC_CLI_FEAT_NFY_MULTI = @as(c_int, 0x04);
pub const BT_GATT_CHRC_SERVER_FEAT_EATT = @as(c_int, 0x01);
pub const BT_ATT_DEBUG = @as(c_int, 0x00);
pub const BT_ATT_DEBUG_VERBOSE = @as(c_int, 0x01);
pub const BT_ATT_DEBUG_HEXDUMP = @as(c_int, 0x02);
pub inline fn bt_att_chan_send_rsp(chan: anytype, opcode: anytype, pdu: anytype, len: anytype) @TypeOf(bt_att_chan_send(chan, opcode, pdu, len, null, null, null)) {
    _ = &chan;
    _ = &opcode;
    _ = &pdu;
    _ = &len;
    return bt_att_chan_send(chan, opcode, pdu, len, null, null, null);
}
pub const UUID_GAP = @as(c_int, 0x1800);
pub const UUID_GATT = @as(c_int, 0x1801);
pub const UUID_MESSAGE = @as(c_int, 0x180e);
pub const UUID_MESSAGE_TEXT = @as(c_int, 0x1133);
pub const MAX_MSG_LENGTH = @as(c_int, 140);
pub const MAX_MSG_LOG = @as(c_int, 300);
pub const ATT_CID = @as(c_int, 4);

pub const BTPROTO_L2CAP = @as(c_int, 0);
pub const BTPROTO_HCI = @as(c_int, 1);
pub const BTPROTO_SCO = @as(c_int, 2);
pub const BTPROTO_RFCOMM = @as(c_int, 3);
pub const BTPROTO_BNEP = @as(c_int, 4);
pub const BTPROTO_CMTP = @as(c_int, 5);
pub const BTPROTO_HIDP = @as(c_int, 6);
pub const BTPROTO_AVDTP = @as(c_int, 7);
pub const BTPROTO_ISO = @as(c_int, 8);
pub const SOL_HCI = @as(c_int, 0);
pub const SOL_L2CAP = @as(c_int, 6);
pub const SOL_SCO = @as(c_int, 17);
pub const SOL_RFCOMM = @as(c_int, 18);
pub const BT_SECURITY = @as(c_int, 4);
pub const BT_SECURITY_SDP = @as(c_int, 0);
pub const BT_SECURITY_LOW = @as(c_int, 1);
pub const BT_SECURITY_MEDIUM = @as(c_int, 2);
pub const BT_SECURITY_HIGH = @as(c_int, 3);
pub const BT_SECURITY_FIPS = @as(c_int, 4);
pub const BT_DEFER_SETUP = @as(c_int, 7);
pub const BT_FLUSHABLE = @as(c_int, 8);
pub const BT_FLUSHABLE_OFF = @as(c_int, 0);
pub const BT_FLUSHABLE_ON = @as(c_int, 1);
pub const BT_POWER = @as(c_int, 9);
pub const BT_POWER_FORCE_ACTIVE_OFF = @as(c_int, 0);
pub const BT_POWER_FORCE_ACTIVE_ON = @as(c_int, 1);
pub const BT_CHANNEL_POLICY = @as(c_int, 10);
pub const BT_CHANNEL_POLICY_BREDR_ONLY = @as(c_int, 0);
pub const BT_CHANNEL_POLICY_BREDR_PREFERRED = @as(c_int, 1);
pub const BT_CHANNEL_POLICY_AMP_PREFERRED = @as(c_int, 2);
pub const BT_VOICE = @as(c_int, 11);
pub const BT_SNDMTU = @as(c_int, 12);
pub const BT_RCVMTU = @as(c_int, 13);
pub const BT_VOICE_TRANSPARENT = @as(c_int, 0x0003);
pub const BT_VOICE_CVSD_16BIT = @as(c_int, 0x0060);
pub const BT_PHY = @as(c_int, 14);
pub const BT_PHY_BR_1M_1SLOT = @as(c_int, 0x00000001);
pub const BT_PHY_BR_1M_3SLOT = @as(c_int, 0x00000002);
pub const BT_PHY_BR_1M_5SLOT = @as(c_int, 0x00000004);
pub const BT_PHY_EDR_2M_1SLOT = @as(c_int, 0x00000008);
pub const BT_PHY_EDR_2M_3SLOT = @as(c_int, 0x00000010);
pub const BT_PHY_EDR_2M_5SLOT = @as(c_int, 0x00000020);
pub const BT_PHY_EDR_3M_1SLOT = @as(c_int, 0x00000040);
pub const BT_PHY_EDR_3M_3SLOT = @as(c_int, 0x00000080);
pub const BT_PHY_EDR_3M_5SLOT = @as(c_int, 0x00000100);
pub const BT_PHY_LE_1M_TX = @as(c_int, 0x00000200);
pub const BT_PHY_LE_1M_RX = @as(c_int, 0x00000400);
pub const BT_PHY_LE_2M_TX = @as(c_int, 0x00000800);
pub const BT_PHY_LE_2M_RX = @as(c_int, 0x00001000);
pub const BT_PHY_LE_CODED_TX = @as(c_int, 0x00002000);
pub const BT_PHY_LE_CODED_RX = @as(c_int, 0x00004000);
pub const BT_MODE = @as(c_int, 15);
pub const BT_MODE_BASIC = @as(c_int, 0x00);
pub const BT_MODE_ERTM = @as(c_int, 0x01);
pub const BT_MODE_STREAMING = @as(c_int, 0x02);
pub const BT_MODE_LE_FLOWCTL = @as(c_int, 0x03);
pub const BT_MODE_EXT_FLOWCTL = @as(c_int, 0x04);
pub const BT_PKT_STATUS = @as(c_int, 16);
pub const BT_SCM_PKT_STATUS = @as(c_int, 0x03);
pub const BT_ISO_QOS = @as(c_int, 17);
pub const BT_ISO_QOS_CIG_UNSET = @as(c_int, 0xff);
pub const BT_ISO_QOS_CIS_UNSET = @as(c_int, 0xff);
pub const BT_ISO_QOS_BIG_UNSET = @as(c_int, 0xff);
pub const BT_ISO_QOS_BIS_UNSET = @as(c_int, 0xff);
pub const BT_ISO_QOS_GROUP_UNSET = @as(c_int, 0xff);
pub const BT_ISO_QOS_STREAM_UNSET = @as(c_int, 0xff);
pub const BASE_MAX_LENGTH = @as(c_int, 248);
pub const BT_CODEC = @as(c_int, 19);
pub const BT_ISO_BASE = @as(c_int, 20);

pub const PF_UNSPEC = @as(c_int, 0);
pub const PF_LOCAL = @as(c_int, 1);
pub const PF_UNIX = PF_LOCAL;
pub const PF_FILE = PF_LOCAL;
pub const PF_INET = @as(c_int, 2);
pub const PF_AX25 = @as(c_int, 3);
pub const PF_IPX = @as(c_int, 4);
pub const PF_APPLETALK = @as(c_int, 5);
pub const PF_NETROM = @as(c_int, 6);
pub const PF_BRIDGE = @as(c_int, 7);
pub const PF_ATMPVC = @as(c_int, 8);
pub const PF_X25 = @as(c_int, 9);
pub const PF_INET6 = @as(c_int, 10);
pub const PF_ROSE = @as(c_int, 11);
pub const PF_DECnet = @as(c_int, 12);
pub const PF_NETBEUI = @as(c_int, 13);
pub const PF_SECURITY = @as(c_int, 14);
pub const PF_KEY = @as(c_int, 15);
pub const PF_NETLINK = @as(c_int, 16);
pub const PF_ROUTE = PF_NETLINK;
pub const PF_PACKET = @as(c_int, 17);
pub const PF_ASH = @as(c_int, 18);
pub const PF_ECONET = @as(c_int, 19);
pub const PF_ATMSVC = @as(c_int, 20);
pub const PF_RDS = @as(c_int, 21);
pub const PF_SNA = @as(c_int, 22);
pub const PF_IRDA = @as(c_int, 23);
pub const PF_PPPOX = @as(c_int, 24);
pub const PF_WANPIPE = @as(c_int, 25);
pub const PF_LLC = @as(c_int, 26);
pub const PF_IB = @as(c_int, 27);
pub const PF_MPLS = @as(c_int, 28);
pub const PF_CAN = @as(c_int, 29);
pub const PF_TIPC = @as(c_int, 30);
pub const PF_BLUETOOTH = @as(c_int, 31);
pub const PF_IUCV = @as(c_int, 32);
pub const PF_RXRPC = @as(c_int, 33);
pub const PF_ISDN = @as(c_int, 34);
pub const PF_PHONET = @as(c_int, 35);
pub const PF_IEEE802154 = @as(c_int, 36);
pub const PF_CAIF = @as(c_int, 37);
pub const PF_ALG = @as(c_int, 38);
pub const PF_NFC = @as(c_int, 39);
pub const PF_VSOCK = @as(c_int, 40);
pub const PF_KCM = @as(c_int, 41);
pub const PF_QIPCRTR = @as(c_int, 42);
pub const PF_SMC = @as(c_int, 43);
pub const PF_XDP = @as(c_int, 44);
pub const PF_MCTP = @as(c_int, 45);
pub const PF_MAX = @as(c_int, 46);
pub const AF_UNSPEC = PF_UNSPEC;
pub const AF_LOCAL = PF_LOCAL;
pub const AF_UNIX = PF_UNIX;
pub const AF_FILE = PF_FILE;
pub const AF_INET = PF_INET;
pub const AF_AX25 = PF_AX25;
pub const AF_IPX = PF_IPX;
pub const AF_APPLETALK = PF_APPLETALK;
pub const AF_NETROM = PF_NETROM;
pub const AF_BRIDGE = PF_BRIDGE;
pub const AF_ATMPVC = PF_ATMPVC;
pub const AF_X25 = PF_X25;
pub const AF_INET6 = PF_INET6;
pub const AF_ROSE = PF_ROSE;
pub const AF_DECnet = PF_DECnet;
pub const AF_NETBEUI = PF_NETBEUI;
pub const AF_SECURITY = PF_SECURITY;
pub const AF_KEY = PF_KEY;
pub const AF_NETLINK = PF_NETLINK;
pub const AF_ROUTE = PF_ROUTE;
pub const AF_PACKET = PF_PACKET;
pub const AF_ASH = PF_ASH;
pub const AF_ECONET = PF_ECONET;
pub const AF_ATMSVC = PF_ATMSVC;
pub const AF_RDS = PF_RDS;
pub const AF_SNA = PF_SNA;
pub const AF_IRDA = PF_IRDA;
pub const AF_PPPOX = PF_PPPOX;
pub const AF_WANPIPE = PF_WANPIPE;
pub const AF_LLC = PF_LLC;
pub const AF_IB = PF_IB;
pub const AF_MPLS = PF_MPLS;
pub const AF_CAN = PF_CAN;
pub const AF_TIPC = PF_TIPC;
pub const AF_BLUETOOTH = PF_BLUETOOTH;
pub const AF_IUCV = PF_IUCV;
pub const AF_RXRPC = PF_RXRPC;
pub const AF_ISDN = PF_ISDN;
pub const AF_PHONET = PF_PHONET;
pub const AF_IEEE802154 = PF_IEEE802154;
pub const AF_CAIF = PF_CAIF;
pub const AF_ALG = PF_ALG;
pub const AF_NFC = PF_NFC;
pub const AF_VSOCK = PF_VSOCK;
pub const AF_KCM = PF_KCM;
pub const AF_QIPCRTR = PF_QIPCRTR;
pub const AF_SMC = PF_SMC;
pub const AF_XDP = PF_XDP;
pub const AF_MCTP = PF_MCTP;
pub const AF_MAX = PF_MAX;
pub const SOL_RAW = @as(c_int, 255);
pub const SOL_DECNET = @as(c_int, 261);
pub const SOL_X25 = @as(c_int, 262);
pub const SOL_PACKET = @as(c_int, 263);
pub const SOL_ATM = @as(c_int, 264);
pub const SOL_AAL = @as(c_int, 265);
pub const SOL_IRDA = @as(c_int, 266);
pub const SOL_NETBEUI = @as(c_int, 267);
pub const SOL_LLC = @as(c_int, 268);
pub const SOL_DCCP = @as(c_int, 269);
pub const SOL_NETLINK = @as(c_int, 270);
pub const SOL_TIPC = @as(c_int, 271);
pub const SOL_RXRPC = @as(c_int, 272);
pub const SOL_PPPOL2TP = @as(c_int, 273);
pub const SOL_BLUETOOTH = @as(c_int, 274);
pub const SOL_PNPIPE = @as(c_int, 275);
pub const SOL_RDS = @as(c_int, 276);
pub const SOL_IUCV = @as(c_int, 277);
pub const SOL_CAIF = @as(c_int, 278);
pub const SOL_ALG = @as(c_int, 279);
pub const SOL_NFC = @as(c_int, 280);
pub const SOL_KCM = @as(c_int, 281);
pub const SOL_TLS = @as(c_int, 282);
pub const SOL_XDP = @as(c_int, 283);
pub const SOL_MPTCP = @as(c_int, 284);
pub const SOL_MCTP = @as(c_int, 285);
pub const SOL_SMC = @as(c_int, 286);
pub const SOMAXCONN = @as(c_int, 4096);
pub const SOCK_STREAM: c_int = 1;
pub const SOCK_DGRAM: c_int = 2;
pub const SOCK_RAW: c_int = 3;
pub const SOCK_RDM: c_int = 4;
pub const SOCK_SEQPACKET: c_int = 5;
pub const SOCK_DCCP: c_int = 6;
pub const SOCK_PACKET: c_int = 10;
pub const SOCK_CLOEXEC: c_int = 524288;
pub const SOCK_NONBLOCK: c_int = 2048;
pub const enum___socket_type = c_uint;
pub const sa_family_t = c_ushort;
pub const struct_sockaddr = extern struct {
    sa_family: sa_family_t = @import("std").mem.zeroes(sa_family_t),
    sa_data: [14]u8 = @import("std").mem.zeroes([14]u8),
};
pub const struct_sockaddr_storage = extern struct {
    ss_family: sa_family_t = @import("std").mem.zeroes(sa_family_t),
    __ss_padding: [118]u8 = @import("std").mem.zeroes([118]u8),
    __ss_align: c_ulong = @import("std").mem.zeroes(c_ulong),
};
pub const MSG_OOB: c_int = 1;
pub const MSG_PEEK: c_int = 2;
pub const MSG_DONTROUTE: c_int = 4;
pub const MSG_TRYHARD: c_int = 4;
pub const MSG_CTRUNC: c_int = 8;
pub const MSG_PROXY: c_int = 16;
pub const MSG_TRUNC: c_int = 32;
pub const MSG_DONTWAIT: c_int = 64;
pub const MSG_EOR: c_int = 128;
pub const MSG_WAITALL: c_int = 256;
pub const MSG_FIN: c_int = 512;
pub const MSG_SYN: c_int = 1024;
pub const MSG_CONFIRM: c_int = 2048;
pub const MSG_RST: c_int = 4096;
pub const MSG_ERRQUEUE: c_int = 8192;
pub const MSG_NOSIGNAL: c_int = 16384;
pub const MSG_MORE: c_int = 32768;
pub const MSG_WAITFORONE: c_int = 65536;
pub const MSG_BATCH: c_int = 262144;
pub const MSG_ZEROCOPY: c_int = 67108864;
pub const MSG_FASTOPEN: c_int = 536870912;
pub const MSG_CMSG_CLOEXEC: c_int = 1073741824;
const enum_unnamed_10 = c_uint;
pub const socklen_t = c_uint;
pub const struct_iovec = extern struct {
    iov_base: ?*anyopaque = @import("std").mem.zeroes(?*anyopaque),
    iov_len: usize = @import("std").mem.zeroes(usize),
};
pub const struct_msghdr = extern struct {
    msg_name: ?*anyopaque = @import("std").mem.zeroes(?*anyopaque),
    msg_namelen: socklen_t = @import("std").mem.zeroes(socklen_t),
    msg_iov: [*c]struct_iovec = @import("std").mem.zeroes([*c]struct_iovec),
    msg_iovlen: usize = @import("std").mem.zeroes(usize),
    msg_control: ?*anyopaque = @import("std").mem.zeroes(?*anyopaque),
    msg_controllen: usize = @import("std").mem.zeroes(usize),
    msg_flags: c_int = @import("std").mem.zeroes(c_int),
};
pub const struct_cmsghdr = extern struct {
    cmsg_len: usize align(8) = @import("std").mem.zeroes(usize),
    cmsg_level: c_int = @import("std").mem.zeroes(c_int),
    cmsg_type: c_int = @import("std").mem.zeroes(c_int),
    pub fn __cmsg_data(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8) {
        const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 16)));
    }
};
pub extern fn __cmsg_nxthdr(__mhdr: [*c]struct_msghdr, __cmsg: [*c]struct_cmsghdr) [*c]struct_cmsghdr;
pub const SCM_RIGHTS: c_int = 1;
pub const SCM_CREDENTIALS: c_int = 2;
pub const SCM_SECURITY: c_int = 3;
pub const SCM_PIDFD: c_int = 4;

pub const struct_sockaddr_l2 = extern struct {
    l2_family: sa_family_t = @import("std").mem.zeroes(sa_family_t),
    l2_psm: c_ushort = @import("std").mem.zeroes(c_ushort),
    l2_bdaddr: bdaddr_t = @import("std").mem.zeroes(bdaddr_t),
    l2_cid: c_ushort = @import("std").mem.zeroes(c_ushort),
    l2_bdaddr_type: u8 = @import("std").mem.zeroes(u8),
};
pub const struct_bt_security = extern struct {
    level: u8 = @import("std").mem.zeroes(u8),
    key_size: u8 = @import("std").mem.zeroes(u8),
};
pub const struct_bt_power = extern struct {
    force_active: u8 = @import("std").mem.zeroes(u8),
};
pub const struct_bt_voice = extern struct {
    setting: u16 = @import("std").mem.zeroes(u16),
};
pub const struct_bt_iso_io_qos = extern struct {
    interval: u32 = @import("std").mem.zeroes(u32),
    latency: u16 = @import("std").mem.zeroes(u16),
    sdu: u16 = @import("std").mem.zeroes(u16),
    phy: u8 = @import("std").mem.zeroes(u8),
    rtn: u8 = @import("std").mem.zeroes(u8),
};
pub const struct_bt_iso_ucast_qos = extern struct {
    cig: u8 = @import("std").mem.zeroes(u8),
    cis: u8 = @import("std").mem.zeroes(u8),
    sca: u8 = @import("std").mem.zeroes(u8),
    packing: u8 = @import("std").mem.zeroes(u8),
    framing: u8 = @import("std").mem.zeroes(u8),
    in: struct_bt_iso_io_qos = @import("std").mem.zeroes(struct_bt_iso_io_qos),
    out: struct_bt_iso_io_qos = @import("std").mem.zeroes(struct_bt_iso_io_qos),
};
pub const struct_bt_iso_bcast_qos = extern struct {
    big: u8 = @import("std").mem.zeroes(u8),
    bis: u8 = @import("std").mem.zeroes(u8),
    sync_factor: u8 = @import("std").mem.zeroes(u8),
    packing: u8 = @import("std").mem.zeroes(u8),
    framing: u8 = @import("std").mem.zeroes(u8),
    in: struct_bt_iso_io_qos = @import("std").mem.zeroes(struct_bt_iso_io_qos),
    out: struct_bt_iso_io_qos = @import("std").mem.zeroes(struct_bt_iso_io_qos),
    encryption: u8 = @import("std").mem.zeroes(u8),
    bcode: [16]u8 = @import("std").mem.zeroes([16]u8),
    options: u8 = @import("std").mem.zeroes(u8),
    skip: u16 = @import("std").mem.zeroes(u16),
    sync_timeout: u16 = @import("std").mem.zeroes(u16),
    sync_cte_type: u8 = @import("std").mem.zeroes(u8),
    mse: u8 = @import("std").mem.zeroes(u8),
    timeout: u16 = @import("std").mem.zeroes(u16),
};
pub const struct_bt_iso_base = extern struct {
    base_len: u8 = @import("std").mem.zeroes(u8),
    base: [248]u8 = @import("std").mem.zeroes([248]u8),
};
const union_unnamed_27 = extern union {
    ucast: struct_bt_iso_ucast_qos,
    bcast: struct_bt_iso_bcast_qos,
};
pub const struct_bt_iso_qos = extern struct {
    unnamed_0: union_unnamed_27 = @import("std").mem.zeroes(union_unnamed_27),
};
pub const struct_codec_caps_28 = extern struct {
    len: u8 align(1) = @import("std").mem.zeroes(u8),
    pub fn data(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8) {
        const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 1)));
    }
};
pub const struct_bt_codec = extern struct {
    id: u8 align(1) = @import("std").mem.zeroes(u8),
    cid: u16 align(1) = @import("std").mem.zeroes(u16),
    vid: u16 align(1) = @import("std").mem.zeroes(u16),
    data_path_id: u8 align(1) = @import("std").mem.zeroes(u8),
    num_caps: u8 align(1) = @import("std").mem.zeroes(u8),
    pub fn caps(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_codec_caps_28) {
        const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_codec_caps_28);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 7)));
    }
};
pub const struct_bt_codecs = extern struct {
    num_codecs: u8 align(1) = @import("std").mem.zeroes(u8),
    pub fn codecs(self: anytype) @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_bt_codec) {
        const Intermediate = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), u8);
        const ReturnType = @import("std").zig.c_translation.FlexibleArrayType(@TypeOf(self), struct_bt_codec);
        return @as(ReturnType, @ptrCast(@alignCast(@as(Intermediate, @ptrCast(self)) + 1)));
    }
};
pub const BT_CONNECTED: c_int = 1;
pub const BT_OPEN: c_int = 2;
pub const BT_BOUND: c_int = 3;
pub const BT_LISTEN: c_int = 4;
pub const BT_CONNECT: c_int = 5;
pub const BT_CONNECT2: c_int = 6;
pub const BT_CONFIG: c_int = 7;
pub const BT_DISCONN: c_int = 8;
pub const BT_CLOSED: c_int = 9;
