use crate::core::Stats;
use std::ffi::{c_int, c_void};

#[repr(C)]
pub(crate) struct Conn {
    _opaque: [u8; 0],
}

#[repr(C)]
pub(crate) struct Cache {
    _opaque: [u8; 0],
}

#[repr(C)]
pub(crate) struct Config {
    pub max_send_buffer: u64,
    pub max_recv_buffer: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
    pub max_streams_bidi: u32,
    pub max_streams_uni: u32,
    pub replay_cache: *mut Cache,
}

#[repr(C)]
pub(crate) struct Event {
    pub kind: c_int,
    pub stream_id: u32,
    pub data: *const u8,
    pub length: usize,
    pub close_code: u16,
    pub remote: c_int,
}

extern "C" {
    pub(crate) fn mist_config_default(config: *mut Config);
    pub(crate) fn mist_public_key(out: *mut u8, private_key: *const u8);
    pub(crate) fn mist_replay_cache_create(capacity: usize) -> *mut Cache;
    pub(crate) fn mist_replay_cache_destroy(cache: *mut Cache);
    pub(crate) fn mist_client_create(
        config: *const Config,
        local: *const u8,
        peer: *const u8,
    ) -> *mut Conn;
    pub(crate) fn mist_server_create(
        config: *const Config,
        local: *const u8,
        peer: *const u8,
    ) -> *mut Conn;
    pub(crate) fn mist_server_create_with_policy(
        config: *const Config,
        local: *const u8,
        authorize: unsafe extern "C" fn(*mut c_void, *const u8) -> c_int,
        context: *mut c_void,
    ) -> *mut Conn;
    pub(crate) fn mist_destroy(conn: *mut Conn);
    pub(crate) fn mist_supply_random(conn: *mut Conn, data: *const u8, len: usize) -> c_int;
    pub(crate) fn mist_input(conn: *mut Conn, data: *const u8, len: usize, now_us: u64) -> c_int;
    pub(crate) fn mist_poll(conn: *mut Conn, now_us: u64) -> c_int;
    pub(crate) fn mist_next_event(conn: *mut Conn, event: *mut Event) -> c_int;
    pub(crate) fn mist_open_stream(conn: *mut Conn, id: *mut u32) -> c_int;
    #[cfg(any(feature = "tokio", all(feature = "toki", target_os = "linux")))]
    pub(crate) fn mist_stream_send_finished(conn: *const Conn, id: u32) -> c_int;
    #[cfg(any(feature = "tokio", all(feature = "toki", target_os = "linux")))]
    pub(crate) fn mist_ack_pending(conn: *const Conn) -> c_int;
    pub(crate) fn mist_stream_write(conn: *mut Conn, id: u32, data: *const u8, len: usize)
        -> usize;
    pub(crate) fn mist_stream_finish(conn: *mut Conn, id: u32) -> c_int;
    pub(crate) fn mist_send_message(conn: *mut Conn, data: *const u8, len: usize) -> c_int;
    pub(crate) fn mist_stream_consume(conn: *mut Conn, id: u32, len: usize) -> c_int;
    pub(crate) fn mist_message_consume(conn: *mut Conn, id: u32) -> c_int;
    pub(crate) fn mist_close(conn: *mut Conn, code: u16) -> c_int;
    pub(crate) fn mist_next_deadline(conn: *const Conn) -> u64;
    pub(crate) fn mist_get_stats(conn: *const Conn, stats: *mut Stats) -> c_int;
}
