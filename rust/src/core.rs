//! A thin, sans-I/O Rust binding for MIST. Supply datagrams, monotonic
//! microseconds, and cryptographically secure randomness from your application.

use crate::ffi;

use std::{
    ffi::{c_int, c_void},
    mem::MaybeUninit,
    panic::{catch_unwind, AssertUnwindSafe},
    ptr::{self, NonNull},
    slice,
    sync::{Arc, Mutex},
};

pub const MAX_DATAGRAM: usize = 1200;
pub const MAX_MESSAGE: usize = 1024;

pub fn public_key(private_key: &[u8; 32]) -> [u8; 32] {
    let mut key = [0; 32];
    unsafe { ffi::mist_public_key(key.as_mut_ptr(), private_key.as_ptr()) };
    key
}

/// Share among responder slots for one identity in the same clock domain.
/// Clone the handle to share the cache. Connections keep their own handle.
#[derive(Clone)]
pub struct ReplayCache(Arc<Mutex<Cache>>);

struct Cache {
    ptr: NonNull<ffi::Cache>,
}

// The cache is heap-owned by C. Access to its contents is serialized.
unsafe impl Send for Cache {}

impl ReplayCache {
    /// The C core accepts capacities from 1 through 4096.
    pub fn new(capacity: usize) -> Option<Self> {
        let ptr = NonNull::new(unsafe { ffi::mist_replay_cache_create(capacity) })?;
        Some(Self(Arc::new(Mutex::new(Cache { ptr }))))
    }
}

impl Drop for Cache {
    fn drop(&mut self) {
        unsafe { ffi::mist_replay_cache_destroy(self.ptr.as_ptr()) };
    }
}

#[derive(Clone)]
pub struct Config {
    pub max_send_buffer: u64,
    pub max_recv_buffer: u64,
    pub initial_max_data: u64,
    pub initial_max_stream_data: u64,
    pub max_streams_bidi: u32,
    pub max_streams_uni: u32,
    pub replay_cache: Option<ReplayCache>,
}

impl Default for Config {
    fn default() -> Self {
        let mut raw = MaybeUninit::uninit();
        unsafe { ffi::mist_config_default(raw.as_mut_ptr()) };
        let raw = unsafe { raw.assume_init() };
        Self {
            max_send_buffer: raw.max_send_buffer,
            max_recv_buffer: raw.max_recv_buffer,
            initial_max_data: raw.initial_max_data,
            initial_max_stream_data: raw.initial_max_stream_data,
            max_streams_bidi: raw.max_streams_bidi,
            max_streams_uni: raw.max_streams_uni,
            replay_cache: None,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub next_packet_number: u64,
    pub latest_rtt_us: u64,
    pub min_rtt_us: u64,
    pub smoothed_rtt_us: u64,
    pub rtt_variance_us: u64,
    pub cwnd: u64,
    pub ssthresh: u64,
    pub bytes_in_flight: u64,
    pub packets_lost: u64,
    pub probe_timeouts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Again,
    Invalid,
    NoMemory,
}

fn status(code: std::ffi::c_int) -> Result<(), Error> {
    match code {
        0 => Ok(()),
        1 => Err(Error::Again),
        -1 => Err(Error::Invalid),
        -2 => Err(Error::NoMemory),
        _ => unreachable!("unexpected MIST status {code}"),
    }
}

/// Payloads borrow the connection until the application finishes using them.
/// Consume stream bytes and messages separately to return receive credit.
#[derive(Debug, Eq, PartialEq)]
pub enum Event<'a> {
    NeedRandom(usize),
    SendDatagram(&'a [u8]),
    Connected(&'a [u8; 32]),
    StreamOpen(u32),
    StreamReadable(u32, &'a [u8]),
    StreamFin(u32),
    Message(u32, &'a [u8]),
    Writable,
    ReconnectRequired,
    Closed { code: u16, remote: bool },
}

/// Authorize an initiator after its X25519 identity has been authenticated.
pub type KeyPolicy = Box<dyn Fn(&[u8; 32]) -> bool + Send>;

// The outer allocation gives C a thin pointer that remains stable as the
// connection moves. Rust keeps ownership until after mist_destroy.
struct PolicyContext(*mut KeyPolicy);

impl Drop for PolicyContext {
    fn drop(&mut self) {
        unsafe { drop(Box::from_raw(self.0)) };
    }
}

unsafe extern "C" fn authorize_key(context: *mut c_void, key: *const u8) -> c_int {
    if context.is_null() {
        return 1;
    }
    // C borrows the boxed policy from Connection and the key for this call.
    let policy = unsafe { &*context.cast::<KeyPolicy>() };
    let key = unsafe { &*key.cast::<[u8; 32]>() };
    c_int::from(catch_unwind(AssertUnwindSafe(|| policy(key))).unwrap_or(false))
}

pub struct Connection {
    ptr: NonNull<ffi::Conn>,
    _cache: Option<ReplayCache>,
    _policy: Option<PolicyContext>,
}

// Each connection is exclusively owned. Only the replay cache can be shared,
// and calls that access its contents hold its lock.
unsafe impl Send for Connection {}

impl Connection {
    /// Create an initiator with the pinned responder public key.
    pub fn client(config: Option<&Config>, local: &[u8; 32], peer: &[u8; 32]) -> Option<Self> {
        Self::create(config, local, |raw, local| unsafe {
            ffi::mist_client_create(raw, local, peer.as_ptr())
        })
    }

    /// Create one responder slot for an allowed initiator public key.
    pub fn server(config: Option<&Config>, local: &[u8; 32], peer: &[u8; 32]) -> Option<Self> {
        Self::create(config, local, |raw, local| unsafe {
            ffi::mist_server_create(raw, local, peer.as_ptr())
        })
    }

    /// Use a policy to authorize authenticated initiators, or pass `None`
    /// to accept all authenticated keys. A policy must avoid driving another
    /// connection that shares this connection's replay cache.
    pub fn server_with_policy(
        config: Option<&Config>,
        local: &[u8; 32],
        policy: Option<KeyPolicy>,
    ) -> Option<Self> {
        let policy = policy.map(|policy| PolicyContext(Box::into_raw(Box::new(policy))));
        let context = policy.as_ref().map_or(ptr::null_mut(), |p| p.0.cast());
        let mut conn = Self::create(config, local, |raw, local| unsafe {
            ffi::mist_server_create_with_policy(raw, local, authorize_key, context)
        })?;
        conn._policy = policy;
        Some(conn)
    }

    fn create(
        config: Option<&Config>,
        local: &[u8; 32],
        create: impl FnOnce(*const ffi::Config, *const u8) -> *mut ffi::Conn,
    ) -> Option<Self> {
        let cache = config.and_then(|config| config.replay_cache.clone());
        let raw = config.map(|c| ffi::Config {
            max_send_buffer: c.max_send_buffer,
            max_recv_buffer: c.max_recv_buffer,
            initial_max_data: c.initial_max_data,
            initial_max_stream_data: c.initial_max_stream_data,
            max_streams_bidi: c.max_streams_bidi,
            max_streams_uni: c.max_streams_uni,
            replay_cache: cache
                .as_ref()
                .map_or(ptr::null_mut(), |c| c.0.lock().unwrap().ptr.as_ptr()),
        });
        let raw = raw.as_ref().map_or(ptr::null(), ptr::from_ref);
        // The core copies both keys and the config. The cache stays alive
        // until after Drop tears down the core connection.
        let ptr = NonNull::new(create(raw, local.as_ptr()))?;
        Some(Self {
            ptr,
            _cache: cache,
            _policy: None,
        })
    }

    pub fn supply_random(&mut self, bytes: &[u8]) -> Result<(), Error> {
        status(unsafe { ffi::mist_supply_random(self.ptr.as_ptr(), bytes.as_ptr(), bytes.len()) })
    }

    pub fn input(&mut self, datagram: &[u8], now_us: u64) -> Result<(), Error> {
        let _cache = self._cache.as_ref().map(|cache| cache.0.lock().unwrap());
        status(unsafe {
            ffi::mist_input(self.ptr.as_ptr(), datagram.as_ptr(), datagram.len(), now_us)
        })
    }

    pub fn poll(&mut self, now_us: u64) -> Result<(), Error> {
        status(unsafe { ffi::mist_poll(self.ptr.as_ptr(), now_us) })
    }

    /// Drain events after input or polling. Send datagrams promptly.
    pub fn next_event(&mut self) -> Option<Event<'_>> {
        let mut raw = MaybeUninit::uninit();
        match unsafe { ffi::mist_next_event(self.ptr.as_ptr(), raw.as_mut_ptr()) } {
            0 => return None,
            1 => {}
            code => unreachable!("unexpected MIST event status {code}"),
        }
        let raw = unsafe { raw.assume_init() };
        let bytes = || {
            if raw.length == 0 {
                &[]
            } else {
                // The core owns the payload and keeps it valid while the
                // event's borrow prevents mutations or destruction.
                unsafe { slice::from_raw_parts(raw.data, raw.length) }
            }
        };
        Some(match raw.kind {
            0 => Event::NeedRandom(raw.length),
            1 => Event::SendDatagram(bytes()),
            2 => Event::Connected(bytes().try_into().expect("MIST peer key length")),
            3 => Event::StreamOpen(raw.stream_id),
            4 => Event::StreamReadable(raw.stream_id, bytes()),
            5 => Event::StreamFin(raw.stream_id),
            6 => Event::Message(raw.stream_id, bytes()),
            7 => Event::Writable,
            8 => Event::ReconnectRequired,
            9 => Event::Closed {
                code: raw.close_code,
                remote: raw.remote != 0,
            },
            kind => unreachable!("unexpected MIST event type {kind}"),
        })
    }

    pub fn open_stream(&mut self) -> Result<u32, Error> {
        let mut id = 0;
        status(unsafe { ffi::mist_open_stream(self.ptr.as_ptr(), &mut id) })?;
        Ok(id)
    }

    #[cfg(any(feature = "tokio", all(feature = "toki", target_os = "linux")))]
    pub(crate) fn stream_send_finished(&self, id: u32) -> bool {
        unsafe { ffi::mist_stream_send_finished(self.ptr.as_ptr(), id) != 0 }
    }

    #[cfg(any(feature = "tokio", all(feature = "toki", target_os = "linux")))]
    pub(crate) fn ack_pending(&self) -> bool {
        unsafe { ffi::mist_ack_pending(self.ptr.as_ptr()) != 0 }
    }

    pub fn stream_write(&mut self, id: u32, data: &[u8]) -> usize {
        unsafe { ffi::mist_stream_write(self.ptr.as_ptr(), id, data.as_ptr(), data.len()) }
    }

    pub fn stream_finish(&mut self, id: u32) -> Result<(), Error> {
        status(unsafe { ffi::mist_stream_finish(self.ptr.as_ptr(), id) })
    }

    pub fn send_message(&mut self, data: &[u8]) -> Result<(), Error> {
        status(unsafe { ffi::mist_send_message(self.ptr.as_ptr(), data.as_ptr(), data.len()) })
    }

    pub fn stream_consume(&mut self, id: u32, len: usize) -> Result<(), Error> {
        status(unsafe { ffi::mist_stream_consume(self.ptr.as_ptr(), id, len) })
    }

    pub fn message_consume(&mut self, id: u32) -> Result<(), Error> {
        status(unsafe { ffi::mist_message_consume(self.ptr.as_ptr(), id) })
    }

    pub fn close(&mut self, code: u16) -> Result<(), Error> {
        status(unsafe { ffi::mist_close(self.ptr.as_ptr(), code) })
    }

    pub fn next_deadline(&self) -> Option<u64> {
        match unsafe { ffi::mist_next_deadline(self.ptr.as_ptr()) } {
            u64::MAX => None,
            now => Some(now),
        }
    }

    pub fn stats(&self) -> Stats {
        let mut stats = Stats::default();
        let result = unsafe { ffi::mist_get_stats(self.ptr.as_ptr(), &mut stats) };
        assert_eq!(result, 0);
        stats
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { ffi::mist_destroy(self.ptr.as_ptr()) };
    }
}
