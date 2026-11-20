//! Byte-socket implementation shared by the runtime adapters.

use crate::core::{self, MAX_DATAGRAM};
use ::tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::oneshot,
};
use std::{
    future::{pending, Future},
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex, OnceLock},
    task::{Context, Poll},
    time::{Duration, Instant},
};

// Internal backends choose whether their futures and sockets are Send.
#[allow(async_fn_in_trait)]
pub trait Udp: Sized + Unpin + 'static {
    async fn bind(address: SocketAddr) -> io::Result<Self>;
    async fn connect(&self, address: SocketAddr) -> io::Result<()>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn try_send(&self, packet: &[u8]) -> io::Result<usize>;
    async fn send(&self, packet: &[u8]) -> io::Result<usize>;
    async fn recv(&self, packet: &mut [u8]) -> io::Result<usize>;
    async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr)>;
    fn now() -> Instant;
    async fn sleep_until(deadline: Instant);
    fn spawn(driver: Driver<Self>);
}

/// A UDP listener for one authenticated MIST socket.
pub struct Listener<U: Udp> {
    socket: U,
    transport: core::Connection,
}

impl<U: Udp> Listener<U> {
    /// Bind a listener with an optional policy for authenticated initiator keys.
    /// Pass `None` to accept any authenticated key.
    pub async fn bind(
        address: SocketAddr,
        private: &[u8; 32],
        authorize: Option<core::KeyPolicy>,
    ) -> io::Result<Self> {
        let socket = U::bind(address).await?;
        let transport = core::Connection::server_with_policy(None, private, authorize)
            .ok_or_else(|| io::Error::other("create MIST responder"))?;
        Ok(Self { socket, transport })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Accept one connection. The bound UDP socket becomes its dedicated path.
    pub async fn accept(self) -> io::Result<(Socket<U>, SocketAddr)> {
        let Self {
            socket,
            mut transport,
        } = self;
        let mut packet = [0; MAX_DATAGRAM + 1];
        let peer = loop {
            let (size, source) = socket.recv_from(&mut packet).await?;
            transport
                .input(&packet[..size], now_us::<U>())
                .map_err(transport_error)?;
            // The core asks for entropy only after authenticating the INIT.
            if let Some(core::Event::NeedRandom(length)) = transport.next_event() {
                supply_random(&mut transport, length)?;
                break source;
            }
        };
        socket.connect(peer).await?;
        let mut connection = Connection::new(socket, transport);
        wait_connected(&mut connection).await?;
        match connection.next_event().await? {
            Some(Event::StreamOpen(0)) => Ok((Socket::start(connection, 0)?, peer)),
            Some(Event::Closed(code)) => Err(closed(code)),
            _ => Err(unexpected()),
        }
    }
}

type Failure = Arc<Mutex<Option<io::Error>>>;

/// A reliable byte socket over one MIST bidirectional stream.
pub struct Socket<U: Udp> {
    pipe: DuplexStream,
    _stop: oneshot::Sender<()>,
    _runtime: PhantomData<U>,
    shutdown: Option<oneshot::Receiver<()>>,
    failure: Failure,
    local: SocketAddr,
    peer: SocketAddr,
}

impl<U: Udp> Socket<U> {
    pub async fn connect(
        address: SocketAddr,
        private: &[u8; 32],
        peer: &[u8; 32],
    ) -> io::Result<Self> {
        let bind = if address.is_ipv4() {
            SocketAddr::from(([0; 4], 0))
        } else {
            SocketAddr::from(([0; 8], 0))
        };
        let socket = U::bind(bind).await?;
        socket.connect(address).await?;
        let transport = core::Connection::client(None, private, peer)
            .ok_or_else(|| io::Error::other("create MIST initiator"))?;
        let mut connection = Connection::new(socket, transport);
        wait_connected(&mut connection).await?;
        let core = &mut connection.transport;
        let id = core.open_stream().map_err(transport_error)?;
        Self::start(connection, id)
    }

    fn start(connection: Connection<U>, id: u32) -> io::Result<Self> {
        let local = connection.socket.local_addr()?;
        let peer = connection.socket.peer_addr()?;
        let (pipe, worker) = io::duplex(16 * 1024);
        let (send, shutdown) = oneshot::channel();
        let (stop, cancelled) = oneshot::channel();
        let failure = Failure::default();
        U::spawn(Driver {
            connection,
            id,
            worker,
            send,
            cancelled,
            failure: failure.clone(),
        });
        Ok(Self {
            pipe,
            _stop: stop,
            _runtime: PhantomData,
            shutdown: Some(shutdown),
            failure,
            local,
            peer,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    fn failed(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .unwrap()
            .as_ref()
            .map(|error| io::Error::new(error.kind(), error.to_string()))
    }
}

impl<U: Udp> AsyncRead for Socket<U> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let previous = buf.filled().len();
        let remaining = buf.remaining();
        match Pin::new(&mut self.pipe).poll_read(cx, buf) {
            Poll::Ready(Ok(())) if remaining != 0 && buf.filled().len() == previous => {
                Poll::Ready(self.failed().map_or(Ok(()), Err))
            }
            result => result,
        }
    }
}

impl<U: Udp> AsyncWrite for Socket<U> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.pipe).poll_write(cx, buf) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.failed().unwrap_or(error))),
            result => result,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.pipe).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        std::task::ready!(Pin::new(&mut self.pipe).poll_shutdown(cx))?;
        let Some(shutdown) = &mut self.shutdown else {
            return Poll::Ready(Ok(()));
        };
        match std::task::ready!(Pin::new(shutdown).poll(cx)) {
            Ok(()) => self.shutdown = None,
            Err(_) => {
                return Poll::Ready(Err(self
                    .failed()
                    .unwrap_or_else(|| io::ErrorKind::BrokenPipe.into())))
            }
        }
        Poll::Ready(Ok(()))
    }
}

async fn wait_connected<U: Udp>(connection: &mut Connection<U>) -> io::Result<()> {
    match connection.next_event().await? {
        Some(Event::Connected) => Ok(()),
        Some(Event::Closed(code)) => Err(closed(code)),
        _ => Err(unexpected()),
    }
}

pub struct Driver<U: Udp> {
    connection: Connection<U>,
    id: u32,
    worker: DuplexStream,
    send: oneshot::Sender<()>,
    cancelled: oneshot::Receiver<()>,
    failure: Failure,
}

impl<U: Udp> Driver<U> {
    pub async fn run(self) {
        let Self {
            connection,
            id,
            mut worker,
            send,
            cancelled,
            failure,
        } = self;
        let mut send = Some(send);
        ::tokio::select! {
            biased;
            _ = cancelled => {}
            result = drive(connection, id, &mut worker, &mut send) => {
                if let Err(error) = result {
                    *failure.lock().unwrap() = Some(error);
                }
            }
        }
    }
}

async fn drive<U: Udp>(
    mut connection: Connection<U>,
    id: u32,
    pipe: &mut DuplexStream,
    shutdown: &mut Option<oneshot::Sender<()>>,
) -> io::Result<()> {
    let (mut source, mut sink) = io::split(pipe);
    let mut output = [0; 4096];
    let mut queued = 0..0;
    let mut input: Option<(Vec<u8>, usize)> = None;
    let mut source_eof = false;
    let mut fin_sent = false;
    let mut fin_received = false;
    let mut sink_eof = false;

    loop {
        let core = &mut connection.transport;
        if !queued.is_empty() {
            queued.start += core.stream_write(id, &output[queued.clone()]);
        }
        if source_eof && !fin_sent && queued.is_empty() {
            match core.stream_finish(id) {
                Ok(()) => fin_sent = true,
                Err(core::Error::Again) => {}
                Err(error) => return Err(transport_error(error)),
            }
        }
        if fin_sent && shutdown.is_some() && core.stream_send_finished(id) {
            let _ = shutdown.take().unwrap().send(());
        }
        // Keep answering retransmissions while the application owns the socket.
        let finished = sink_eof && shutdown.is_none();
        let wait_shutdown = fin_sent && shutdown.is_some();
        let wait_eof = fin_received && !sink_eof && input.is_none();
        ::tokio::select! {
            length = source.read(&mut output), if !source_eof && queued.is_empty() => {
                let length = length?;
                queued = 0..length;
                source_eof = length == 0;
            }
            written = async {
                let (bytes, offset) = input.as_ref().unwrap();
                sink.write(&bytes[*offset..]).await
            }, if input.is_some() => {
                let (bytes, offset) = input.as_mut().unwrap();
                let written = written?;
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                *offset += written;
                if *offset == bytes.len() {
                    connection.transport.stream_consume(id, bytes.len()).map_err(transport_error)?;
                    input = None;
                }
            }
            event = connection.drive_until(|core| {
                (wait_shutdown && core.stream_send_finished(id)) || (wait_eof && !core.ack_pending())
            }) => match event? {
                Some(Event::StreamReadable(stream, bytes)) if stream == id => input = Some((bytes, 0)),
                Some(Event::StreamFin(stream)) if stream == id => fin_received = true,
                Some(Event::Writable) => {}
                Some(Event::Closed(_)) if finished => return Ok(()),
                Some(Event::Closed(code)) => return Err(closed(code)),
                Some(_) => return Err(unexpected()),
                None => {
                    if wait_eof && !connection.transport.ack_pending() {
                        sink.shutdown().await?;
                        sink_eof = true;
                    }
                }
            }
        }
    }
}

fn closed(code: u16) -> io::Error {
    let kind = if code == 5 {
        io::ErrorKind::TimedOut
    } else {
        io::ErrorKind::ConnectionReset
    };
    io::Error::new(kind, format!("MIST connection closed ({code})"))
}

fn unexpected() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "unexpected event on MIST byte socket",
    )
}

enum Event {
    Connected,
    StreamOpen(u32),
    StreamReadable(u32, Vec<u8>),
    StreamFin(u32),
    Writable,
    Closed(u16),
}

struct Connection<U: Udp> {
    socket: U,
    transport: core::Connection,
    outgoing: Option<Vec<u8>>,
    closed: bool,
}

impl<U: Udp> Connection<U> {
    fn new(socket: U, transport: core::Connection) -> Self {
        Self {
            socket,
            transport,
            outgoing: None,
            closed: false,
        }
    }

    async fn next_event(&mut self) -> io::Result<Option<Event>> {
        self.drive_until(|_| false).await
    }

    async fn drive_until(
        &mut self,
        ready: impl Fn(&core::Connection) -> bool,
    ) -> io::Result<Option<Event>> {
        if self.closed {
            return Ok(None);
        }
        let epoch = epoch::<U>();

        // An extra byte distinguishes a maximum-sized datagram from a
        // truncated oversize datagram.
        let mut input = [0; MAX_DATAGRAM + 1];
        loop {
            if let Some(packet) = &self.outgoing {
                check_send(self.socket.send(packet).await?, packet.len())?;
                self.outgoing = None;
            }

            let now = now_us::<U>();
            if self.transport.next_deadline().is_some_and(|at| at <= now) {
                self.transport.poll(now).map_err(transport_error)?;
            }

            if let Some(event) = self.transport.next_event() {
                let event = match event {
                    core::Event::SendDatagram(packet) => {
                        match self.socket.try_send(packet) {
                            Ok(sent) => check_send(sent, packet.len())?,
                            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                self.outgoing = Some(packet.to_vec());
                            }
                            Err(error) => return Err(error),
                        }
                        continue;
                    }
                    core::Event::NeedRandom(length) => {
                        supply_random(&mut self.transport, length)?;
                        continue;
                    }
                    core::Event::Connected(_) => Event::Connected,
                    core::Event::StreamOpen(id) => Event::StreamOpen(id),
                    core::Event::StreamReadable(id, bytes) => {
                        Event::StreamReadable(id, bytes.to_vec())
                    }
                    core::Event::StreamFin(id) => Event::StreamFin(id),
                    core::Event::Message(..) => return Err(unexpected()),
                    core::Event::Writable => Event::Writable,
                    core::Event::ReconnectRequired => continue,
                    core::Event::Closed { code, .. } => {
                        self.closed = true;
                        Event::Closed(code)
                    }
                };
                return Ok(Some(event));
            }

            if ready(&self.transport) {
                return Ok(None);
            }
            let deadline = self.transport.next_deadline();
            ::tokio::select! {
                length = self.socket.recv(&mut input) => {
                    self.transport.input(&input[..length?], now_us::<U>()).map_err(transport_error)?;
                }
                () = async {
                    match deadline {
                        Some(at) => U::sleep_until(epoch + Duration::from_micros(at)).await,
                        None => pending().await,
                    }
                } => {}
            }
        }
    }
}

// Shared replay caches require one clock domain across responder slots.
fn epoch<U: Udp>() -> Instant {
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    *EPOCH.get_or_init(U::now)
}

fn now_us<U: Udp>() -> u64 {
    U::now().saturating_duration_since(epoch::<U>()).as_micros() as u64
}

fn check_send(sent: usize, expected: usize) -> io::Result<()> {
    if sent == expected {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::WriteZero, "short UDP send"))
    }
}

fn transport_error(error: core::Error) -> io::Error {
    io::Error::other(format!("MIST transport error {error:?}"))
}

fn supply_random(transport: &mut core::Connection, length: usize) -> io::Result<()> {
    let mut bytes = [0; 48];
    let bytes = &mut bytes[..length];
    getrandom::fill(bytes).map_err(io::Error::other)?;
    transport.supply_random(bytes).map_err(transport_error)
}
