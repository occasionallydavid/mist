//! Authenticated MIST byte sockets for the single-threaded Toki runtime.

/// A UDP listener for one authenticated MIST socket.
pub type Listener = crate::socket::Listener<runtime::Udp>;
/// A reliable byte socket over one MIST bidirectional stream.
pub type Socket = crate::socket::Socket<runtime::Udp>;

mod runtime {
    use crate::socket::{Driver, Udp as Backend};
    use ::toki::{context, Interest, RegistrationHandle};
    use std::{
        future::poll_fn,
        io,
        net::{SocketAddr, UdpSocket},
        os::fd::AsRawFd,
        task::Poll,
        time::Instant,
    };

    pub struct Udp {
        // Deregister before closing the file descriptor.
        registration: RegistrationHandle,
        socket: UdpSocket,
    }

    impl Udp {
        async fn receive<T>(&self, mut read: impl FnMut() -> io::Result<T>) -> io::Result<T> {
            poll_fn(|cx| {
                if self.registration.is_read_ready() {
                    match read() {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            self.registration.clear_read_ready();
                        }
                        result => return Poll::Ready(result),
                    }
                }
                self.registration.register_read_waker(cx.waker());
                Poll::Pending
            })
            .await
        }
    }

    // Toki's UDP wrapper provides receive-only I/O. Use its reactor with a
    // standard nonblocking socket to retain datagram addresses and send packets.
    impl Backend for Udp {
        async fn bind(address: SocketAddr) -> io::Result<Self> {
            let reactor =
                context::reactor().ok_or_else(|| io::Error::other("Toki executor is required"))?;
            let socket = UdpSocket::bind(address)?;
            socket.set_nonblocking(true)?;
            let registration = reactor.register(socket.as_raw_fd(), Interest::ReadWrite)?;
            Ok(Self {
                registration,
                socket,
            })
        }

        async fn connect(&self, address: SocketAddr) -> io::Result<()> {
            self.socket.connect(address)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.socket.local_addr()
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.socket.peer_addr()
        }

        fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
            self.socket.send(packet)
        }

        async fn send(&self, packet: &[u8]) -> io::Result<usize> {
            poll_fn(|cx| {
                if self.registration.is_write_ready() {
                    match self.try_send(packet) {
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            self.registration.clear_write_ready();
                        }
                        result => return Poll::Ready(result),
                    }
                }
                self.registration.register_write_waker(cx.waker());
                Poll::Pending
            })
            .await
        }

        async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
            self.receive(|| self.socket.recv(packet)).await
        }

        async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.receive(|| self.socket.recv_from(packet)).await
        }

        fn now() -> Instant {
            Instant::now()
        }

        async fn sleep_until(deadline: Instant) {
            poll_fn(|cx| {
                if Instant::now() >= deadline {
                    Poll::Ready(())
                } else {
                    // Toki drives timers in its busy-poll executor. Keep the
                    // transport deadline on the same monotonic clock as input.
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            })
            .await
        }

        fn spawn(driver: Driver<Self>) {
            ::toki::spawn_local(driver.run());
        }
    }
}
