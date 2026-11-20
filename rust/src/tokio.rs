//! Authenticated MIST byte sockets for Tokio.

/// A UDP listener for one authenticated MIST socket.
pub type Listener = crate::socket::Listener<runtime::Udp>;
/// A reliable byte socket over one MIST bidirectional stream.
pub type Socket = crate::socket::Socket<runtime::Udp>;

mod runtime {
    use crate::socket::{Driver, Udp as Backend};
    use ::tokio::{net::UdpSocket, time};
    use std::{io, net::SocketAddr, time::Instant};

    pub struct Udp(UdpSocket);

    impl Backend for Udp {
        async fn bind(address: SocketAddr) -> io::Result<Self> {
            UdpSocket::bind(address).await.map(Self)
        }

        async fn connect(&self, address: SocketAddr) -> io::Result<()> {
            self.0.connect(address).await
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            self.0.local_addr()
        }

        fn peer_addr(&self) -> io::Result<SocketAddr> {
            self.0.peer_addr()
        }

        fn try_send(&self, packet: &[u8]) -> io::Result<usize> {
            self.0.try_send(packet)
        }

        async fn send(&self, packet: &[u8]) -> io::Result<usize> {
            self.0.send(packet).await
        }

        async fn recv(&self, packet: &mut [u8]) -> io::Result<usize> {
            self.0.recv(packet).await
        }

        async fn recv_from(&self, packet: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            self.0.recv_from(packet).await
        }

        fn now() -> Instant {
            time::Instant::now().into_std()
        }

        async fn sleep_until(deadline: Instant) {
            time::sleep_until(time::Instant::from_std(deadline)).await;
        }

        fn spawn(driver: Driver<Self>) {
            ::tokio::spawn(driver.run());
        }
    }
}
