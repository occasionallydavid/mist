#![cfg(all(feature = "toki", target_os = "linux"))]

use mist::{
    core::public_key,
    toki::{Listener, Socket},
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[test]
fn toki_socket_echo_and_half_close() {
    // Toki's executor and reactor are single-threaded.
    toki::context::create_executor().block_on(async {
        toki::time::timeout(Duration::from_secs(10), async {
            let server_private = [31; 32];
            let server_public = public_key(&server_private);
            let client_private = [32; 32];
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &server_private, None)
                .await
                .unwrap();
            let addr = listener.local_addr().unwrap();

            let (client, (server, peer)) = tokio::try_join!(
                Socket::connect(addr, &client_private, &server_public),
                listener.accept(),
            )
            .unwrap();
            assert_eq!(client.local_addr(), peer);
            assert_eq!(client.peer_addr(), server.local_addr());

            let (mut client_read, mut client_write) = tokio::io::split(client);
            let (mut server_read, mut server_write) = tokio::io::split(server);
            let sent: Vec<_> = (0..100_000).map(|i| (i % 251) as u8).collect();
            let client_send = async {
                client_write.write_all(&sent).await?;
                client_write.shutdown().await
            };
            let client_read = async {
                let mut echo = Vec::new();
                client_read.read_to_end(&mut echo).await?;
                assert_eq!(echo, sent);
                Ok::<_, std::io::Error>(())
            };
            let server_echo = async {
                assert_eq!(
                    tokio::io::copy(&mut server_read, &mut server_write).await?,
                    sent.len() as u64
                );
                server_write.shutdown().await
            };
            tokio::try_join!(client_send, client_read, server_echo).unwrap();
        })
        .await
        .unwrap();
    });
}
