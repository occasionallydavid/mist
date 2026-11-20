#![cfg(feature = "tokio")]

use mist::{
    core::public_key,
    tokio::{Listener, Socket},
};
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{net::UdpSocket, sync::Notify, time::timeout};

#[tokio::test]
async fn socket_connect_retransmits_init() {
    timeout(Duration::from_secs(4), async {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let private = [5; 32];
        let peer_key = public_key(&[6; 32]);
        let connect = Socket::connect(peer.local_addr().unwrap(), &private, &peer_key);
        let receive_retries = async {
            let mut first = [0; 1200];
            let (n, source) = peer.recv_from(&mut first).await.unwrap();
            assert_eq!(&first[..6], b"MST1\x01\x01");
            let mut retry = [0; 1200];
            let (retry_len, retry_source) = peer.recv_from(&mut retry).await.unwrap();
            assert_eq!(retry_source, source);
            assert_eq!(&retry[..retry_len], &first[..n]);
        };
        tokio::select! {
            result = connect => {
                assert!(result.is_ok(), "socket connect failed early: {:?}", result.err());
                panic!("socket connected without a responder");
            }
            () = receive_retries => {}
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn byte_socket_server_first_and_half_close() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    timeout(Duration::from_secs(10), async {
        let client_private = [11; 32];
        let server_private = [12; 32];
        let client_public = public_key(&client_private);
        let server_public = public_key(&server_private);
        let allowed = [public_key(&[14; 32]), client_public];
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen_by_policy = seen.clone();
        let denied = Arc::new(Notify::new());
        let denied_by_policy = denied.clone();
        let listener = Listener::bind(
            "127.0.0.1:0".parse().unwrap(),
            &server_private,
            Some(Box::new(move |key| {
                seen_by_policy.lock().unwrap().push(*key);
                let authorized = allowed.contains(key);
                if !authorized {
                    denied_by_policy.notify_one();
                }
                authorized
            })),
        )
        .await
        .unwrap();
        let address = listener.local_addr().unwrap();

        let accept = listener.accept();
        tokio::pin!(accept);
        let unauthorized = Socket::connect(address, &[13; 32], &server_public);
        tokio::select! {
            _ = &mut accept => panic!("listener stopped on an unauthorized INIT"),
            _ = unauthorized => panic!("unauthorized connection completed"),
            () = denied.notified() => {}
        }

        let (client, accepted) = tokio::join!(
            Socket::connect(address, &client_private, &server_public),
            accept,
        );
        let mut client = client.unwrap();
        let (mut server, peer) = accepted.unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            [public_key(&[13; 32]), client_public]
        );
        assert_eq!(client.local_addr(), peer);
        assert_eq!(client.peer_addr(), server.local_addr());

        let sent: Vec<_> = (0..200_000).map(|i| (i % 251) as u8).collect();
        let client = async {
            let mut received = Vec::new();
            client.read_to_end(&mut received).await.unwrap();
            assert_eq!(received, sent);
            client.write_all(b"ack").await.unwrap();
            client.shutdown().await.unwrap();
        };
        let server = async {
            server.write_all(&sent).await.unwrap();
            server.shutdown().await.unwrap();
            let mut reply = Vec::new();
            server.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, b"ack");
        };
        tokio::join!(client, server);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn listener_without_policy_accepts_any_authenticated_key() {
    timeout(Duration::from_secs(5), async {
        let server_private = [21; 32];
        let server_public = public_key(&server_private);
        for client_private in [[22; 32], [23; 32]] {
            let listener = Listener::bind("127.0.0.1:0".parse().unwrap(), &server_private, None)
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let unrelated = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            unrelated.send_to(b"MST1", address).await.unwrap();

            let (client, (_, peer)) = tokio::try_join!(
                Socket::connect(address, &client_private, &server_public),
                listener.accept(),
            )
            .unwrap();
            assert_eq!(client.local_addr(), peer);
        }
    })
    .await
    .unwrap();
}
