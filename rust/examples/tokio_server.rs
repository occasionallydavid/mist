use mist::tokio::Listener;
use std::io;
use tokio::io::{self as tokio_io, AsyncWriteExt};

const SERVER_PRIVATE_KEY: [u8; 32] = [2; 32];
const CLIENT_PUBLIC_KEY: [u8; 32] = [
    0xa4, 0xe0, 0x92, 0x92, 0xb6, 0x51, 0xc2, 0x78, 0xb9, 0x77, 0x2c, 0x56, 0x9f, 0x5f, 0xa9, 0xbb,
    0x13, 0xd9, 0x06, 0xb4, 0x6a, 0xb6, 0x8c, 0x9d, 0xf9, 0xdc, 0x2b, 0x44, 0x09, 0xf8, 0xa2, 0x09,
];

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let address = "127.0.0.1:43000".parse().unwrap();
    let listener = Listener::bind(
        address,
        &SERVER_PRIVATE_KEY,
        Some(Box::new(|key| key == &CLIENT_PUBLIC_KEY)),
    )
    .await?;
    println!("waiting on {}", listener.local_addr()?);

    let (socket, peer) = listener.accept().await?;
    println!("authenticated {peer}");
    let (mut reader, mut writer) = tokio_io::split(socket);
    let echoed = tokio_io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await?;
    println!("echoed {echoed} bytes");
    Ok(())
}
