use mist::tokio::Socket;
use std::io;
use tokio::io::{self as tokio_io, AsyncReadExt, AsyncWriteExt};

const CLIENT_PRIVATE_KEY: [u8; 32] = [1; 32];
const SERVER_PUBLIC_KEY: [u8; 32] = [
    0xce, 0x8d, 0x3a, 0xd1, 0xcc, 0xb6, 0x33, 0xec, 0x7b, 0x70, 0xc1, 0x78, 0x14, 0xa5, 0xc7, 0x6e,
    0xcd, 0x02, 0x96, 0x85, 0x05, 0x0d, 0x34, 0x47, 0x45, 0xba, 0x05, 0x87, 0x0e, 0x58, 0x7d, 0x59,
];

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let message = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "hello MIST".into());
    let server = "127.0.0.1:43000".parse().unwrap();
    let socket = Socket::connect(server, &CLIENT_PRIVATE_KEY, &SERVER_PUBLIC_KEY).await?;
    let (mut reader, mut writer) = tokio_io::split(socket);
    let mut echo = Vec::new();

    tokio::try_join!(
        async {
            writer.write_all(message.as_bytes()).await?;
            writer.shutdown().await
        },
        reader.read_to_end(&mut echo),
    )?;

    if echo != message.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected echo",
        ));
    }

    println!("echo: {message}");
    Ok(())
}
