use mist::core::{public_key, Config, Connection, Error, Event, ReplayCache};

fn relay(from: &mut Connection, to: &mut Connection, now: u64) {
    from.poll(now).unwrap();
    let Some(Event::SendDatagram(packet)) = from.next_event() else {
        panic!("expected a datagram");
    };
    to.input(packet, now).unwrap();
}

#[test]
fn handshake_and_deliver() {
    let client_private = [7; 32];
    let server_private = [8; 32];
    let client_public = public_key(&client_private);
    let server_public = public_key(&server_private);
    let config = Config {
        replay_cache: Some(ReplayCache::new(8).unwrap()),
        ..Config::default()
    };
    let mut client = Connection::client(None, &client_private, &server_public).unwrap();
    let mut server = Connection::server(Some(&config), &server_private, &client_public).unwrap();
    drop(config);

    assert_eq!(client.next_event(), Some(Event::NeedRandom(48)));
    assert_eq!(client.supply_random(&[9; 47]), Err(Error::Invalid));
    client.supply_random(&[9; 48]).unwrap();
    relay(&mut client, &mut server, 0);

    assert_eq!(server.next_event(), Some(Event::NeedRandom(32)));
    server.supply_random(&[10; 32]).unwrap();
    relay(&mut server, &mut client, 1);
    assert_eq!(client.next_event(), Some(Event::Connected(&server_public)));

    relay(&mut client, &mut server, 2);
    assert_eq!(server.next_event(), Some(Event::Connected(&client_public)));

    let stream = client.open_stream().unwrap();
    assert_eq!(client.stream_write(stream, b"stream bytes"), 12);
    client.stream_finish(stream).unwrap();
    client.send_message(b"message").unwrap();

    let (mut opened, mut read, mut finished, mut message) = (false, false, false, false);
    for now in [100_000, 200_000, 300_000, 400_000] {
        client.poll(now).unwrap();
        if let Some(Event::SendDatagram(packet)) = client.next_event() {
            server.input(packet, now).unwrap();
        }
        while let Some(event) = server.next_event() {
            match event {
                Event::StreamOpen(id) if id == stream => opened = true,
                Event::StreamReadable(id, bytes) if id == stream => {
                    assert_eq!(bytes, b"stream bytes");
                    let len = bytes.len();
                    server.stream_consume(id, len).unwrap();
                    read = true;
                }
                Event::StreamFin(id) if id == stream => finished = true,
                Event::Message(id, bytes) => {
                    assert_eq!(bytes, b"message");
                    server.message_consume(id).unwrap();
                    message = true;
                }
                event => panic!("unexpected event {event:?}"),
            }
        }
    }
    assert!(opened && read && finished && message);
}
