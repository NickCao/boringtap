use argh::FromArgs;
use boringtap::noise::errors::WireGuardError;
use boringtap::noise::handshake::parse_handshake_anon;
use boringtap::noise::{rate_limiter::RateLimiter, Tunn};
use boringtap::noise::{Packet, TunnResult};
use boringtap::EUI48;
use etherparse::SlicedPacket;
use futures::stream::TryStreamExt;
use multi_map::MultiMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::spawn;
use tokio::sync::Mutex;
use tokio::{io::AsyncReadExt, time::interval};
use x25519_dalek::{PublicKey, StaticSecret};

const BUFFER_SIZE: usize = (1 << 16) - 1;
const HANDSHAKE_RATE_LIMIT: u64 = 100;
const KEYPAIRS: [&str; 3] = [
    "qGn4gHhUgf/apQ/JPw7+RCWe0Gk/mqvSxLy0r5uGcmc=",
    "4PCwNBhWgQDbRbL6QCswQhrbs84WtjRPxp/l/lgIPVo=",
    "OF1Jd0gX5xPqcEDxfcSzATe1tFMnJXNl/QHt1v/PG00=",
];

#[derive(FromArgs)]
/// boringtap
struct Args {
    /// node index
    #[argh(option, short = 'i')]
    index: usize,
}

struct Peer {
    tunnel: Tunn,
    endpoint: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = argh::from_env();
    let sock = Arc::new(
        UdpSocket::bind(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(127, 0, 0, 1),
            3000 + args.index as u16,
        )))
        .await?,
    );

    let keypairs = KEYPAIRS.map(|sk| {
        let sk = base64::decode(sk).unwrap();
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&sk);
        let sk = StaticSecret::from(buf);
        let pk = PublicKey::from(&sk);
        (sk, pk)
    });

    let limiter = Arc::new(RateLimiter::new(
        &keypairs[args.index].1,
        HANDSHAKE_RATE_LIMIT,
    ));

    let limiter_reset = limiter.clone();
    let a = spawn(async move {
        let mut timer = interval(Duration::from_secs(1));
        loop {
            timer.tick().await;
            limiter_reset.reset_count();
        }
    });

    let mut peer_map = MultiMap::new();
    for (index, peer) in keypairs.iter().enumerate() {
        if index != args.index {
            let tunnel = Tunn::new(
                keypairs[args.index].0.clone(),
                peer.1,
                None,
                None,
                index as u32,
                limiter.clone(),
            )
            .unwrap();
            peer_map.insert(
                peer.1.into(),
                index as u32,
                Mutex::new(Peer {
                    tunnel,
                    endpoint: SocketAddr::V4(SocketAddrV4::new(
                        Ipv4Addr::new(127, 0, 0, 1),
                        3000 + index as u16,
                    )),
                }),
            );
        }
    }
    let peer_map: Arc<MultiMap<EUI48, u32, Mutex<Peer>>> = Arc::new(peer_map);

    let tap_name = format!("boringtap{}", args.index);
    let tap = tokio_tun::TunBuilder::new()
        .name(&tap_name)
        .tap(true)
        .packet_info(false)
        .try_build()?;

    let (conn, handle, _) = rtnetlink::new_connection().unwrap();
    spawn(conn);

    let mut link = handle.link().get().match_name(tap_name).execute();
    let link = if let Some(link) = link.try_next().await? {
        let eui: EUI48 = keypairs[args.index].1.into();
        handle
            .link()
            .set(link.header.index)
            .address(eui.0.to_vec())
            .up()
            .execute()
            .await
            .unwrap();
        link.header.index
    } else {
        unreachable!()
    };

    for (addr, (_, _)) in peer_map.iter() {
        handle
            .neighbours()
            .add(link, addr.into())
            .link_local_address(&addr.0)
            .execute()
            .await
            .unwrap();
    }

    let (mut reader, mut writer) = tokio::io::split(tap);

    let sock1 = sock.clone();
    let peer_map1 = peer_map.clone();
    let b = spawn(async move {
        let mut timer = interval(Duration::from_millis(250));
        let mut dst = [0u8; BUFFER_SIZE];
        loop {
            timer.tick().await;
            for (_, (_, peer)) in peer_map1.iter() {
                let mut peer = peer.lock().await;
                match peer.tunnel.update_timers(&mut dst) {
                    TunnResult::Done => (),
                    TunnResult::Err(WireGuardError::ConnectionExpired) => (),
                    TunnResult::Err(err) => {
                        tracing::error!(message = "error in update timers", error = ?err)
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        sock1.send_to(packet, peer.endpoint).await.unwrap();
                    }
                    _ => unreachable!(),
                };
            }
        }
    });

    let sock2 = sock.clone();
    let peer_map2 = peer_map.clone();
    let c = spawn(async move {
        let mut src = [0u8; BUFFER_SIZE];
        let mut dst = [0u8; BUFFER_SIZE];
        loop {
            if let Ok((n, addr)) = sock2.recv_from(&mut src).await {
                let packet = match limiter.verify_packet(Some(addr.ip()), &src[..n], &mut dst) {
                    Ok(packet) => packet,
                    Err(TunnResult::WriteToNetwork(cookie)) => {
                        sock2.send_to(cookie, addr).await.unwrap();
                        continue;
                    }
                    _ => continue,
                };

                let peer = match &packet {
                    Packet::HandshakeInit(p) => {
                        parse_handshake_anon(&keypairs[args.index].0, &keypairs[args.index].1, p)
                            .ok()
                            .and_then(|h| peer_map2.get(&h.peer_static_public[..].into()))
                    }
                    Packet::HandshakeResponse(p) => peer_map2.get_alt(&(p.receiver_idx >> 8)),
                    Packet::PacketCookieReply(p) => peer_map2.get_alt(&(p.receiver_idx >> 8)),
                    Packet::PacketData(p) => peer_map2.get_alt(&(p.receiver_idx >> 8)),
                };

                let peer = match peer {
                    None => continue,
                    Some(peer) => peer,
                };
                let mut peer = peer.lock().await;
                match peer.tunnel.handle_verified_packet(packet, &mut dst) {
                    TunnResult::Done => (),
                    TunnResult::Err(_) => continue,
                    TunnResult::WriteToNetwork(packet) => {
                        sock2.send_to(packet, addr).await.unwrap();
                        while let TunnResult::WriteToNetwork(packet) =
                            peer.tunnel.decapsulate(None, &[], &mut dst)
                        {
                            sock2.send_to(packet, addr).await.unwrap();
                        }
                    }
                    TunnResult::WriteToTunnel(packet) => {
                        writer.write(packet).await.unwrap();
                    }
                }
                peer.endpoint = addr;
            }
        }
    });

    let sock2 = sock.clone();
    let d = spawn(async move {
        loop {
            let mut buf = [0u8; BUFFER_SIZE];
            let mut dst = [0u8; BUFFER_SIZE];
            loop {
                let n = reader.read(&mut buf).await.unwrap();
                let packet = SlicedPacket::from_ethernet(&buf[..n]).unwrap();
                if let Some(link) = packet.link {
                    let header = link.to_header();
                    // https://en.wikipedia.org/wiki/MAC_address#Ranges_of_group_and_locally_administered_addresses
                    match header.destination {
                        // locally administered unicast
                        [b0, _, _, _, _, _] if (b0 & 0b00000011) == 0b00000010 => {
                            let peer = peer_map.get(&EUI48(header.destination));
                            if let Some(peer) = peer {
                                let mut peer = peer.lock().await;
                                match peer.tunnel.encapsulate(&buf[..n], &mut dst) {
                                    TunnResult::Done => {}
                                    TunnResult::Err(e) => {
                                        tracing::error!(message = "encapsulate error", error = ?e)
                                    }
                                    TunnResult::WriteToNetwork(packet) => {
                                        sock2.send_to(packet, peer.endpoint).await.unwrap();
                                    }
                                    _ => unreachable!(),
                                };
                            }
                        }
                        // multicast
                        [b0, _, _, _, _, _] if (b0 & 0b00000001) == 0b00000001 => {
                            for (_, (_, peer)) in peer_map.iter() {
                                let mut peer = peer.lock().await;
                                match peer.tunnel.encapsulate(&buf[..n], &mut dst) {
                                    TunnResult::Done => {}
                                    TunnResult::Err(e) => {
                                        tracing::error!(message = "encapsulate error", error = ?e)
                                    }
                                    TunnResult::WriteToNetwork(packet) => {
                                        sock2.send_to(packet, peer.endpoint).await.unwrap();
                                    }
                                    _ => unreachable!(),
                                };
                            }
                        }
                        _ => {}
                    }
                } else {
                    tracing::error!("ethernet packet error");
                }
            }
        }
    });

    tokio::join!(a, b, c, d);

    Ok(())
}
