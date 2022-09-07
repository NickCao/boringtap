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
use std::thread::available_parallelism;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::UdpSocket;
use tokio::spawn;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
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
    tunnel: Arc<Mutex<Tunn>>,
    endpoint: Arc<RwLock<SocketAddr>>,
    handle: JoinHandle<()>,
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

    let mut tasks = vec![];
    let limiter_reset = limiter.clone();
    tasks.push(spawn(async move {
        let mut timer = interval(Duration::from_secs(1));
        loop {
            timer.tick().await;
            limiter_reset.reset_count();
        }
    }));

    let mut peer_map = MultiMap::new();
    for (index, peer) in keypairs.iter().enumerate() {
        if index != args.index {
            let tunnel = Arc::new(Mutex::new(Tunn::new(
                keypairs[args.index].0.clone(),
                peer.1,
                None,
                None,
                index as u32,
                limiter.clone(),
            )?));
            let endpoint = Arc::new(RwLock::new(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                3000 + index as u16,
            ))));
            let tunnel1 = tunnel.clone();
            let sock1 = sock.clone();
            let endpoint1 = endpoint.clone();
            let handle = spawn(async move {
                let mut timer = interval(Duration::from_millis(250));
                let mut dst = [0u8; BUFFER_SIZE];
                loop {
                    timer.tick().await;
                    match tunnel1.lock().await.update_timers(&mut dst) {
                        TunnResult::Done => (),
                        TunnResult::Err(WireGuardError::ConnectionExpired) => (),
                        TunnResult::Err(err) => {
                            tracing::error!(message = "error in update timers", error = ?err)
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            sock1
                                .send_to(packet, *endpoint1.read().await)
                                .await
                                .unwrap();
                        }
                        _ => unreachable!(),
                    };
                }
            });
            peer_map.insert(
                peer.1.into(),
                index as u32,
                Peer {
                    tunnel,
                    endpoint,
                    handle,
                },
            );
        }
    }
    let peer_map: Arc<MultiMap<EUI48, u32, Peer>> = Arc::new(peer_map);

    let queues = available_parallelism().unwrap().get();
    let tap_name = format!("boringtap{}", args.index);
    let tap = tokio_tun::TunBuilder::new()
        .name(&tap_name)
        .tap(true)
        .packet_info(false)
        .try_build_mq(queues)?;

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

    for tap in tap.into_iter() {
        let (mut reader, mut writer) = tokio::io::split(tap);
        let kp = keypairs[args.index].clone();
        let sock1 = sock.clone();
        let peer_map1 = peer_map.clone();
        let limiter1 = limiter.clone();
        tasks.push(spawn(async move {
            let mut src = [0u8; BUFFER_SIZE];
            let mut dst = [0u8; BUFFER_SIZE];
            loop {
                if let Ok((n, addr)) = sock1.recv_from(&mut src).await {
                    let packet = match limiter1.verify_packet(Some(addr.ip()), &src[..n], &mut dst)
                    {
                        Ok(packet) => packet,
                        Err(TunnResult::WriteToNetwork(cookie)) => {
                            sock1.send_to(cookie, addr).await.unwrap();
                            continue;
                        }
                        _ => continue,
                    };

                    let peer = match &packet {
                        Packet::HandshakeInit(p) => parse_handshake_anon(&kp.0, &kp.1, p)
                            .ok()
                            .and_then(|h| peer_map1.get(&h.peer_static_public[..].into())),
                        Packet::HandshakeResponse(p) => peer_map1.get_alt(&(p.receiver_idx >> 8)),
                        Packet::PacketCookieReply(p) => peer_map1.get_alt(&(p.receiver_idx >> 8)),
                        Packet::PacketData(p) => peer_map1.get_alt(&(p.receiver_idx >> 8)),
                    };

                    let peer = match peer {
                        None => continue,
                        Some(peer) => peer,
                    };
                    let mut tunnel = peer.tunnel.lock().await;
                    match tunnel.handle_verified_packet(packet, &mut dst) {
                        TunnResult::Done => (),
                        TunnResult::Err(_) => continue,
                        TunnResult::WriteToNetwork(packet) => {
                            sock1.send_to(packet, addr).await.unwrap();
                            while let TunnResult::WriteToNetwork(packet) =
                                tunnel.decapsulate(None, &[], &mut dst)
                            {
                                sock1.send_to(packet, addr).await.unwrap();
                            }
                        }
                        TunnResult::WriteToTunnel(packet) => {
                            writer.write(packet).await.unwrap();
                        }
                    }
                    *peer.endpoint.write().await = addr;
                }
            }
        }));

        let sock2 = sock.clone();
        let peer_map2 = peer_map.clone();
        tasks.push(spawn(async move {
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
                            let peer = peer_map2.get(&EUI48(header.destination));
                            if let Some(peer) = peer {
                                match peer.tunnel.lock().await.encapsulate(&buf[..n], &mut dst) {
                                    TunnResult::Done => {}
                                    TunnResult::Err(e) => {
                                        tracing::error!(message = "encapsulate error", error = ?e)
                                    }
                                    TunnResult::WriteToNetwork(packet) => {
                                        sock2
                                            .send_to(packet, *peer.endpoint.read().await)
                                            .await
                                            .unwrap();
                                    }
                                    _ => unreachable!(),
                                };
                            }
                        }
                        // multicast
                        [b0, _, _, _, _, _] if (b0 & 0b00000001) == 0b00000001 => {
                            for (_, (_, peer)) in peer_map2.iter() {
                                match peer.tunnel.lock().await.encapsulate(&buf[..n], &mut dst) {
                                    TunnResult::Done => {}
                                    TunnResult::Err(e) => {
                                        tracing::error!(message = "encapsulate error", error = ?e)
                                    }
                                    TunnResult::WriteToNetwork(packet) => {
                                        sock2
                                            .send_to(packet, *peer.endpoint.read().await)
                                            .await
                                            .unwrap();
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
        }));
    }

    for t in tasks {
        t.await.unwrap();
    }

    Ok(())
}
