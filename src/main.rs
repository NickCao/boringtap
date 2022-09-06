use argh::FromArgs;
use boringtap::noise::errors::WireGuardError;
use boringtap::noise::handshake::parse_handshake_anon;
use boringtap::noise::{rate_limiter::RateLimiter, Tunn};
use boringtap::noise::{Packet, TunnResult};
use etherparse::SlicedPacket;
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

    let mut tunnels = vec![];
    let mut peers = vec![];
    for (index, peer) in keypairs.iter().enumerate() {
        let tunnel = Tunn::new(
            keypairs[args.index].0.clone(),
            PublicKey::from(peer.1),
            None,
            None,
            index as u32,
            limiter.clone(),
        )
        .unwrap();
        tunnels.push(tunnel);
        peers.push(PublicKey::from(peer.1));
    }
    let tunnels = Arc::new(Mutex::new(tunnels));

    let tap = tokio_tun::TunBuilder::new()
        .name(&format!("boringtap{}", args.index))
        .tap(true)
        .packet_info(false)
        .up()
        .try_build()?;
    let (mut reader, mut writer) = tokio::io::split(tap);

    let tunnels1 = tunnels.clone();
    let sock1 = sock.clone();
    let b = spawn(async move {
        let mut timer = interval(Duration::from_millis(250));
        let mut dst = [0u8; BUFFER_SIZE];
        loop {
            timer.tick().await;
            let mut tunnels = tunnels1.lock().await;
            for (index, tunnel) in tunnels.iter_mut().enumerate() {
                match tunnel.update_timers(&mut dst) {
                    TunnResult::Done => {}
                    TunnResult::Err(WireGuardError::ConnectionExpired) => {}
                    TunnResult::Err(e) => eprintln!("{:?}", e),
                    TunnResult::WriteToNetwork(packet) => {
                        sock1
                            .send_to(
                                packet,
                                SocketAddr::V4(SocketAddrV4::new(
                                    Ipv4Addr::new(127, 0, 0, 1),
                                    3000 + index as u16,
                                )),
                            )
                            .await
                            .unwrap();
                    }
                    _ => panic!("Unexpected result from update_timers"),
                };
            }
        }
    });

    let sock_recv = sock.clone();
    let tunnels2 = tunnels.clone();
    let c = spawn(async move {
        let mut src = [0u8; BUFFER_SIZE];
        let mut dst = [0u8; BUFFER_SIZE];
        loop {
            if let Ok((n, addr)) = sock_recv.recv_from(&mut src).await {
                eprintln!("received packet from {}", addr);
                let packet = match limiter.verify_packet(Some(addr.ip()), &src[..n], &mut dst) {
                    Ok(packet) => packet,
                    Err(TunnResult::WriteToNetwork(cookie)) => {
                        sock_recv.send_to(cookie, addr).await.unwrap();
                        eprintln!("doint handshake");
                        continue;
                    }
                    _ => continue,
                };

                eprintln!("parsed packet");
                let peer_index = match &packet {
                    Packet::HandshakeInit(p) => {
                        parse_handshake_anon(&keypairs[args.index].0, &keypairs[args.index].1, &p)
                            .ok()
                            .and_then(|h| {
                                peers.iter().enumerate().find_map(|t| {
                                    if t.1.as_bytes() == &h.peer_static_public {
                                        Some(t.0 as u32)
                                    } else {
                                        None
                                    }
                                })
                            })
                    }
                    Packet::HandshakeResponse(p) => Some(p.receiver_idx),
                    Packet::PacketCookieReply(p) => Some(p.receiver_idx),
                    Packet::PacketData(p) => Some(p.receiver_idx),
                };

                eprintln!("found peer");
                let mut tunnels = tunnels2.lock().await;
                let tunnel = match peer_index {
                    None => continue,
                    Some(peer_index) => &mut tunnels[(peer_index >> 8) as usize],
                };
                eprintln!("found tunnel");

                match tunnel.handle_verified_packet(packet, &mut dst) {
                    TunnResult::Done => (),
                    TunnResult::Err(e) => {
                        eprintln!("{:?}", e);
                        continue;
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        sock_recv.send_to(packet, addr).await.unwrap();
                        while let TunnResult::WriteToNetwork(packet) =
                            tunnel.decapsulate(None, &[], &mut dst)
                        {
                            sock_recv.send_to(packet, addr).await.unwrap();
                        }
                    }
                    TunnResult::WriteToTunnel(packet) => {
                        eprintln!("written packet to tunnel");
                        writer.write(packet).await.unwrap();
                    }
                }
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
                    let mut tunnels = tunnels.lock().await;
                    // https://en.wikipedia.org/wiki/MAC_address#Ranges_of_group_and_locally_administered_addresses
                    match header.destination {
                        // IPv6 multicast
                        [a0, _, _, _, _, _] if a0 & 0x01 == 0x01 => {
                            eprintln!("broadcasting");
                            for (index, tunnel) in tunnels.iter_mut().enumerate() {
                                match tunnel.encapsulate(&buf[..n], &mut dst) {
                                    TunnResult::Done => {}
                                    TunnResult::Err(e) => eprintln!("{:?}", e),
                                    TunnResult::WriteToNetwork(packet) => {
                                        sock2
                                            .send_to(
                                                packet,
                                                SocketAddr::V4(SocketAddrV4::new(
                                                    Ipv4Addr::new(127, 0, 0, 1),
                                                    3000 + index as u16,
                                                )),
                                            )
                                            .await
                                            .unwrap();
                                    }
                                    _ => unreachable!(),
                                };
                            }
                        }
                        // boringtun locally administered unicast
                        [0x02, 0x00, a0, a1, a2, _] => {
                            let index = u32::from_be_bytes([a0, a1, a2, 0]) >> 8;
                            match tunnels[index as usize].encapsulate(&buf[..n], &mut dst) {
                                TunnResult::Done => {}
                                TunnResult::Err(e) => eprintln!("{:?}", e),
                                TunnResult::WriteToNetwork(packet) => {
                                    sock2
                                        .send_to(
                                            packet,
                                            SocketAddr::V4(SocketAddrV4::new(
                                                Ipv4Addr::new(127, 0, 0, 1),
                                                3000 + index as u16,
                                            )),
                                        )
                                        .await
                                        .unwrap();
                                }
                                _ => unreachable!(),
                            };
                        }
                        a => eprintln!("destination address out of supported range: {:x?}", a),
                    }
                } else {
                    eprintln!("invalid ethernet packet");
                }
            }
        }
    });

    tokio::join!(a, b, c, d);

    Ok(())
}
