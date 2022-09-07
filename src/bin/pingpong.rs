#![feature(async_closure)]
use argh::FromArgs;
use glommio::io::{BufferedFile, DmaBuffer, DmaFile};
use glommio::{net, prelude::*};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::os::unix::prelude::{AsRawFd, FromRawFd};
use std::sync::Arc;
use std::thread::available_parallelism;
use std::vec;

const BUFFER_SIZE: usize = (1 << 16) - 1;

#[derive(FromArgs)]
/// pingpong
struct Args {
    /// node index
    #[argh(option, short = 'i')]
    index: usize,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = argh::from_env();

    let us = SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(127, 0, 0, 1),
        3000 + args.index as u16,
    ));
    let peer = SocketAddr::V4(SocketAddrV4::new(
        Ipv4Addr::new(127, 0, 0, 1),
        3000 + 1 - args.index as u16,
    ));

    for _ in 0..available_parallelism().unwrap().get() {
        let tap_name = format!("pingpong{}", args.index);
        std::thread::spawn(move || {
            LocalExecutorBuilder::default()
                .spawn(async move || {
                    let mut tasks: Vec<glommio::Task<()>> = vec![];
                    let sock = Arc::new(net::UdpSocket::bind(us).unwrap());
                    let tun = boringtap::open_tap(&tap_name).unwrap();
                    let tun = Arc::new(unsafe { BufferedFile::from_raw_fd(tun) });
                    let tun1 = tun.clone();
                    let tun2 = tun.clone();
                    let sock1 = sock.clone();
                    let sock2 = sock.clone();
                    tasks.push(spawn_local(async move {
                        let mut buf = [0u8; BUFFER_SIZE];
                        loop {
                            if let Ok((n, _)) = sock1.recv_from(&mut buf).await {
                                drop(tun1.write_at(buf[..n].to_vec(), 0).await);
                            }
                        }
                    }));
                    tasks.push(spawn_local(async move {
                        loop {
                            if let Ok(buf) = tun2.read_at(0, BUFFER_SIZE).await {
                                drop(sock2.send_to(&buf[..buf.len()], peer).await);
                            }
                        }
                    }));
                    for task in tasks {
                        task.await;
                    }
                })
                .unwrap();
        });
    }

    loop {}
}
