use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::unix::prelude::AsRawFd;

use argh::FromArgs;
use io_uring::{opcode, squeue::Flags, types, IoUring};
use libc::{iovec, malloc};

const BUF_SIZE: usize = 65535;

#[derive(FromArgs)]
/// pingpong
struct Args {
    /// tap name
    #[argh(option, short = 'n')]
    name: String,
    /// bind address
    #[argh(option, short = 'b')]
    bind: SocketAddr,
    /// peer address
    #[argh(option, short = 'p')]
    peer: SocketAddr,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = argh::from_env();

    let tap = boringtap::open_tap(&args.name).unwrap();

    let sock = UdpSocket::bind(args.bind).unwrap();
    sock.connect(args.peer).unwrap();
    sock.set_nonblocking(true).unwrap();

    let fds = [tap.as_raw_fd(), sock.as_raw_fd()];

    for _ in 0..1 {
        std::thread::spawn(move || {
            let iov = unsafe {
                [
                    iovec {
                        iov_base: malloc(BUF_SIZE),
                        iov_len: BUF_SIZE,
                    },
                    iovec {
                        iov_base: malloc(BUF_SIZE),
                        iov_len: BUF_SIZE,
                    },
                ]
            };

            let mut ring = IoUring::builder().build(128).unwrap();
            let submitter = ring.submitter();

            submitter.register_files(&fds).unwrap();
            submitter.register_buffers(&iov).unwrap();

            unsafe {
                ring.submission()
                    .push(
                        &opcode::ReadFixed::new(
                            types::Fixed(0),
                            iov[0].iov_base as _,
                            iov[0].iov_len as _,
                            0,
                        )
                        .build()
                        .user_data(0),
                    )
                    .unwrap();
                ring.submission()
                    .push(
                        &opcode::ReadFixed::new(
                            types::Fixed(1),
                            iov[1].iov_base as _,
                            iov[1].iov_len as _,
                            1,
                        )
                        .build()
                        .user_data(1),
                    )
                    .unwrap();
                ring.submit().unwrap();

                loop {
                    for cqe in ring.completion_shared().into_iter() {
                        let data = cqe.user_data();
                        if data != u64::MAX {
                            let read_from = data as usize;
                            let write_to = 1 - read_from;
                            if cqe.result() > 0 {
                                ring.submission_shared()
                                    .push(
                                        &opcode::WriteFixed::new(
                                            types::Fixed(write_to as u32),
                                            iov[read_from].iov_base as _,
                                            cqe.result() as u32,
                                            read_from as u16,
                                        )
                                        .build()
                                        .flags(Flags::IO_LINK)
                                        .user_data(u64::MAX),
                                    )
                                    .unwrap();
                            }
                            ring.submission_shared()
                                .push(
                                    &opcode::ReadFixed::new(
                                        types::Fixed(read_from as u32),
                                        iov[read_from].iov_base as _,
                                        iov[read_from].iov_len as _,
                                        read_from as u16,
                                    )
                                    .build()
                                    .user_data(read_from as u64),
                                )
                                .unwrap();
                            ring.submit().unwrap();
                        } else {
                        }
                    }
                }
            }
        });
    }
    loop {}
}
