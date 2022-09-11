use io_uring::cqueue::buffer_select;
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::fs::File;
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::unix::prelude::{AsRawFd, FromRawFd, RawFd};
use std::time::Duration;

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
            let eventfd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };

            let mut poll = Poll::new().unwrap();
            poll.registry()
                .register(&mut SourceFd(&eventfd), Token(0), Interest::READABLE)
                .unwrap();
            let mut events = Events::with_capacity(1024);

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
            submitter.register_eventfd(eventfd).unwrap();

            let buffers = unsafe { malloc(128 * BUF_SIZE) };

            unsafe {
                ring.submission()
                    .push(
                        &opcode::ProvideBuffers::new(
                            buffers as _,
                            128 * BUF_SIZE as i32,
                            128,
                            0,
                            0,
                        )
                        .build()
                        .user_data(3),
                    )
                    .unwrap();

                ring.submission()
                    .push(
                        &opcode::Read::new(types::Fixed(0), std::ptr::null_mut(), BUF_SIZE as _)
                            .buf_group(0)
                            .build()
                            .flags(Flags::BUFFER_SELECT)
                            .user_data(0),
                    )
                    .unwrap();

                ring.submission()
                    .push(
                        &opcode::Read::new(types::Fixed(1), std::ptr::null_mut(), BUF_SIZE as _)
                            .buf_group(0)
                            .build()
                            .flags(Flags::BUFFER_SELECT)
                            .user_data(1),
                    )
                    .unwrap();

                ring.submit().unwrap();

                loop {
                    drop(poll.poll(&mut events, None));
                    for cqe in ring.completion_shared().into_iter() {
                        let data = cqe.user_data();
                        match data {
                            0 | 1 => {
                                let read_from = data as usize;
                                let write_to = 1 - read_from;
                                if cqe.result() > 0 {
                                    let buf = buffer_select(cqe.flags()).unwrap() as usize;
                                    ring.submission_shared()
                                        .push(
                                            &opcode::Write::new(
                                                types::Fixed(write_to as u32),
                                                (buffers as usize + buf * BUF_SIZE) as _,
                                                cqe.result() as u32,
                                            )
                                            .build()
                                            .user_data((((buf as u64) << 32) + 2) as u64),
                                        )
                                        .unwrap();
                                } else if cqe.result() != -libc::ENOBUFS {
                                    let buf = buffer_select(cqe.flags()).unwrap() as usize;
                                    ring.submission_shared()
                                        .push(
                                            &opcode::ProvideBuffers::new(
                                                (buffers as usize + buf * BUF_SIZE) as _,
                                                BUF_SIZE as _,
                                                1,
                                                0,
                                                buf as _,
                                            )
                                            .build()
                                            .user_data(3),
                                        )
                                        .unwrap();
                                }
                                ring.submission_shared()
                                    .push(
                                        &opcode::Read::new(
                                            types::Fixed(read_from as u32),
                                            std::ptr::null_mut(),
                                            BUF_SIZE as _,
                                        )
                                        .buf_group(0)
                                        .build()
                                        .flags(Flags::BUFFER_SELECT)
                                        .user_data(read_from as u64),
                                    )
                                    .unwrap();
                                ring.submit().unwrap();
                            }
                            3 => {}
                            _ => {
                                let buf = (data >> 32) as usize;
                                ring.submission_shared()
                                    .push(
                                        &opcode::ProvideBuffers::new(
                                            (buffers as usize + buf * BUF_SIZE) as _,
                                            BUF_SIZE as _,
                                            1,
                                            0,
                                            buf as _,
                                        )
                                        .build()
                                        .user_data(3),
                                    )
                                    .unwrap();
                                ring.submit().unwrap();
                            }
                        }
                    }
                }
            }
        });
    }
    loop {}
}
