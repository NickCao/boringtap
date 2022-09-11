use argh::FromArgs;
use io_uring::cqueue::buffer_select;
use io_uring::squeue;
use io_uring::{opcode, squeue::Flags, types, IoUring};
use libc::{c_void, malloc};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::unix::prelude::AsRawFd;

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

fn prep_read(fd: u32) -> squeue::Entry {
    opcode::Read::new(types::Fixed(fd), std::ptr::null_mut(), BUF_SIZE as _)
        .buf_group(0)
        .build()
        .flags(Flags::BUFFER_SELECT)
        .user_data(fd.into())
}

fn prep_buffer(buffers: *mut c_void, bid: u16) -> squeue::Entry {
    opcode::ProvideBuffers::new(
        unsafe { (buffers as *mut u8).offset((bid as usize * BUF_SIZE) as isize) },
        BUF_SIZE as _,
        1,
        0,
        bid,
    )
    .build()
    .user_data(3)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Args = argh::from_env();

    let tap = boringtap::open_tap(&args.name).unwrap();

    let sock = UdpSocket::bind(args.bind).unwrap();
    sock.connect(args.peer).unwrap();
    sock.set_nonblocking(true).unwrap();

    let fds = [tap.as_raw_fd(), sock.as_raw_fd()];

    for _ in 0..4 {
        std::thread::spawn(move || {
            let eventfd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };

            let mut poll = Poll::new().unwrap();
            poll.registry()
                .register(&mut SourceFd(&eventfd), Token(0), Interest::READABLE)
                .unwrap();
            let mut events = Events::with_capacity(1024);

            let mut ring = IoUring::builder().build(128).unwrap();
            let submitter = ring.submitter();
            submitter.register_files(&fds).unwrap();
            submitter.register_eventfd(eventfd).unwrap();

            let buffers = unsafe { malloc(128 * BUF_SIZE) };

            unsafe {
                ring.submission()
                    .push(
                        &opcode::ProvideBuffers::new(buffers as _, BUF_SIZE as _, 128, 0, 0)
                            .build()
                            .user_data(3),
                    )
                    .unwrap();

                ring.submission().push(&prep_read(0)).unwrap();
                ring.submission().push(&prep_read(1)).unwrap();
                ring.submit().unwrap();

                loop {
                    drop(poll.poll(&mut events, None));
                    for cqe in ring.completion_shared() {
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
                                } else if let Some(buf) = buffer_select(cqe.flags()) {
                                    ring.submission_shared()
                                        .push(&prep_buffer(buffers, buf))
                                        .unwrap();
                                }
                                ring.submission_shared()
                                    .push(&prep_read(read_from as u32))
                                    .unwrap();
                                ring.submit().unwrap();
                            }
                            3 => {}
                            _ => {
                                let buf = (data >> 32) as u16;
                                ring.submission_shared()
                                    .push(&prep_buffer(buffers, buf))
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
