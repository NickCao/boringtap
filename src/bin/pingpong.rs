use argh::FromArgs;
use io_uring::cqueue::buffer_select;
use io_uring::squeue;
use io_uring::{opcode, squeue::Flags, types, IoUring};
use libc::{c_void, malloc};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll, Token};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::net::SocketAddr;
use std::net::UdpSocket;
use std::os::unix::prelude::AsRawFd;
use std::slice::from_raw_parts_mut;

const PKT_SIZE: usize = 65535;
const BUF_SIZE: usize = PKT_SIZE * 2;

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
    opcode::Read::new(types::Fixed(fd), std::ptr::null_mut(), PKT_SIZE as _)
        .buf_group(0)
        .build()
        .flags(Flags::BUFFER_SELECT)
        .user_data(fd.into())
}

fn prep_write(fd: u32, buffers: *mut c_void, bid: u16, n: u32) -> [squeue::Entry; 2] {
    [
        opcode::Write::new(
            types::Fixed(fd),
            unsafe { (buffers as *mut u8).add((bid as usize * BUF_SIZE) + PKT_SIZE) },
            n,
        )
        .build()
        .flags(Flags::IO_HARDLINK)
        .user_data(u64::MAX),
        prep_buffer(buffers, bid),
    ]
}

fn prep_buffer(buffers: *mut c_void, bid: u16) -> squeue::Entry {
    opcode::ProvideBuffers::new(
        unsafe { (buffers as *mut u8).add(bid as usize * BUF_SIZE) },
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
            let psk = UnboundKey::new(&CHACHA20_POLY1305, &[1u8; 32]).unwrap();
            let key = LessSafeKey::new(psk);

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
                    let mut sq = ring.submission_shared();
                    for cqe in ring.completion_shared() {
                        let data = cqe.user_data();
                        match data {
                            0 | 1 => {
                                let buf = buffer_select(cqe.flags());
                                if cqe.result() > 0 {
                                    let packet = from_raw_parts_mut(
                                        (buffers as *mut u8).add(buf.unwrap() as usize * BUF_SIZE),
                                        cqe.result() as usize,
                                    );
                                    let dst = from_raw_parts_mut(
                                        (buffers as *mut u8)
                                            .add((buf.unwrap() as usize * BUF_SIZE) + PKT_SIZE),
                                        PKT_SIZE,
                                    );
                                    let len = match data {
                                        0 => {
                                            let tag = key
                                                .seal_in_place_separate_tag(
                                                    Nonce::assume_unique_for_key([0u8; 12]),
                                                    Aad::empty(),
                                                    packet,
                                                )
                                                .unwrap();
                                            dst[..packet.len()].copy_from_slice(packet);
                                            dst[packet.len()..packet.len() + tag.as_ref().len()]
                                                .copy_from_slice(tag.as_ref());
                                            packet.len() + tag.as_ref().len()
                                        }
                                        1 => {
                                            let plain = key
                                                .open_in_place(
                                                    Nonce::assume_unique_for_key([0u8; 12]),
                                                    Aad::empty(),
                                                    packet,
                                                )
                                                .unwrap();
                                            dst[..plain.len()].copy_from_slice(plain);
                                            plain.len()
                                        }
                                        _ => unreachable!(),
                                    };
                                    sq.push_multiple(&prep_write(
                                        (1 - data) as u32,
                                        buffers,
                                        buf.unwrap(),
                                        len as u32,
                                    ))
                                    .unwrap();
                                } else if let Some(buf) = buf {
                                    sq.push(&prep_buffer(buffers, buf)).unwrap();
                                }
                                sq.push(&prep_read(data as u32)).unwrap();
                            }
                            _ => {}
                        }
                    }
                    sq.sync();
                    ring.submit().unwrap();
                }
            }
        });
    }
    loop {}
}
