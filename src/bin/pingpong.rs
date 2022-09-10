use io_uring::{opcode, squeue::Flags, types, IoUring};
use libc::{iovec, malloc};

const BUF_SIZE: usize = 65535;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ping = boringtap::open_tap("ping").unwrap();
    let pong = boringtap::open_tap("pong").unwrap();
    let fds = [ping, pong];

    for _ in 0..4 {
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
                        ring.completion_shared().sync();
                    }
                }
            }
        });
    }
    loop {}
}
