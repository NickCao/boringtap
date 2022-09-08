use std::os::unix::prelude::FromRawFd;
use std::thread::available_parallelism;

const BUFFER_SIZE: usize = 65535;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ping = boringtap::open_tap("ping").unwrap();
    let pong = boringtap::open_tap("pong").unwrap();
    for _ in 0..available_parallelism().unwrap().get() {
        std::thread::spawn(move || {
            glommio::LocalExecutorBuilder::default()
                .spawn(move || async move {
                    let a = glommio::spawn_local(async move {
                        let ping = unsafe { glommio::io::BufferedFile::from_raw_fd(ping) };
                        let pong = unsafe { glommio::io::BufferedFile::from_raw_fd(pong) };
                        loop {
                            if let Ok(buf) = ping.read_at(0, BUFFER_SIZE).await {
                                drop(pong.write_at(buf.to_vec(), 0).await);
                            }
                        }
                    });
                    let b = glommio::spawn_local(async move {
                        let ping = unsafe { glommio::io::BufferedFile::from_raw_fd(ping) };
                        let pong = unsafe { glommio::io::BufferedFile::from_raw_fd(pong) };
                        loop {
                            if let Ok(buf) = pong.read_at(0, BUFFER_SIZE).await {
                                drop(ping.write_at(buf.to_vec(), 0).await);
                            }
                        }
                    });
                    a.await;
                    b.await;
                })
                .unwrap();
        });
    }
    loop {}
}
