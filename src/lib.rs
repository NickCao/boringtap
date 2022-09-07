use libc::*;
use std::{
    net::{IpAddr, Ipv6Addr},
    os::unix::prelude::RawFd,
};
use x25519_dalek::PublicKey;

pub mod noise;

#[derive(Eq, Hash, PartialEq, Clone)]
pub struct EUI48(pub [u8; 6]);

impl From<&[u8]> for EUI48 {
    fn from(key: &[u8]) -> Self {
        let octs = xxhash_rust::xxh3::xxh3_64(key).to_be_bytes();
        EUI48([
            octs[0] & 0b11111110 | 0b00000010,
            octs[1],
            octs[2],
            octs[3],
            octs[4],
            octs[5],
        ])
    }
}

impl From<PublicKey> for EUI48 {
    fn from(key: PublicKey) -> Self {
        key.as_bytes()[..].into()
    }
}

impl Into<IpAddr> for &EUI48 {
    fn into(self) -> IpAddr {
        let octs = self.0;
        IpAddr::V6(Ipv6Addr::from(u128::from_be_bytes([
            0xfe,
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            octs[0] ^ 0b00000010,
            octs[1],
            octs[2],
            0xff,
            0xfe,
            octs[3],
            octs[4],
            octs[5],
        ])))
    }
}

const TUNSETIFF: u64 = 0x4004_54ca;

#[repr(C)]
union IfrIfru {
    ifru_addr: sockaddr,
    ifru_addr_v4: sockaddr_in,
    ifru_addr_v6: sockaddr_in,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_flags: c_short,
    ifru_metric: c_int,
    ifru_mtu: c_int,
    ifru_phys: c_int,
    ifru_media: c_int,
    ifru_intval: c_int,
    //ifru_data: caddr_t,
    //ifru_devmtu: ifdevmtu,
    //ifru_kpi: ifkpi,
    ifru_wake_flags: u32,
    ifru_route_refcnt: u32,
    ifru_cap: [c_int; 2],
    ifru_functional_type: u32,
}

#[repr(C)]
#[allow(non_camel_case_types)]
struct ifreq {
    ifr_name: [c_uchar; IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

pub fn open_tap(name: &str) -> std::io::Result<RawFd> {
    let fd = match unsafe { open(b"/dev/net/tun\0".as_ptr() as _, O_RDWR) } {
        -1 => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "failed to open char dev",
            ));
        }
        fd => fd,
    };

    let iface_name = name.as_bytes();
    let mut ifr = ifreq {
        ifr_name: [0; IFNAMSIZ],
        ifr_ifru: IfrIfru {
            ifru_flags: (IFF_TAP | IFF_NO_PI | IFF_MULTI_QUEUE) as _,
        },
    };

    if iface_name.len() >= ifr.ifr_name.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ifname too long",
        ));
    }

    ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

    if unsafe { ioctl(fd, TUNSETIFF as _, &ifr) } < 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "ioctl failed",
        ));
    }

    match unsafe { fcntl(fd, F_GETFL) } {
        -1 => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "get flags failed",
        )),
        flags => match unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } {
            -1 => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "set non block failed",
            )),
            _ => Ok(fd),
        },
    }
}
