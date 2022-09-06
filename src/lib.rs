use std::net::{IpAddr, Ipv6Addr};

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
