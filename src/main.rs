use etherparse::Icmpv6Type;
use etherparse::InternetSlice;
use etherparse::PacketBuilder;
use etherparse::SlicedPacket;
use etherparse::TransportSlice;
use std::net::Ipv6Addr;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

const BUFFER_SIZE: usize = (1 << 16) - 1;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tap = tokio_tun::TunBuilder::new()
        .name("boringtap")
        .tap(true)
        .packet_info(false)
        .up()
        .try_build()?;
    let (mut reader, mut writer) = tokio::io::split(tap);

    let mut buf = [0u8; BUFFER_SIZE];
    loop {
        let n = reader.read(&mut buf).await?;
        let pkt = SlicedPacket::from_ethernet(&buf[..n]).unwrap();
        match pkt {
            SlicedPacket {
                link: Some(link),
                ip: Some(InternetSlice::Ipv6(header, _)),
                transport: Some(TransportSlice::Icmpv6(transport)),
                ..
            } => {
                // https://www.rfc-editor.org/rfc/rfc4861#section-4.3
                match transport.icmp_type() {
                    Icmpv6Type::Unknown {
                        type_u8: 135,
                        code_u8: 0,
                        bytes5to8: [0, 0, 0, 0],
                    } => {}
                    _ => continue,
                };

                let mut target_address = [0u8; 16];
                target_address.copy_from_slice(&transport.payload()[..16]); // FIXME: check length
                let target_address: Ipv6Addr = target_address.into();

                let (upper, lower) = match target_address.segments() {
                    [0xfe80, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, upper, lower] => {
                        (upper.to_be_bytes(), lower.to_be_bytes())
                    }
                    _ => continue,
                };

                // https://en.wikipedia.org/wiki/MAC_address#Ranges_of_group_and_locally_administered_addresses
                let link_address = [0x02, 0x00, upper[0], upper[1], lower[0], lower[1]];
                let builder = PacketBuilder::ethernet2(link_address, link.to_header().source);

                let builder = builder.ipv6(target_address.octets(), header.source(), 255);

                // https://www.rfc-editor.org/rfc/rfc4861#section-4.4
                let builder = builder.icmpv6(Icmpv6Type::Unknown {
                    type_u8: 136,
                    code_u8: 0,
                    bytes5to8: [0x60, 0x00, 0x00, 0x00],
                });

                let payload = [
                    &target_address.octets()[..],
                    &[0x02, 0x01],
                    &link_address[..],
                ]
                .concat();
                let mut buffer = vec![];
                builder.write(&mut buffer, &payload).unwrap();
                writer.write(&buffer).await.unwrap();
            }
            _ => (),
        }
    }
}
