#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::time::SystemTime;

use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, MutableIcmpPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{self, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{Packet, icmp};
use pnet::util::MacAddr;

pub fn build_icmp_packet(mac_src: MacAddr, mac_dst: MacAddr, ip_src: Ipv4Addr, ip_dst: Ipv4Addr, packet_id: u16) -> Vec<u8> {
    let mut buffer = [0u8; 98]; // Ethernet (14) + IP (20) + ICMP (64)
    let mut ip_buffer = [0u8; 84]; // IP (20) + ICMP (64)
    let mut icmp_buffer = [0u8; 64]; // ICMP (64)

    let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    ethernet_packet.set_destination(mac_dst);
    ethernet_packet.set_source(mac_src);
    ethernet_packet.set_ethertype(EtherTypes::Ipv4);

    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(84);
    ip_packet.set_identification(packet_id);
    ip_packet.set_flags(0x02);
    ip_packet.set_ttl(64);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_packet.set_source(ip_src);
    ip_packet.set_destination(ip_dst);
    let ip_checksum = ipv4::checksum(&Ipv4Packet::new(ip_packet.packet()).unwrap());
    ip_packet.set_checksum(ip_checksum);

    let mut icmp_packet = MutableIcmpPacket::new(&mut icmp_buffer).unwrap();
    icmp_packet.set_icmp_type(IcmpTypes::EchoRequest);

    let mut icmp_payload = packet_id.to_be_bytes().to_vec();
    icmp_payload.push(0x00);
    icmp_payload.push(0x01);
    icmp_payload.extend(SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs().to_le_bytes());
    icmp_payload.extend(ICMP_PADDING_DATA);

    icmp_packet.set_payload(&icmp_payload.to_vec());
    let icmp_checksum = icmp::checksum(&IcmpPacket::new(icmp_packet.packet()).unwrap());
    icmp_packet.set_checksum(icmp_checksum);
    ip_packet.set_payload(icmp_packet.packet());
    ethernet_packet.set_payload(ip_packet.packet());
    ethernet_packet.packet().to_vec()
}

// hardcoded padding data
const ICMP_PADDING_DATA: [u8; 48] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
];
