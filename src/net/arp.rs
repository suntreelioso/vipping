#![allow(dead_code)]
use std::net::Ipv4Addr;

use pnet::{
    packet::{
        Packet,
        arp::{ArpHardwareType, ArpOperations, MutableArpPacket},
        ethernet::{EtherTypes, MutableEthernetPacket},
    },
    util::MacAddr,
};

pub fn build_arp_request(mac_src: MacAddr, ip_src: Ipv4Addr, ip_dst: Ipv4Addr) -> Vec<u8> {
    let mut buffer = [0u8; 42]; // Ethernet (14) + ARP (28)
    let mut epkt = MutableEthernetPacket::new(&mut buffer).unwrap();
    epkt.set_destination(MacAddr::broadcast());
    epkt.set_source(mac_src);
    epkt.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut apkt = MutableArpPacket::new(&mut arp_buffer).unwrap();
    apkt.set_operation(ArpOperations::Request);
    apkt.set_hardware_type(ArpHardwareType::new(1));
    apkt.set_protocol_type(EtherTypes::Ipv4);
    apkt.set_hw_addr_len(6);
    apkt.set_proto_addr_len(4);
    apkt.set_sender_hw_addr(mac_src);
    apkt.set_target_hw_addr(MacAddr::zero());
    apkt.set_sender_proto_addr(ip_src);
    apkt.set_target_proto_addr(ip_dst);
    epkt.set_payload(&arp_buffer);
    epkt.packet().to_vec()
}

pub fn build_arp_reply(mac_src: MacAddr, mac_dst: MacAddr, ip_src: Ipv4Addr, ip_dst: Ipv4Addr) -> Vec<u8> {
    let mut buffer = [0u8; 42]; // Ethernet (14) + ARP (28)
    let mut epkt = MutableEthernetPacket::new(&mut buffer).unwrap();
    epkt.set_destination(mac_dst);
    epkt.set_source(mac_src);
    epkt.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut apkt = MutableArpPacket::new(&mut arp_buffer).unwrap();
    apkt.set_operation(ArpOperations::Reply);
    apkt.set_hardware_type(ArpHardwareType::new(1));
    apkt.set_protocol_type(EtherTypes::Ipv4);
    apkt.set_hw_addr_len(6);
    apkt.set_proto_addr_len(4);
    apkt.set_sender_hw_addr(mac_src);
    apkt.set_target_hw_addr(mac_dst);
    apkt.set_sender_proto_addr(ip_src);
    apkt.set_target_proto_addr(ip_dst);
    epkt.set_payload(&arp_buffer);
    epkt.packet().to_vec()
}
