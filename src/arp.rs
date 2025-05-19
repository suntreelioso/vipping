#![allow(dead_code)]

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, mpsc};
use std::thread::spawn;
use std::time::Duration;

use pnet::datalink::NetworkInterface;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::Packet;
use pnet::packet::arp::{ArpHardwareType, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

const RW_BUFFER_SIZE: usize = 256;

pub(crate) fn get_target_mac_by_arp(
    iface: &NetworkInterface,
    src: Ipv4Addr,
    dst: Ipv4Addr,
    timeout: Option<u64>,
) -> Result<MacAddr, ()> {
    let mut config = datalink::Config::default();
    config.read_buffer_size = RW_BUFFER_SIZE;
    config.write_buffer_size = RW_BUFFER_SIZE;
    let (mut tx, mut rx) = match datalink::channel(&iface, config) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(()),
        Err(e) => {
            println!("Error: {}", e);
            return Err(());
        }
    };

    let arp_request = build_arp_packet(iface, src, dst);
    match tx.send_to(&arp_request, None) {
        None => {
            println!("Error: Failed to send ARP request");
            return Err(());
        }
        _ => {}
    }

    let th_timeout = Arc::new(Mutex::new(true));
    let th_timeout_clone = th_timeout.clone();
    let (send, recv) = mpsc::channel();
    let jh = spawn(move || {
        while *th_timeout_clone.lock().unwrap() {
            match rx.next() {
                Ok(packet) => {
                    let packet = EthernetPacket::new(packet).unwrap();
                    if packet.get_ethertype() != EtherTypes::Arp {
                        continue;
                    }
                    let r_arp = ArpPacket::new(packet.payload()).unwrap();
                    if r_arp.get_operation() == ArpOperations::Reply && r_arp.get_sender_proto_addr() == dst {
                        send.send(r_arp.get_sender_hw_addr()).unwrap();
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    match recv.recv_timeout(Duration::from_secs(match timeout {
        Some(t) => t,
        None => 1,
    })) {
        Ok(mac_addr) => {
            jh.join().unwrap();
            Ok(mac_addr)
        }
        Err(_) => {
            *th_timeout.lock().unwrap() = false;
            jh.join().unwrap();
            Err(())
        }
    }
}

fn build_arp_packet(iface: &NetworkInterface, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut buffer = [0u8; 42]; // Ethernet (14) + ARP (28)
    let mut ethernet_packet = MutableEthernetPacket::new(&mut buffer).unwrap();
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(iface.mac.unwrap());
    ethernet_packet.set_ethertype(EtherTypes::Arp);

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_hardware_type(ArpHardwareType::new(1));
    arp_packet.set_protocol_type(EtherTypes::Ipv4);
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_sender_hw_addr(iface.mac.unwrap());
    arp_packet.set_target_hw_addr(MacAddr::zero());
    arp_packet.set_sender_proto_addr(src);
    arp_packet.set_target_proto_addr(dst);
    ethernet_packet.set_payload(arp_packet.packet());
    ethernet_packet.packet().to_vec()
}
