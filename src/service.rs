#![allow(dead_code)]

use std::{
    env,
    net::Ipv4Addr,
    process::exit,
    time::{Duration, SystemTime},
};

use actix_web::rt::time::sleep;
use log::*;
use moka::future::Cache;
use once_cell::sync::Lazy;
use pnet::{
    datalink::NetworkInterface,
    packet::{
        Packet,
        arp::{ArpOperations, ArpPacket},
        ethernet::{EtherTypes, EthernetPacket},
        icmp::{IcmpPacket, IcmpTypes},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
    },
    util::MacAddr,
};

use crate::{
    net::{self, ChannelPair},
    types::PingIdRecordEntry,
};

const CACHE_TIME_TO_LIVE: Duration = Duration::from_secs(90);

static USED_IPADDR: Lazy<Cache<Ipv4Addr, ()>> = Lazy::new(|| Cache::builder().time_to_live(CACHE_TIME_TO_LIVE / 2).build());
static ARP_RECORD: Lazy<Cache<Ipv4Addr, MacAddr>> = Lazy::new(|| Cache::builder().time_to_live(CACHE_TIME_TO_LIVE).build());
static PING_ID_RECORD: Lazy<Cache<Ipv4Addr, PingIdRecordEntry>> = Lazy::new(|| Cache::builder().time_to_live(CACHE_TIME_TO_LIVE).build());
static PING_SUCESS: Lazy<Cache<Ipv4Addr, f64>> = Lazy::new(|| Cache::builder().time_to_live(CACHE_TIME_TO_LIVE).build());

static INTERFACE: Lazy<NetworkInterface> = Lazy::new(|| {
    let name = env::var("INTERFACE").unwrap_or_else(|_| {
        error!("INTERFACE not set");
        exit(1);
    });
    let interface = net::get_interface_by_name(&name).unwrap_or_else(|| {
        error!("INTERFACE not set");
        exit(1);
    });
    interface
});

static CHPAIR: Lazy<ChannelPair> = Lazy::new(|| get_channel_pair());

fn get_channel_pair() -> ChannelPair {
    match net::get_channel(&INTERFACE) {
        Ok(v) => v,
        Err(_) => {
            error!("get channel failed");
            exit(1);
        }
    }
}

pub(crate) async fn ping(ip_src: Ipv4Addr, ip_dst: Ipv4Addr, gateway: Option<Ipv4Addr>, timeout: Duration) -> Option<f64> {
    USED_IPADDR.insert(ip_src, ()).await;

    let arp_target = match gateway {
        Some(v) => v,
        None => ip_dst,
    };

    let target_mac = match ARP_RECORD.get(&arp_target).await {
        Some(cache_mac) => {
            debug!("hit arp cache [{} <-> {}]", arp_target, cache_mac);
            cache_mac
        }
        None => {
            send_arp_request(ip_src, arp_target);
            let arp_timer = SystemTime::now();
            let mut result: Option<MacAddr> = None;
            while arp_timer.elapsed().unwrap() < timeout && result.is_none() {
                match ARP_RECORD.get(&arp_target).await {
                    Some(mac) => result = Some(mac),
                    None => sleep(Duration::from_millis(2)).await,
                }
            }
            if result.is_none() {
                warn!("get target({}) mac timeout", arp_target);
                return None;
            }
            result.unwrap()
        }
    };

    let packet_id = send_icmp_request(target_mac, ip_src, ip_dst);
    let ping_timer = SystemTime::now();
    PING_ID_RECORD.insert(ip_dst, PingIdRecordEntry::new(packet_id, ping_timer)).await;
    let ping_timer = SystemTime::now();
    let mut result: Option<f64> = None;
    while ping_timer.elapsed().unwrap() < timeout && result.is_none() {
        let ms = PING_SUCESS.get(&ip_dst).await;
        if ms.is_some() {
            result = ms;
        } else {
            sleep(Duration::from_micros(300)).await
        }
    }
    return result;
}

pub(crate) async fn start_net_service() {
    info!("start net service");
    let rx = &mut CHPAIR.rx.lock().unwrap();
    loop {
        let pkt = rx.next().unwrap();
        let pkt = EthernetPacket::new(pkt).unwrap();
        match pkt.get_ethertype() {
            EtherTypes::Arp => {
                let arp_pkt = pnet::packet::arp::ArpPacket::new(pkt.payload()).unwrap();
                process_arp_pkt(&arp_pkt).await;
            }
            EtherTypes::Ipv4 => {
                let ip_pkt = Ipv4Packet::new(pkt.payload()).unwrap();
                match ip_pkt.get_next_level_protocol() {
                    IpNextHeaderProtocols::Icmp => {
                        let icmp_pkt = IcmpPacket::new(ip_pkt.payload()).unwrap();
                        process_icmp_pkt(&ip_pkt, &icmp_pkt).await;
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
}

async fn process_icmp_pkt(ip_pkt: &Ipv4Packet<'_>, icmp_pkt: &IcmpPacket<'_>) {
    if IcmpTypes::EchoReply == icmp_pkt.get_icmp_type() {
        debug!("received icmp echo reply packet {} <-> {}", ip_pkt.get_source(), ip_pkt.get_destination());
        let payload = icmp_pkt.payload();
        let packet_id = u16::from_be_bytes([payload[0], payload[1]]);
        if let Some(entry) = PING_ID_RECORD.get(&ip_pkt.get_source()).await {
            if entry.equals(packet_id) {
                PING_ID_RECORD.remove(&ip_pkt.get_source()).await;
                PING_SUCESS.insert(ip_pkt.get_source(), entry.get_time_elapsed_ms()).await;
            }
        }
    }
}

async fn process_arp_pkt(arp_pkt: &ArpPacket<'_>) {
    match arp_pkt.get_operation() {
        ArpOperations::Request => {
            let target_ip = arp_pkt.get_target_proto_addr();
            if let Some(()) = USED_IPADDR.get(&target_ip).await {
                debug!("received arp request packet {:?}", arp_pkt);
                send_arp_reply(
                    arp_pkt.get_sender_hw_addr(),
                    arp_pkt.get_target_proto_addr(),
                    arp_pkt.get_sender_proto_addr(),
                );
            }
        }
        ArpOperations::Reply => {
            debug!("received arp reply packet {:?}", arp_pkt);
            let sender_ip = arp_pkt.get_sender_proto_addr();
            let sender_mac = arp_pkt.get_sender_hw_addr();
            ARP_RECORD.insert(sender_ip, sender_mac).await;
            debug!("arp cache updated [{} <-> {}]", sender_ip, sender_mac);
        }
        _ => {}
    }
}

fn send_arp_request(ip_src: Ipv4Addr, ip_dst: Ipv4Addr) {
    debug!("send arp request from {} to {}", ip_src, ip_dst);
    let pkt = net::arp::build_arp_request(INTERFACE.mac.unwrap(), ip_src, ip_dst);
    let _ = CHPAIR.tx.lock().unwrap().send_to(&pkt, None).unwrap();
}

fn send_arp_reply(mac_dst: MacAddr, ip_src: Ipv4Addr, ip_dst: Ipv4Addr) {
    debug!("send arp reply from {} to {}", ip_src, ip_dst);
    let pkt = net::arp::build_arp_reply(INTERFACE.mac.unwrap(), mac_dst, ip_src, ip_dst);
    let _ = CHPAIR.tx.lock().unwrap().send_to(&pkt, None).unwrap();
}

/// return icmp packet id
fn send_icmp_request(mac_dst: MacAddr, ip_src: Ipv4Addr, ip_dst: Ipv4Addr) -> u16 {
    debug!("send icmp echo request from {} to {}", ip_src, ip_dst);
    let packet_id = rand::random::<u16>();
    let pkt = net::icmp::build_icmp_packet(INTERFACE.mac.unwrap(), mac_dst, ip_src, ip_dst, packet_id);
    let _ = CHPAIR.tx.lock().unwrap().send_to(&pkt, None).unwrap();
    packet_id
}
