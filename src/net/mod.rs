#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use pnet::datalink::{Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface, channel};

pub mod arp;
pub mod icmp;

const RW_BUFFER_SIZE: usize = 256;

pub type Tx = Arc<Mutex<Box<dyn DataLinkSender>>>;
pub type Rx = Mutex<Box<dyn DataLinkReceiver>>;

pub struct ChannelPair {
    pub tx: Tx,
    pub rx: Rx,
}

pub fn get_interface_by_name(name: &str) -> Option<NetworkInterface> {
    let interfaces = pnet::datalink::interfaces();
    for interface in interfaces {
        if interface.name == name {
            return Some(interface);
        }
    }
    None
}

pub fn get_channel(interface: &NetworkInterface) -> Result<ChannelPair, ()> {
    let mut config = Config::default();
    config.read_buffer_size = RW_BUFFER_SIZE;
    config.write_buffer_size = RW_BUFFER_SIZE;

    match channel(interface, config) {
        Ok(Channel::Ethernet(tx, rx)) => Ok(ChannelPair {
            tx: Arc::new(Mutex::new(tx)),
            rx: Mutex::new(rx),
        }),
        _ => {
            println!("error: Failed to create raw socket");
            Err(())
        }
    }
}
