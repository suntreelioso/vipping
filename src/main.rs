use std::{
    net::Ipv4Addr,
    process::{ExitCode, exit},
};

use clap::{Parser, arg};
use pnet::datalink::{self};

mod arp;
mod icmp;

fn main() -> ExitCode {
    let args = Args::parse();
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == args.interface)
        .unwrap_or_else(|| {
            println!("Error: Interface not found");
            exit(1);
        });

    let mac_dst = if args.gateway != None {
        match arp::get_target_mac_by_arp(&interface, args.source, args.gateway.unwrap(), Some(args.timeout)) {
            Ok(mac) => mac,
            Err(()) => {
                println!("Error: Failed to get gateway MAC address");
                return ExitCode::FAILURE;
            }
        }
    } else {
        match arp::get_target_mac_by_arp(&interface, args.source, args.destination, Some(args.timeout)) {
            Ok(mac) => mac,
            Err(()) => {
                println!("Error: Failed to get target MAC address");
                return ExitCode::FAILURE;
            }
        }
    };

    // println!("IP: {} -> MAC: {}", args.destination, mac_dst);
    match icmp::send_icmp_packet(&interface, mac_dst, args.source, args.destination, Some(args.timeout)) {
        Ok(t) => {
            println!("{} ms", t.as_micros() as f64 / 1000.0);
        }
        Err(_) => {
            println!("Error: Could not send ICMP echo request");
            return ExitCode::FAILURE;
        }
    };
    ExitCode::SUCCESS
}

#[derive(Parser, Debug)]
#[command(about)]
struct Args {
    /// Local interface
    #[arg(short, long)]
    interface: String,

    /// Source IP
    #[arg(short, long)]
    source: Ipv4Addr,

    /// Destination IP
    #[arg(short, long)]
    destination: Ipv4Addr,

    /// Gateway IP
    #[arg(short, long, default_value = None)]
    gateway: Option<Ipv4Addr>,

    /// Timeout in seconds
    #[arg(short, long, default_value_t = 1)]
    timeout: u64,
}
