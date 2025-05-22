#![allow(dead_code)]

use std::{net::Ipv4Addr, time::SystemTime};

use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
pub(crate) struct PingArgs {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub timeout: u64,
}

#[derive(Serialize)]
pub(crate) struct PingResponse<'a> {
    pub code: i32,
    pub time_ms: f64,
    pub info: &'a PingArgs,
}

#[derive(Clone)]
pub struct PingIdRecordEntry {
    id: u16,
    time: SystemTime,
}

impl PingIdRecordEntry {
    pub fn new(id: u16, time: SystemTime) -> Self {
        Self { id, time }
    }

    pub fn equals(&self, id: u16) -> bool {
        self.id == id
    }

    pub fn get_time_elapsed_ms(&self) -> f64 {
        self.time.elapsed().unwrap().as_micros() as f64 / 1000.0
    }
}
