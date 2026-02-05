// src/utils.rs
use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MessageType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    Data = 4,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(MessageType::HandshakeInitiation),
            2 => Some(MessageType::HandshakeResponse),
            3 => Some(MessageType::CookieReply),
            4 => Some(MessageType::Data),
            _ => None,
        }
    }
}

pub const PROTOCOL_NAME: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
pub const IDENTIFIER: &[u8] = b"WireGuard v1 zx2c4 Jason@zx2c4.com";
pub const LABEL_MAC1: &[u8] = b"mac1----";
pub const LABEL_COOKIE: &[u8] = b"cookie--";
pub const WINDOW_SIZE: usize = 2048;

pub fn constant_time_equals(a: &Bytes, b: &Bytes) -> bool {
    if a.len() != b.len() {
        false
    } else {
        a.iter().zip(b.iter()).fold(0u8, |acc, (&x, &y)| acc | (x ^ y)) == 0
    }
}

pub struct IPPacketUtils;

impl IPPacketUtils {
    pub fn get_destination_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() { return None; }
        let version = (packet[0] >> 4) as u8;
        match version {
            4 => {
                if packet.len() < 20 { None } else {
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(&packet[16..20]);
                    Some(IpAddr::V4(Ipv4Addr::from(ip)))
                }
            }
            6 => {
                if packet.len() < 40 { None } else {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&packet[24..40]);
                    Some(IpAddr::V6(Ipv6Addr::from(ip)))
                }
            }
            _ => None,
        }
    }

    pub fn get_source_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() { return None; }
        let version = (packet[0] >> 4) as u8;
        match version {
            4 => {
                if packet.len() < 20 { None } else {
                    let mut ip = [0u8; 4];
                    ip.copy_from_slice(&packet[12..16]);
                    Some(IpAddr::V4(Ipv4Addr::from(ip)))
                }
            }
            6 => {
                if packet.len() < 40 { None } else {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(&packet[8..24]);
                    Some(IpAddr::V6(Ipv6Addr::from(ip)))
                }
            }
            _ => None,
        }
    }
}

//NEW MEMORY POOL SYSTEM
pub struct BufferPool {
    pool: Mutex<Vec<Vec<u8>>>,
    capacity: usize,
}

impl BufferPool {
    pub fn new(capacity: usize) -> Self {
        Self {
            pool: Mutex::new(Vec::new()),
            capacity,
        }
    }

    pub fn acquire(&self) -> Vec<u8> {
        let mut guard = self.pool.lock().unwrap();
        if let Some(mut buf) = guard.pop() {
            buf.clear(); // Reset length to 0, capacity remains
            buf
        } else {
            Vec::with_capacity(self.capacity)
        }
    }

    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() >= self.capacity {
            let mut guard = self.pool.lock().unwrap();
            // Cap the pool size to prevent infinite growth if bursts happen
            if guard.len() < 1000 {
                guard.push(buf);
            }
        }
    }
}