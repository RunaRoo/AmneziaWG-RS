// src/node.rs
use super::config::*;
use super::cryptography::*;
use super::device::*;
use super::message::*;
use super::noise::*;
use super::peer::*;
use super::routing::*;
use super::utils::*;
use bytes::Bytes;
use smol::channel::{bounded, Receiver, Sender};
use dashmap::DashMap;
use log::{debug, error, info, trace, warn};
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;
use smol::net::UdpSocket;
use smol::Timer;
use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_UDP_PACKET: usize = 65535;

#[derive(Clone, Copy, Debug, Default)]
pub struct Range {
    pub min: u32,
    pub max: u32,
}

impl Range {
    pub fn contains(&self, val: u32) -> bool {
        val >= self.min && val <= self.max
    }
}

fn parse_range(s: &str) -> Range {
    if let Some((min_str, max_str)) = s.split_once('-') {
        let min = min_str.trim().parse::<u32>().unwrap_or(0);
        let max = max_str.trim().parse::<u32>().unwrap_or(0);
        if min <= max {
            return Range { min, max };
        }
    }
    let v = s.parse::<u32>().unwrap_or(0);
    Range { min: v, max: v }
}

#[cfg(feature = "amnezia")]
#[derive(Debug, Default)]
pub struct AmneziaConfig {
    pub jc: u32,
    pub jmin: usize,
    pub jmax: usize,
    pub s1: usize,
    pub s2: usize,
    pub h1: Range,
    pub h2: Range,
    pub h3: Range,
    pub h4: Range,
}

#[cfg(not(feature = "amnezia"))]
#[derive(Debug, Default)]
pub struct AmneziaConfig;

fn human_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    if bytes < KB { format!("{} B", bytes) }
    else if bytes < MB { format!("{:.2} KB", bytes as f64 / KB as f64) }
    else if bytes < GB { format!("{:.2} MB", bytes as f64 / MB as f64) }
    else { format!("{:.2} GB", bytes as f64 / GB as f64) }
}

pub struct Node<D: TunDevice + 'static> {
    pub iface_config: InterfaceConfig,
    pub(crate) device: Arc<D>,
    pub peers_by_public_key: Arc<DashMap<Key, Arc<Peer<D>>>>,
    sessions: DashMap<u32, Key>,
    route_cache: DashMap<IpAddr, Arc<Peer<D>>>,
    routing_table: RoutingTable<Arc<Peer<D>>>,
    pub(crate) server_private_key: Key,
    pub(crate) server_public_key: Key,
    pub(crate) cookie_generator: CookieGenerator,
    pub(crate) udp_socket: UdpSocket,
    print_stats: bool,
    #[cfg(feature = "amnezia")]
    pub(crate) amnezia_config: AmneziaConfig,
    pub(crate) buffer_pool: Arc<BufferPool>,
    num_workers: usize,
    max_buffer_bytes: u64,
}

impl<D: TunDevice + 'static> Node<D> {
    pub async fn new(
        iface_config: InterfaceConfig,
        peer_configs: Vec<PeerConfig>,
        device: Arc<D>,
        print_stats: bool,
        num_workers: usize,
        max_buffer_bytes: u64,
    ) -> Arc<Self> {
        let private_key = Key::try_from_base64(&iface_config.private_key).expect("Invalid Private Key");
        let public_key = private_to_public_key(&private_key);
        let cookie_generator = CookieGenerator::new(public_key.clone());
        let socket = UdpSocket::bind(("0.0.0.0", iface_config.listen_port.unwrap_or(0))).await.unwrap();

        let routing_table = RoutingTable::<Arc<Peer<D>>>::new();
        let peers_map = Arc::new(DashMap::new());

        #[cfg(feature = "amnezia")]
        let amnezia_config = AmneziaConfig {
            jc: iface_config.awg_jc,
            jmin: iface_config.awg_jmin as usize,
            jmax: iface_config.awg_jmax as usize,
            s1: iface_config.awg_s1 as usize,
            s2: iface_config.awg_s2 as usize,
            h1: parse_range(&iface_config.awg_h1),
            h2: parse_range(&iface_config.awg_h2),
            h3: parse_range(&iface_config.awg_h3),
            h4: parse_range(&iface_config.awg_h4),
        };
        #[cfg(not(feature = "amnezia"))]
        let amnezia_config = AmneziaConfig;

        let buffer_pool = Arc::new(BufferPool::new(max_buffer_bytes, MAX_UDP_PACKET));

        let self_arc = Arc::new(Self {
            iface_config,
            device,
            peers_by_public_key: peers_map.clone(),
            sessions: DashMap::new(),
            route_cache: DashMap::new(),
            routing_table,
            server_private_key: private_key,
            server_public_key: public_key,
            cookie_generator,
            udp_socket: socket,
            print_stats,
            #[cfg(feature = "amnezia")]
            amnezia_config,
            buffer_pool,
            num_workers: num_workers.max(1),
            max_buffer_bytes,
        });

        for peer_config in peer_configs {
            let peer = Peer::new(self_arc.clone(), peer_config.clone());
            peers_map.insert(peer.public_key.clone(), peer.clone());
            for allowed in &peer.peer_config.allowed_ips {
                self_arc.routing_table.insert(allowed, peer.clone());
            }
        }
        self_arc
    }

    #[cfg(feature = "amnezia")]
    pub fn random_padding(&self, len: usize) -> Vec<u8> {
        let mut padding = vec![0u8; len];
        if len > 0 { OsRng.fill_bytes(&mut padding); }
        padding
    }

    #[cfg(feature = "amnezia")]
    pub fn random_header(&self, range: &Range) -> u32 {
        if range.min == range.max { range.min }
        else { OsRng.gen_range(range.min..=range.max) }
    }

    pub async fn start(self: Arc<Self>) {
        let queue_depth = 10240; // High capacity for millions of clients
        let mut worker_senders = Vec::with_capacity(self.num_workers);

        for _ in 0..self.num_workers {
            let (tx, rx) = bounded::<(Bytes, SocketAddr)>(queue_depth);
            worker_senders.push(tx);
            let node = self.clone();
            smol::spawn(async move { node.packet_worker(rx).await }).detach();
        }

        smol::spawn(self.clone().udp_receiver(worker_senders)).detach();
        smol::spawn(self.clone().tun_reader()).detach();
        smol::spawn(self.clone().peer_timers()).detach();

        if self.print_stats {
            smol::spawn(self.clone().stats_dumper()).detach();
        }
    }

    async fn udp_receiver(self: Arc<Self>, senders: Vec<Sender<(Bytes, SocketAddr)>>) {
        let num_shards = senders.len();
        loop {
            let mut buf = self.buffer_pool.acquire();
            unsafe { buf.set_len(buf.capacity()); }

            match self.udp_socket.recv_from(&mut buf).await {
                Ok((n, sender_addr)) if n >= 4 => {
                    unsafe { buf.set_len(n); }
                    let raw = Bytes::from(buf);

                    let mut hasher = DefaultHasher::new();
                    sender_addr.hash(&mut hasher);
                    let shard_idx = (hasher.finish() as usize) % num_shards;

                    // Await send for backpressure (prevents OOM under millions of clients)
                    let _ = senders[shard_idx].send((raw, sender_addr)).await;
                }
                _ => { self.buffer_pool.release(buf); }
            }
        }
    }

    async fn packet_worker(self: Arc<Self>, rx: Receiver<(Bytes, SocketAddr)>) {
        while let Ok((raw, sender)) = rx.recv().await {
            let mut msg = None;

            if raw.len() >= 4 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 && (1..=4).contains(&raw[0]) {
                msg = self.try_parse_standard(&raw);
            }

            #[cfg(feature = "amnezia")]
            if msg.is_none() {
                msg = self.try_parse_obfuscated_packet(&raw, raw.len());
            }

            if let Some(m) = msg {
                if let Some(peer) = self.find_peer_for_message(&m) {
                    peer.on_udp_packet(m, sender);
                } else if let Message::HandshakeInitiation(m_init) = m {
                    self.handle_unknown_initiation(&m_init, sender).await;
                }
            }
        }
    }

    async fn handle_unknown_initiation(&self, m: &HandshakeInitiationMessage, sender: SocketAddr) {
        let mut state = HandshakeState::new(hash(&[PROTOCOL_NAME]), hash(&[&hash(&[PROTOCOL_NAME])[..], IDENTIFIER]));
        state.mix_hash(&self.server_public_key.0);
        state.mix_hash(&m.unencrypted_ephemeral.0);
        state.chaining_key = kdf1(&state.chaining_key, &m.unencrypted_ephemeral.0);

        let shared1 = x25519(&self.server_private_key, &m.unencrypted_ephemeral);
        let (_ck1, key1) = kdf2(&state.chaining_key, &shared1);

        if let Some(static_key_bytes) = chacha20_poly1305_decrypt(&key1, 0, &m.encrypted_static, &state.hash) {
            let key = Key(static_key_bytes);
            if let Some(peer) = self.peers_by_public_key.get(&key) {
                peer.on_udp_packet(Message::HandshakeInitiation(m.clone()), sender);
            }
        }
    }

    fn try_parse_standard(&self, raw: &Bytes) -> Option<Message> {
        let msg_type = MessageType::from_u8(raw[0])?;
        match msg_type {
            MessageType::HandshakeInitiation if raw.len() >= 148 => Some(Message::HandshakeInitiation(HandshakeInitiationMessage::from_bytes(raw))),
            MessageType::HandshakeResponse if raw.len() >= 92 => Some(Message::HandshakeResponse(HandshakeResponseMessage::from_bytes(raw))),
            MessageType::CookieReply if raw.len() >= 64 => Some(Message::CookieReply(CookieReplyMessage::from_bytes(raw))),
            MessageType::Data if raw.len() >= 32 => Some(Message::Data(DataMessage::from_bytes(raw))),
            _ => None
        }
    }

    #[cfg(feature = "amnezia")]
    fn try_parse_obfuscated_packet(&self, raw: &[u8], n: usize) -> Option<Message> {
        let am = &self.amnezia_config;
        if n == 148 + am.s1 {
            let magic = u32::from_le_bytes([raw[am.s1], raw[am.s1+1], raw[am.s1+2], raw[am.s1+3]]);
            if am.h1.contains(magic) {
                let mut msg = HandshakeInitiationMessage::from_bytes(&Bytes::copy_from_slice(&raw[am.s1..]));
                msg.wire_header = magic;
                return Some(Message::HandshakeInitiation(msg));
            }
        }
        if n == 92 + am.s2 {
            let magic = u32::from_le_bytes([raw[am.s2], raw[am.s2+1], raw[am.s2+2], raw[am.s2+3]]);
            if am.h2.contains(magic) {
                let mut msg = HandshakeResponseMessage::from_bytes(&Bytes::copy_from_slice(&raw[am.s2..]));
                msg.wire_header = magic;
                return Some(Message::HandshakeResponse(msg));
            }
        }
        if n >= 32 {
            let magic = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);
            if n == 64 && am.h3.contains(magic) { return Some(Message::CookieReply(CookieReplyMessage::from_bytes(&Bytes::copy_from_slice(raw)))); }
            if am.h4.contains(magic) { return Some(Message::Data(DataMessage::from_bytes(&Bytes::copy_from_slice(raw)))); }
        }
        None
    }

    #[cfg(not(feature = "amnezia"))]
    fn try_parse_obfuscated_packet(&self, _: &[u8], _: usize) -> Option<Message> { None }

    pub async fn send_udp_packet(&self, data: Bytes, destination: SocketAddr) {
        let _ = self.udp_socket.send_to(&data, destination).await;
    }

    fn find_peer_for_message(&self, msg: &Message) -> Option<Arc<Peer<D>>> {
        let idx = match msg {
            Message::HandshakeResponse(m) => m.receiver_index,
            Message::CookieReply(m) => m.receiver_index,
            Message::Data(m) => m.receiver_index,
            _ => return None,
        };
        self.get_peer_by_session(idx)
    }

    fn get_peer_by_session(&self, session_index: u32) -> Option<Arc<Peer<D>>> {
        self.sessions.get(&session_index)
            .and_then(|pk| self.peers_by_public_key.get(pk.value()).map(|p| p.value().clone()))
    }

    async fn tun_reader(self: Arc<Self>) {
        loop {
            let mut buf = self.buffer_pool.acquire();
            unsafe { buf.set_len(buf.capacity()); }

            if let Ok(n) = self.device.read(&mut buf).await {
                unsafe { buf.set_len(n); }
                if let Some(dest) = IPPacketUtils::get_destination_address(&buf) {
                    if let Some(peer) = self.route_cache.get(&dest) {
                        peer.value().on_tun_packet(buf);
                        continue;
                    }
                    if let Some(peer) = self.routing_table.find_best_match(dest) {
                        self.route_cache.insert(dest, peer.clone());
                        peer.on_tun_packet(buf);
                    } else { self.buffer_pool.release(buf); }
                } else { self.buffer_pool.release(buf); }
            } else { self.buffer_pool.release(buf); }
        }
    }

    async fn peer_timers(self: Arc<Self>) {
        loop {
            Timer::after(Duration::from_secs(1)).await;
            for entry in self.peers_by_public_key.iter() {
                entry.value().tick();
            }
        }
    }

    async fn stats_dumper(self: Arc<Self>) {
        let stats_path = format!("stats.{}.txt", self.device.name());
        loop {
            Timer::after(Duration::from_secs(5)).await;
            if let Ok(mut file) = File::create(&stats_path) {
                let mut output = format!("interface: {}\nworkers: {}\n", self.device.name(), self.num_workers);
                for entry in self.peers_by_public_key.iter() {
                    let p = entry.value();
                    let ep = p.current_endpoint.read().unwrap().map_or("none".into(), |a| a.to_string());
                    output.push_str(&format!("peer: {}\n  rx/tx: {} / {}\n",
                                             p.public_key.to_base64(), human_bytes(p.rx_bytes.load(Ordering::Relaxed)), human_bytes(p.tx_bytes.load(Ordering::Relaxed))));
                }
                let _ = file.write_all(output.as_bytes());
            }
        }
    }

    pub fn is_under_load(&self) -> bool { false }

    pub fn validate_packet_source(&self, source_ip: IpAddr, peer: &Peer<D>) -> bool {
        // FIXED: Manual bitmask check for massive scalability
        peer.peer_config.allowed_ips.iter().any(|cidr| {
            match (source_ip, cidr.address) {
                (IpAddr::V4(s), IpAddr::V4(n)) => {
                    if cidr.prefix == 0 { return true; }
                    let mask = u32::MAX.checked_shl(32 - cidr.prefix as u32).unwrap_or(0);
                    (u32::from(s) & mask) == (u32::from(n) & mask)
                }
                (IpAddr::V6(s), IpAddr::V6(n)) => {
                    let s_oct = s.octets();
                    let n_oct = n.octets();
                    let full_bytes = cidr.prefix as usize / 8;
                    let remaining_bits = cidr.prefix as usize % 8;
                    if s_oct[..full_bytes] != n_oct[..full_bytes] { return false; }
                    if remaining_bits > 0 {
                        let mask = 0xFFu8 << (8 - remaining_bits);
                        (s_oct[full_bytes] & mask) == (n_oct[full_bytes] & mask)
                    } else { true }
                }
                _ => false
            }
        })
    }

    pub fn register_session(&self, session_index: u32, public_key: &Key) {
        self.sessions.insert(session_index, public_key.clone());
    }

    pub fn remove_session(&self, session_id: u32) {
        self.sessions.remove(&session_id);
    }

    pub fn find_available_index(&self) -> u32 {
        let mut rng = OsRng;
        loop {
            let index = rng.gen_range(1..u32::MAX);
            if !self.sessions.contains_key(&index) { return index; }
        }
    }

    pub fn decrypt_cookie(&self, msg: &CookieReplyMessage, mac1: &Bytes, pub_key: &Key) -> Option<Bytes> {
        let cookie_key = Key(hash(&[LABEL_COOKIE, &pub_key.0]));
        xchacha20_poly1305_decrypt(&cookie_key, &msg.nonce, &msg.encrypted_cookie, mac1)
    }
}