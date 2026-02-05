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
use dashmap::DashMap;
use log::{debug, error, info, trace, warn};
use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;
use smol::net::UdpSocket;
use smol::Timer;
use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

//todo logger on trace/debug levels are really talkative (To debug possible errors)
//Since protocol (AmneziaWG 1.0/1.3 implemented corre

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

pub struct Node<D: TunDevice + 'static> {
    pub iface_config: InterfaceConfig,
    pub(crate) device: Arc<D>,
    pub peers_by_public_key: Arc<DashMap<Key, Arc<Peer<D>>>>,
    sessions: RwLock<HashMap<u32, Key>>,
    routing_table: RoutingTable<Arc<Peer<D>>>,
    pub(crate) server_private_key: Key,
    pub(crate) server_public_key: Key,
    pub(crate) cookie_generator: CookieGenerator,
    pub(crate) udp_socket: UdpSocket,
    print_stats: bool,
    #[cfg(feature = "amnezia")]
    pub(crate) amnezia_config: AmneziaConfig,
    pub(crate) buffer_pool: BufferPool,
}

fn human_time(ago_secs: i64) -> String {
    if ago_secs < 60 {
        format!("{}s", ago_secs)
    } else if ago_secs < 3600 {
        format!("{}m {}s", ago_secs / 60, ago_secs % 60)
    } else if ago_secs < 86400 {
        format!("{}h {}m", ago_secs / 3600, (ago_secs % 3600) / 60)
    } else {
        format!("{}d {}h", ago_secs / 86400, (ago_secs % 86400) / 3600)
    }
}

fn human_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;
    const EB: u64 = TB * 1024;
    // Let me know if you download too much torrents and you need value in Petabytes

    if bytes < KB {
        format!("{} B", bytes)
    } else if bytes < MB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else if bytes < GB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes < TB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes < EB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else {
        format!("{:.2} EB", bytes as f64 / EB as f64)
    }
}

impl<D: TunDevice + 'static> Node<D> {
    pub async fn new(
        iface_config: InterfaceConfig,
        peer_configs: Vec<PeerConfig>,
        device: Arc<D>,
        print_stats: bool,
    ) -> Arc<Self> {
        let private_key =
            Key::try_from_base64(&iface_config.private_key).expect("Invalid Private Key");
        let public_key = private_to_public_key(&private_key);
        let cookie_generator = CookieGenerator::new(public_key.clone());
        let socket = UdpSocket::bind(("0.0.0.0", iface_config.listen_port.unwrap_or(0)))
            .await
            .unwrap();
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

        #[cfg(feature = "amnezia")]
        info!("AmneziaWG Config Loaded: {:?}", amnezia_config);

        #[cfg(not(feature = "amnezia"))]
        let amnezia_config = AmneziaConfig;

        let buffer_pool = BufferPool::new(MAX_UDP_PACKET);

        let self_arc = Arc::new(Self {
            iface_config,
            device,
            peers_by_public_key: peers_map.clone(),
            sessions: RwLock::new(HashMap::new()),
            routing_table,
            server_private_key: private_key,
            server_public_key: public_key,
            cookie_generator,
            udp_socket: socket,
            print_stats,
            #[cfg(feature = "amnezia")]
            amnezia_config,
            buffer_pool,
        });

        for peer_config in peer_configs {
            let peer = Peer::new(self_arc.clone(), peer_config.clone());
            let pk = peer.public_key.clone();
            peers_map.insert(pk, peer.clone());
            for allowed in peer.peer_config.allowed_ips.clone() {
                self_arc.routing_table.insert(&allowed, peer.clone());
            }
        }
        self_arc
    }

    #[cfg(feature = "amnezia")]
    pub fn random_padding(&self, len: usize) -> Vec<u8> {
        let mut padding = vec![0u8; len];
        if len > 0 {
            OsRng.fill_bytes(&mut padding);
        }
        padding
    }

    #[cfg(feature = "amnezia")]
    pub fn random_header(&self, range: &Range) -> u32 {
        if range.min == range.max {
            range.min
        } else {
            let mut rng = OsRng;
            rng.gen_range(range.min..=range.max)
        }
    }

    pub async fn start(self: Arc<Self>) {
        let n1 = self.clone();
        smol::spawn(async move { n1.udp_server().await }).detach();
        let n2 = self.clone();
        smol::spawn(async move { n2.tun_reader().await }).detach();
        let n3 = self.clone();
        smol::spawn(async move { n3.peer_timers().await }).detach();
        if self.print_stats {
            let n4 = self.clone();
            smol::spawn(async move { n4.stats_dumper().await }).detach();
        }
    }

    async fn stats_dumper(&self) {
        let interface_name = self.device.name().to_string();
        let stats_path = format!("stats.{}.txt", interface_name);

        loop {
            Timer::after(Duration::from_secs(5)).await;
            let mut stats_file = File::create(&stats_path).ok();

            let mut output = String::new();
            output.push_str(&format!("interface: {}\n", self.device.name()));
            output.push_str(&format!(
                "  public key: {}\n",
                self.server_public_key.to_base64()
            ));
            output.push_str(&format!(
                "  listening port: {}\n\n",
                self.iface_config.listen_port.unwrap_or(0)
            ));

            let current_ms = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64;

            for entry in self.peers_by_public_key.iter() {
                let peer = entry.value();
                output.push_str(&format!("peer: {}\n", peer.public_key.to_base64()));
                let endpoint_str = peer
                    .current_endpoint
                    .read()
                    .unwrap()
                    .as_ref()
                    .map_or("(none)".to_string(), |addr| addr.to_string());
                output.push_str(&format!("  endpoint: {}\n", endpoint_str));
                let allowed: Vec<String> = peer
                    .peer_config
                    .allowed_ips
                    .iter()
                    .map(|c| format!("{}/{}", c.address, c.prefix))
                    .collect();
                output.push_str(&format!("  allowed ips: {}\n", allowed.join(", ")));

                let handshake_time_ms = peer.last_handshake_time.load(Ordering::Relaxed);
                let handshake_str = if handshake_time_ms == 0 {
                    "(never)".to_string()
                } else {
                    let ago_ms = current_ms - handshake_time_ms;
                    let ago_secs = ago_ms / 1000;
                    format!("{} seconds ago ({})", ago_secs, human_time(ago_secs))
                };
                output.push_str(&format!("  latest handshake: {}\n", handshake_str));

                let rx = peer.rx_bytes.load(Ordering::Relaxed);
                let tx = peer.tx_bytes.load(Ordering::Relaxed);
                output.push_str(&format!(
                    "  transfer: {} B received ({}), {} B sent ({})\n\n",
                    rx,
                    human_bytes(rx),
                    tx,
                    human_bytes(tx)
                ));
            }

            if let Some(file) = &mut stats_file {
                let _ = file.write_all(output.as_bytes());
                let _ = file.flush();
            }
        }
    }

    async fn udp_server(&self) {
        loop {
            let mut buf = self.buffer_pool.acquire();
            unsafe {
                buf.set_len(buf.capacity());
            }

            let (n, sender) = match self.udp_socket.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    error!("UDP recv error: {}", e);
                    self.buffer_pool.release(buf);
                    continue;
                }
            };

            if n < 4 {
                self.buffer_pool.release(buf);
                continue;
            }

            unsafe {
                buf.set_len(n);
            }
            let raw = Bytes::copy_from_slice(&buf);
            self.buffer_pool.release(buf);

            let mut msg = None;

            // -----------------------------------------------------------------
            // 1. Safety Check: Detect Standard WireGuard Packets
            // -----------------------------------------------------------------
            if raw.len() >= 4 && raw[1] == 0 && raw[2] == 0 && raw[3] == 0 && (1..=4).contains(&raw[0]) {
                #[cfg(feature = "amnezia")]
                {
                    warn!("Received STANDARD WireGuard packet (Type {}) from {}. Client might have Amnezia disabled or config mismatch!", raw[0], sender);
                }

                if let Some(m) = self.try_parse_standard(&raw) {
                    trace!("Parsed Standard WireGuard message type {} from {}", raw[0], sender);
                    msg = Some(m);
                }
            }

            // -----------------------------------------------------------------
            // 2. Parse AmneziaWG Packets
            // -----------------------------------------------------------------
            #[cfg(feature = "amnezia")]
            if msg.is_none() {
                if let Some(m) = self.try_parse_obfuscated_packet(&raw, n) {
                    debug!("Parsed AmneziaWG obfuscated message from {}", sender);
                    msg = Some(m);
                }
            }

            // -----------------------------------------------------------------
            // 3. Process Message
            // -----------------------------------------------------------------
            if let Some(m) = msg {
                if let Some(peer) = self.find_peer_for_message(&m) {
                    // Valid packet for known session
                    peer.on_udp_packet(m, sender);
                } else {
                    // Packet parsed but Session ID is unknown
                    match &m {
                        Message::HandshakeInitiation(m_init) => {
                            debug!("Received HandshakeInitiation from unknown index, trying decryption...");
                            self.handle_unknown_initiation(m_init, sender).await;
                        }
                        Message::Data(m_data) => {
                            // Extract S2 value safely based on feature flags
                            #[cfg(feature = "amnezia")]
                            let s2_debug = self.amnezia_config.s2;
                            #[cfg(not(feature = "amnezia"))]
                            let s2_debug = 0;

                            let sessions = self.sessions.read().unwrap();
                            let active_ids: Vec<u32> = sessions.keys().cloned().collect();

                            warn!(
                                "REJECTED Data Packet from {}. Client sent SessionID: {}. Server has Active SessionIDs: {:?}. \n\
                                 Possible Cause: Client 'S2' (Response Padding) config does not match Server 'S2' ({}).",
                                sender,
                                m_data.receiver_index,
                                active_ids,
                                s2_debug
                            );
                        }
                        Message::HandshakeResponse(_) => {
                            trace!("Received HandshakeResponse for unknown session from {}", sender);
                        }
                        Message::CookieReply(_) => {
                            trace!("Received CookieReply for unknown session from {}", sender);
                        }
                    }
                }
            } else {
                trace!("Failed to parse packet from {} (len={})", sender, n);
            }
        }
    }

    async fn handle_unknown_initiation(&self, m: &HandshakeInitiationMessage, sender: SocketAddr) {
        let mut state = HandshakeState::new(
            hash(&[PROTOCOL_NAME]),
            hash(&[&hash(&[PROTOCOL_NAME])[..], IDENTIFIER]),
        );
        state.mix_hash(&self.server_public_key.0);
        state.mix_hash(&m.unencrypted_ephemeral.0);
        state.chaining_key = kdf1(&state.chaining_key, &m.unencrypted_ephemeral.0);
        let shared1 = x25519(&self.server_private_key, &m.unencrypted_ephemeral);
        let (_ck1, key1) = kdf2(&state.chaining_key, &shared1);
        let decrypted = chacha20_poly1305_decrypt(&key1, 0, &m.encrypted_static, &state.hash);

        if let Some(static_key_bytes) = decrypted {
            let key = Key(static_key_bytes);
            if let Some(peer) = self.peers_by_public_key.get(&key) {
                info!("Decrypted HandshakeInitiation for peer {}", key.to_base64());
                peer.on_udp_packet(Message::HandshakeInitiation(m.clone()), sender);
            } else {
                warn!("Decrypted Initiation, but peer {} not found in config.", key.to_base64());
            }
        } else {
            trace!("Failed to decrypt HandshakeInitiation from {}", sender);
        }
    }

    fn try_parse_standard(&self, raw: &Bytes) -> Option<Message> {
        let msg_type = MessageType::from_u8(raw[0])?;
        let min_len = match msg_type {
            MessageType::HandshakeInitiation => 148,
            MessageType::HandshakeResponse => 92,
            MessageType::CookieReply => 64,
            MessageType::Data => 32,
        };
        if raw.len() < min_len {
            return None;
        }

        match msg_type {
            MessageType::HandshakeInitiation => Some(Message::HandshakeInitiation(
                HandshakeInitiationMessage::from_bytes(raw),
            )),
            MessageType::HandshakeResponse => Some(Message::HandshakeResponse(
                HandshakeResponseMessage::from_bytes(raw),
            )),
            MessageType::CookieReply => Some(Message::CookieReply(
                CookieReplyMessage::from_bytes(raw)
            )),
            MessageType::Data => Some(Message::Data(
                DataMessage::from_bytes(raw)
            )),
        }
    }

    #[cfg(feature = "amnezia")]
    fn try_parse_obfuscated_packet(&self, raw: &[u8], n: usize) -> Option<Message> {
        let am = &self.amnezia_config;

        // A. Init (S1 + H1)
        let expected_len = 148 + am.s1 as usize;
        if n == expected_len {
            let offset = am.s1 as usize;
            if offset + 4 <= n {
                let magic = u32::from_le_bytes([raw[offset], raw[offset+1], raw[offset+2], raw[offset+3]]);
                if am.h1.contains(magic) {
                    let mut payload_with_header = vec![0u8; n - offset];
                    payload_with_header.copy_from_slice(&raw[offset..]);
                    let bytes = Bytes::from(payload_with_header);

                    let mut msg = HandshakeInitiationMessage::from_bytes(&bytes);
                    msg.wire_header = magic;
                    return Some(Message::HandshakeInitiation(msg));
                }
            }
        }

        // B. Response (S2 + H2)
        let expected_len = 92 + am.s2 as usize;
        if n == expected_len {
            let offset = am.s2 as usize;
            if offset + 4 <= n {
                let magic = u32::from_le_bytes([raw[offset], raw[offset+1], raw[offset+2], raw[offset+3]]);
                if am.h2.contains(magic) {
                    let mut payload_with_header = vec![0u8; n - offset];
                    payload_with_header.copy_from_slice(&raw[offset..]);
                    let bytes = Bytes::from(payload_with_header);

                    let mut msg = HandshakeResponseMessage::from_bytes(&bytes);
                    msg.wire_header = magic;
                    return Some(Message::HandshakeResponse(msg));
                }
            }
        }

        // C. Transport/Cookie (H4/H3)
        if n >= 32 {
            let magic = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]);

            if n == 64 && am.h3.contains(magic) {
                return Some(Message::CookieReply(CookieReplyMessage::from_bytes(
                    &Bytes::copy_from_slice(raw),
                )));
            }

            if am.h4.contains(magic) {
                return Some(Message::Data(DataMessage::from_bytes(
                    &Bytes::copy_from_slice(raw),
                )));
            }
        }
        None
    }

    #[cfg(not(feature = "amnezia"))]
    fn try_parse_obfuscated_packet(&self, _raw: &[u8], _n: usize) -> Option<Message> {
        None
    }

    pub async fn send_udp_packet(&self, data: Bytes, destination: SocketAddr) {
        if let Err(e) = self.udp_socket.send_to(&data, destination).await {
            error!("Failed to send UDP packet to {}: {}", destination, e);
        }
    }

    fn find_peer_for_message(&self, msg: &Message) -> Option<Arc<Peer<D>>> {
        match msg {
            Message::HandshakeInitiation(_m) => None,
            Message::HandshakeResponse(m) => self.get_peer_by_session(m.receiver_index),
            Message::CookieReply(m) => self.get_peer_by_session(m.receiver_index),
            Message::Data(m) => self.get_peer_by_session(m.receiver_index),
        }
    }

    fn get_peer_by_session(&self, session_index: u32) -> Option<Arc<Peer<D>>> {
        let sessions = self.sessions.read().unwrap();
        sessions
            .get(&session_index)
            .and_then(|pk| self.peers_by_public_key.get(pk).map(|p| p.value().clone()))
    }

    async fn tun_reader(&self) {
        loop {
            let mut buf = self.buffer_pool.acquire();
            unsafe {
                buf.set_len(buf.capacity());
            }

            let n = match self.device.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    error!("TUN read error: {}", e);
                    self.buffer_pool.release(buf);
                    continue;
                }
            };
            unsafe {
                buf.set_len(n);
            }

            if let Some(dest) = IPPacketUtils::get_destination_address(&buf) {
                if let Some(peer) = self.routing_table.find_best_match(dest) {
                    peer.on_tun_packet(buf);
                } else {
                    // No route found
                    self.buffer_pool.release(buf);
                }
            } else {
                // Not IP packet
                self.buffer_pool.release(buf);
            }
        }
    }

    async fn peer_timers(&self) {
        loop {
            Timer::after(Duration::from_secs(1)).await;
            let peers: Vec<Arc<Peer<D>>> = self
                .peers_by_public_key
                .iter()
                .map(|p| p.value().clone())
                .collect();
            for peer in peers {
                peer.tick();
            }
        }
    }

    pub fn is_under_load(&self) -> bool {
        false
    }

    pub fn validate_packet_source(&self, source_ip: std::net::IpAddr, peer: &Peer<D>) -> bool {
        for cidr in &peer.peer_config.allowed_ips {
            match (source_ip, cidr.address) {
                (std::net::IpAddr::V4(s), std::net::IpAddr::V4(n)) => {
                    if cidr.prefix == 0 { return true; }
                    let mask = !0u32 << (32 - cidr.prefix);
                    let s_int: u32 = s.into();
                    let n_int: u32 = n.into();
                    if (s_int & mask) == (n_int & mask) { return true; }
                }
                (std::net::IpAddr::V6(s), std::net::IpAddr::V6(n)) => {
                    if cidr.prefix == 0 { return true; }
                    let s_oct = s.octets();
                    let n_oct = n.octets();
                    let bytes = cidr.prefix as usize / 8;
                    let bits = cidr.prefix as usize % 8;
                    if s_oct[..bytes] != n_oct[..bytes] { continue; }
                    if bits > 0 {
                        let mask = 0xFFu8 << (8 - bits);
                        if (s_oct[bytes] & mask) != (n_oct[bytes] & mask) { continue; }
                    }
                    return true;
                }
                _ => continue,
            }
        }
        false
    }

    pub fn register_session(&self, session_index: u32, public_key: &Key) {
        self.sessions
            .write()
            .unwrap()
            .insert(session_index, public_key.clone());
    }

    pub fn remove_session(&self, session_id: u32) {
        self.sessions.write().unwrap().remove(&session_id);
    }

    pub fn find_available_index(&self) -> u32 {
        let mut rng = OsRng;
        loop {
            let index = rng.gen_range(0..u32::MAX);
            if index != 0 && !self.sessions.read().unwrap().contains_key(&index) {
                return index;
            }
        }
    }

    pub fn decrypt_cookie(
        &self,
        msg: &CookieReplyMessage,
        mac1: &Bytes,
        pub_key: &Key,
    ) -> Option<Bytes> {
        let cookie_key = Key(hash(&[LABEL_COOKIE, &pub_key.0]));
        xchacha20_poly1305_decrypt(&cookie_key, &msg.nonce, &msg.encrypted_cookie, mac1)
    }
}