// src/peer.rs
use std::cmp::Ordering as CmpOrdering;
use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bitvec::prelude::*;
use bytes::{Bytes, BufMut};
use log::{error, info, warn, debug};
use smol::channel::{bounded, Receiver, Sender};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

use rand::rngs::OsRng;
use rand::Rng;
use rand::RngCore;

use crate::config::PeerConfig;
use crate::cryptography::*;
use crate::device::TunDevice; // Import Trait
use crate::message::*;
use crate::node::Node;
use crate::noise::*;
use crate::utils::{constant_time_equals, LABEL_MAC1, WINDOW_SIZE, IPPacketUtils, PROTOCOL_NAME, IDENTIFIER};

pub const REKEY_AFTER_TIME_MS: i64 = 120_000;
pub const REJECT_AFTER_TIME_MS: i64 = 180_000;
pub const REKEY_ATTEMPT_TIME_MS: i64 = 90_000;
pub const REKEY_TIMEOUT_MS: i64 = 5_000;
pub const KEEPALIVE_TIMEOUT_MS: i64 = 10_000;
pub const MAX_QUEUE_SIZE: usize = 1024;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_millis() as i64
}

pub struct KeyPair {
    pub send_key: Key,
    pub recv_key: Key,
    pub remote_index: u32,
    pub local_index: u32,
    pub created_at: i64,
    pub tx_nonce: AtomicU64,
    pub rx_replay_filter: ReplayFilter,
    pub last_packet_sent_timestamp: AtomicI64,
}

impl KeyPair {
    pub fn encrypt_data(&self, packet: &[u8]) -> Option<DataMessage> {
        let nonce = self.tx_nonce.fetch_add(1, Ordering::SeqCst);
        let encrypted = chacha20_poly1305_encrypt(&self.send_key, nonce, packet, &[])?;

        self.last_packet_sent_timestamp.store(now_ms(), Ordering::SeqCst);
        Some(DataMessage {
            receiver_index: self.remote_index,
            counter: nonce,
            encrypted_data: encrypted,
            wire_header: 4,  //Critical for Wireguard compatibility !1!1!1!1 (Header is 4 (deobf))
        })
    }

    pub fn decrypt_data(&self, message: &DataMessage) -> Option<Bytes> {
        if !self.rx_replay_filter.validate(message.counter) {
            return None;
        }
        chacha20_poly1305_decrypt(&self.recv_key, message.counter, &message.encrypted_data, &[])
    }
}

pub struct ReplayFilter {
    max_seq: AtomicI64,
    window: RwLock<BitVec<u8, Lsb0>>,
}

impl ReplayFilter {
    pub fn new() -> Self {
        Self {
            max_seq: AtomicI64::new(-1),
            window: RwLock::new(bitvec![u8, Lsb0; 0; WINDOW_SIZE]),
        }
    }

    pub fn validate(&self, seq: u64) -> bool {
        let seq_i64 = seq as i64;
        let mut guard = match self.window.write() {
            Ok(g) => g,
            Err(e) => {
                error!("ReplayFilter lock poisoned: recovering.");
                e.into_inner()
            }
        };

        let max = self.max_seq.load(Ordering::SeqCst);

        if seq_i64 > max {
            let diff = seq_i64 - max;
            if diff >= WINDOW_SIZE as i64 {
                guard.fill(false);
            } else {
                for i in 1..=diff {
                    let idx = ((max + i) % WINDOW_SIZE as i64) as usize;
                    guard.set(idx, false);
                }
            }
            self.max_seq.store(seq_i64, Ordering::SeqCst);
            let idx = (seq % WINDOW_SIZE as u64) as usize;
            guard.set(idx, true);
            true
        } else {
            let diff = max - seq_i64;
            if diff >= WINDOW_SIZE as i64 {
                return false;
            }
            let idx = (seq % WINDOW_SIZE as u64) as usize;
            if guard.get(idx).as_deref() == Some(&true) {
                return false;
            }
            guard.set(idx, true);
            true
        }
    }
}
//Peer is now async
pub struct Peer<D: TunDevice + 'static> {
    pub public_key: Key,
    pub current_endpoint: RwLock<Option<SocketAddr>>,
    last_packet_received_timestamp: AtomicI64,
    noise: Noise,

    current_key_pair: RwLock<Option<Arc<KeyPair>>>,
    next_key_pair: RwLock<Option<Arc<KeyPair>>>,

    handshake_secrets: RwLock<Option<HandshakeSecrets>>,
    last_initiation_message: RwLock<Option<HandshakeInitiationMessage>>,
    last_handshake_sent_timestamp: AtomicI64,
    is_handshake_in_progress: AtomicBool,

    mailbox: Sender<PeerEvent>,
    outbound_queue: Sender<Vec<u8>>,
    packet_queue: Mutex<VecDeque<Vec<u8>>>,

    //Node is now Node<D> (async)
    node: Arc<Node<D>>,
    pub peer_config: PeerConfig,

    last_activity: AtomicI64,
    keepalive_timeout_ms: i64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub last_handshake_time: AtomicI64,
}

impl<D: TunDevice + 'static> PartialEq for Peer<D> {
    fn eq(&self, other: &Self) -> bool {
        self.public_key == other.public_key
    }
}

impl<D: TunDevice + 'static> Peer<D> {
    // FIX: Constructor now takes Node<D>
    pub fn new(node: Arc<Node<D>>, peer_config: PeerConfig) -> Arc<Self> {
        let config_endpoint = peer_config.endpoint;
        let remote_public = Key::from_base64(&peer_config.public_key);
        let psk = peer_config.preshared_key.as_ref().map(|s| Key::from_base64(s));
        let noise = Noise::new(node.server_private_key.clone(), remote_public.clone(), psk);

        let (mailbox_tx, mailbox_rx) = bounded(1024);
        let (outbound_tx, outbound_rx) = bounded(2048);
        let keepalive_timeout = peer_config.persistent_keepalive.map(|k| k as i64 * 1000).unwrap_or(0);

        if let Some(ep) = config_endpoint {
            info!("Peer {}: Configured with ENDPOINT {}. Role: INITIATOR.", remote_public.to_base64(), ep);
        } else {
            info!("Peer {}: NO ENDPOINT configured. Role: RESPONDER (Passive).", remote_public.to_base64());
        }

        let peer = Arc::new(Self {
            public_key: remote_public,
            current_endpoint: RwLock::new(config_endpoint),
            last_packet_received_timestamp: AtomicI64::new(0),
            noise,
            current_key_pair: RwLock::new(None),
            next_key_pair: RwLock::new(None),
            handshake_secrets: RwLock::new(None),
            last_initiation_message: RwLock::new(None),
            last_handshake_sent_timestamp: AtomicI64::new(0),
            is_handshake_in_progress: AtomicBool::new(false),
            mailbox: mailbox_tx,
            outbound_queue: outbound_tx,
            packet_queue: Mutex::new(VecDeque::with_capacity(MAX_QUEUE_SIZE)),
            node,
            peer_config,
            last_activity: AtomicI64::new(now_ms()),
            keepalive_timeout_ms: keepalive_timeout,
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            last_handshake_time: AtomicI64::new(0),
        });

        let peer_clone = peer.clone();
        smol::spawn(async move { peer_clone.actor_loop(mailbox_rx).await }).detach();

        let peer_clone = peer.clone();
        smol::spawn(async move { peer_clone.outbound_loop(outbound_rx).await }).detach();

        if config_endpoint.is_some() {
            let p_init = peer.clone();
            smol::spawn(async move {
                let _ = p_init.mailbox.send(PeerEvent::InitHandshake).await;
            }).detach();
        }

        peer
    }

    pub fn on_udp_packet(&self, message: Message, sender: SocketAddr) {
        let _ = self.mailbox.try_send(PeerEvent::UdpPacket(message, sender));
    }

    pub fn on_tun_packet(&self, packet: Vec<u8>) {
        if let Err(_) = self.outbound_queue.try_send(packet.clone()) {
            self.node.buffer_pool.release(packet);
        }
    }

    pub fn tick(&self) {
        let _ = self.mailbox.try_send(PeerEvent::Tick);
    }

    fn update_endpoint(&self, sender: SocketAddr) {
        let mut guard = match self.current_endpoint.write() { Ok(g) => g, Err(e) => e.into_inner() };
        if *guard != Some(sender) {
            info!("Peer Roaming: Endpoint updated to {}", sender);
            *guard = Some(sender);
        }
    }

    pub fn queue_packet(&self, packet: Vec<u8>) {
        let mut queue = match self.packet_queue.lock() { Ok(g) => g, Err(e) => e.into_inner() };
        if queue.len() >= MAX_QUEUE_SIZE {
            if let Some(old) = queue.pop_front() {
                self.node.buffer_pool.release(old);
            }
        }
        queue.push_back(packet);
    }

    pub async fn flush_queue(&self) {
        let packets: Vec<Vec<u8>> = {
            let mut queue = match self.packet_queue.lock() { Ok(g) => g, Err(e) => e.into_inner() };
            if queue.is_empty() { return; }
            queue.drain(..).collect()
        };

        let current_kp_opt = match self.current_key_pair.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };
        let endpoint_opt = match self.current_endpoint.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };

        if let (Some(kp), Some(target)) = (current_kp_opt, endpoint_opt) {
            for packet in packets {
                if let Some(encrypted) = kp.encrypt_data(&packet) {
                    self.tx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);
                    self.send_data_packet(encrypted, target).await;
                }
                self.node.buffer_pool.release(packet);
            }
        } else {
            for p in packets {
                self.node.buffer_pool.release(p);
            }
        }
    }

    async fn actor_loop(&self, rx: Receiver<PeerEvent>) {
        while let Ok(event) = rx.recv().await {
            let result = match event {
                PeerEvent::UdpPacket(message, sender) => self.handle_udp_internal(message, sender).await,
                PeerEvent::Tick => self.handle_tick_internal().await,
                PeerEvent::InitHandshake => { self.initiate_handshake(None).await; Ok(()) },
            };
            if let Err(e) = result {
                error!("Peer Actor Error: {}", e);
            }
        }
    }

    async fn outbound_loop(&self, rx: Receiver<Vec<u8>>) {
        let mut last_handshake_check = 0;

        while let Ok(packet) = rx.recv().await {
            let now = now_ms();

            if (now - last_handshake_check) > 1000 {
                if self.should_initiate_handshake() {
                    let _ = self.mailbox.try_send(PeerEvent::InitHandshake);
                }
                last_handshake_check = now;
            }

            let (current, endpoint) = {
                let current_kp_guard = match self.current_key_pair.read() { Ok(g) => g, Err(e) => e.into_inner() };
                let endpoint_guard = match self.current_endpoint.read() { Ok(g) => g, Err(e) => e.into_inner() };
                (current_kp_guard.clone(), endpoint_guard.clone())
            };

            if let (Some(kp), Some(target)) = (current, endpoint) {
                let len = packet.len() as u64;
                if let Some(encrypted_msg) = kp.encrypt_data(&packet) {
                    self.tx_bytes.fetch_add(len, Ordering::Relaxed);
                    self.send_data_packet(encrypted_msg, target).await;
                }
                self.node.buffer_pool.release(packet);
            } else {
                self.queue_packet(packet);
            }
        }
    }

    //Amnezia Helper Methods

    #[cfg(feature = "amnezia")]
    async fn send_junk_packets(&self, endpoint: SocketAddr) {
        let am = &self.node.amnezia_config;

        for _ in 0..am.jc {
            let len = if am.jmin == am.jmax {
                am.jmin
            } else {
                let mut rng = OsRng;
                rng.gen_range(am.jmin..=am.jmax)
            };

            let mut junk = vec![0u8; len];
            OsRng.fill_bytes(&mut junk);
            let _ = self.node.udp_socket.send_to(&junk, endpoint).await;
        }
    }

    #[cfg(feature = "amnezia")]
    async fn send_obfuscated_handshake_initiation(&self, msg: HandshakeInitiationMessage, endpoint: SocketAddr) {
        let am = &self.node.amnezia_config;
        let standard = msg.to_bytes();
        let payload = &standard[4..];
        let padding = self.node.random_padding(am.s1 as usize);
        let header = self.node.random_header(&am.h1);

        let mut full = Vec::with_capacity(padding.len() + 4 + payload.len());
        full.extend(padding);
        full.put_u32_le(header);
        full.extend_from_slice(payload);
        self.node.send_udp_packet(full.into(), endpoint).await;
    }

    #[cfg(feature = "amnezia")]
    async fn send_obfuscated_handshake_response(&self, msg: HandshakeResponseMessage, endpoint: SocketAddr) {
        let am = &self.node.amnezia_config;
        let standard = msg.to_bytes();
        let payload = &standard[4..];
        let padding = self.node.random_padding(am.s2 as usize);
        let header = self.node.random_header(&am.h2);

        let mut full = Vec::with_capacity(padding.len() + 4 + payload.len());
        full.extend(padding);
        full.put_u32_le(header);
        full.extend_from_slice(payload);
        self.node.send_udp_packet(full.into(), endpoint).await;
    }

    #[cfg(feature = "amnezia")]
    async fn send_obfuscated_data(&self, msg: DataMessage, endpoint: SocketAddr) {
        let am = &self.node.amnezia_config;

        // 1. Generate the Amnezia Header (H4)
        let header = self.node.random_header(&am.h4);

        // 2. Calculate exact buffer size
        // Header(4) + Index(4) + Counter(8) + EncryptedData(N)
        let payload_len = msg.encrypted_data.len();
        let mut full = Vec::with_capacity(4 + 4 + 8 + payload_len);

        // 3. Construct packet strictly (Little Endian)
        full.put_u32_le(header);              // Bytes 0-3: H4 Magic
        full.put_u32_le(msg.receiver_index);  // Bytes 4-7: Receiver Index
        full.put_u64_le(msg.counter);         // Bytes 8-15: Counter
        full.extend_from_slice(&msg.encrypted_data); // Bytes 16+: Data + Tag

        // 4. Send
        self.node.send_udp_packet(full.into(), endpoint).await;
    }
    /* //Todo: Not working
    #[cfg(feature = "amnezia")]
    async fn send_obfuscated_data(&self, msg: DataMessage, endpoint: SocketAddr) {
        let am = &self.node.amnezia_config;
        let standard = msg.to_bytes();
        let payload = &standard[4..];
        let header = self.node.random_header(&am.h4);

        let mut full = Vec::with_capacity(4 + payload.len());
        full.put_u32_le(header);
        full.extend_from_slice(payload);
        self.node.send_udp_packet(full.into(), endpoint).await;
    }
     */

    #[cfg(feature = "amnezia")]
    async fn send_obfuscated_cookie(&self, msg: CookieReplyMessage, endpoint: SocketAddr) {
        let am = &self.node.amnezia_config;
        let standard = msg.to_bytes();
        let payload = &standard[4..];
        let header = self.node.random_header(&am.h3);

        let mut full = Vec::with_capacity(4 + payload.len());
        full.put_u32_le(header);
        full.extend_from_slice(payload);
        self.node.send_udp_packet(full.into(), endpoint).await;
    }

    async fn send_data_packet(&self, msg: DataMessage, target: SocketAddr) {
        #[cfg(not(feature = "amnezia"))]
        { self.node.send_udp_packet(msg.to_bytes(), target).await; }

        #[cfg(feature = "amnezia")]
        {
            self.send_obfuscated_data(msg, target).await;
        }
    }

    async fn handle_udp_internal(&self, message: Message, sender: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let now = now_ms();
        self.last_packet_received_timestamp.store(now, Ordering::SeqCst);
        self.last_activity.store(now, Ordering::SeqCst);

        match message {
            Message::HandshakeInitiation(msg) => self.on_handshake_initiation(msg, sender).await?,
            Message::HandshakeResponse(msg) => self.on_handshake_response(msg, sender).await?,
            Message::CookieReply(msg) => self.on_cookie_reply(msg).await?,
            Message::Data(msg) => self.on_data_message(msg, sender).await?,
        }
        Ok(())
    }

    async fn on_handshake_initiation(&self, msg: HandshakeInitiationMessage, sender: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        if self.is_handshake_in_progress.load(Ordering::SeqCst) {
            let self_pub = self.node.server_public_key.to_base64();
            let peer_pub = self.public_key.to_base64();

            if self_pub > peer_pub {
                info!("Handshake Collision: Aborting our handshake, accepting theirs.");
                self.is_handshake_in_progress.store(false, Ordering::SeqCst);
            } else {
                return Ok(());
            }
        }

        let mac1_key = hash(&[LABEL_MAC1, &self.node.server_public_key.0]);
        if !constant_time_equals(&mac(&mac1_key, &[&msg.bytes_for_macs()]), &msg.mac1) {
            return Ok(());
        }

        if self.node.is_under_load() {
            if let Some(reply) = self.node.cookie_generator.create_cookie_reply(&msg, sender.to_string().as_bytes()) {
                self.send_cookie_reply(reply, sender).await;
            }
            return Ok(());
        }

        let (state, err) = self.validate_and_decrypt_initiation(&msg);
        if let Some(state) = state {
            self.update_endpoint(sender);
            self.send_handshake_response(&state, &msg, sender).await?;
        } else {
            warn!("Invalid initiation from {}: {}", sender, err.unwrap_or("unknown".to_string()));
        }
        Ok(())
    }

    async fn send_cookie_reply(&self, msg: CookieReplyMessage, target: SocketAddr) {
        #[cfg(not(feature = "amnezia"))]
        { self.node.send_udp_packet(msg.to_bytes(), target).await; }

        #[cfg(feature = "amnezia")]
        {
            self.send_obfuscated_cookie(msg, target).await;
        }
    }

    async fn send_handshake_response(&self, state: &HandshakeState, msg: &HandshakeInitiationMessage, sender: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let mut ck = state.chaining_key.clone();
        let mut hs = state.hash.clone();

        let (ephemeral_private, ephemeral_public) = generate_keypair();
        hs = hash(&[&hs[..], &ephemeral_public.0]);
        ck = kdf1(&ck, &ephemeral_public.0);

        let shared1 = x25519(&ephemeral_private, &msg.unencrypted_ephemeral);
        ck = kdf1(&ck, &shared1);

        let shared2 = x25519(&ephemeral_private, &self.public_key);
        ck = kdf1(&ck, &shared2);

        let psk = self.noise.preshared_key.as_ref().map(|k| k.0.clone()).unwrap_or(Bytes::from(vec![0; 32]));
        let (ck3, tau, k) = kdf3(&ck, &psk);
        ck = ck3;
        hs = hash(&[&hs[..], &tau.0]);

        let encrypted_nothing = chacha20_poly1305_encrypt(&k, 0, &[], &hs).ok_or("Encryption failed")?;

        let local_index = self.node.find_available_index();
        self.node.register_session(local_index, &self.public_key);

        #[cfg(feature = "amnezia")]
        let wire_header = self.node.random_header(&self.node.amnezia_config.h2);
        #[cfg(not(feature = "amnezia"))]
        let wire_header = 2u32;

        let mut response = HandshakeResponseMessage {
            sender_index: local_index,
            receiver_index: msg.sender_index,
            unencrypted_ephemeral: ephemeral_public,
            encrypted_nothing: Bytes::from(encrypted_nothing),
            mac1: Bytes::from(vec![0; 16]),
            mac2: Bytes::from(vec![0; 16]),
            wire_header,
        };

        let (recv_key_bytes, send_key) = kdf2(&ck, &Bytes::new());

        let key_pair = KeyPair {
            send_key,
            recv_key: Key(recv_key_bytes),
            remote_index: msg.sender_index,
            local_index,
            created_at: now_ms(),
            tx_nonce: AtomicU64::new(0),
            rx_replay_filter: ReplayFilter::new(),
            last_packet_sent_timestamp: AtomicI64::new(0),
        };

        match self.next_key_pair.write() {
            Ok(mut g) => *g = Some(Arc::new(key_pair)),
            Err(e) => *e.into_inner() = Some(Arc::new(key_pair)),
        }
        
        let secrets = HandshakeSecrets {
            chaining_key: ck,
            hash: hs,
            ephemeral_private,
            local_index,
            remote_ephemeral: Some(msg.unencrypted_ephemeral.clone()),
            remote_index: msg.sender_index,
            remote_static: self.public_key.clone(),
        };

        {
            let mut guard = match self.handshake_secrets.write() { Ok(g) => g, Err(e) => e.into_inner() };
            if let Some(old) = guard.as_ref() {
                self.node.remove_session(old.local_index);
            }
            *guard = Some(secrets);
        }

        self.update_handshake_time();

        let mac1_key = hash(&[LABEL_MAC1, &self.public_key.0]);
        response.mac1 = mac(&mac1_key, &[&response.bytes_for_macs()]);

        #[cfg(not(feature = "amnezia"))]
        {
            self.node.send_udp_packet(response.to_bytes(), sender).await;
        }

        #[cfg(feature = "amnezia")]
        {
            self.send_obfuscated_handshake_response(response, sender).await;
        }

        {
            let current_exists = match self.current_key_pair.read() { Ok(g) => g.is_some(), Err(e) => e.into_inner().is_some() };
            if !current_exists {
                self.rotate_keys();
                self.flush_queue().await;
            }
        }
        Ok(())
    }

    async fn on_handshake_response(&self, msg: HandshakeResponseMessage, sender: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let secrets_opt = match self.handshake_secrets.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };

        if let Some(secrets) = secrets_opt {
            let key_pair = self.noise.consume_handshake_response(&secrets, &msg);
            if let Some(kp) = key_pair {
                self.update_endpoint(sender);
                info!("Handshake Completed! Session ID: {}", kp.local_index);
                self.node.register_session(kp.local_index, &self.public_key);

                match self.next_key_pair.write() {
                    Ok(mut g) => *g = Some(Arc::new(kp)),
                    Err(e) => *e.into_inner() = Some(Arc::new(kp)),
                }

                self.rotate_keys();
                self.is_handshake_in_progress.store(false, Ordering::SeqCst);
                self.update_handshake_time();
                self.flush_queue().await;
            } else {
                warn!("Failed to consume handshake response.");
            }
        }
        Ok(())
    }

    async fn on_cookie_reply(&self, msg: CookieReplyMessage) -> Result<(), Box<dyn std::error::Error>> {
        let last_init = match self.last_initiation_message.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };

        if let Some(last) = last_init {
            if msg.receiver_index != last.sender_index {
                return Ok(());
            }
            let decrypted_cookie = self.node.decrypt_cookie(&msg, &last.mac1, &self.public_key);
            if let Some(cookie) = decrypted_cookie {
                self.initiate_handshake(Some(cookie)).await;
            }
        }
        Ok(())
    }

    async fn on_data_message(&self, msg: DataMessage, sender: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let current = match self.current_key_pair.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };
        let next = match self.next_key_pair.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };

        let matching_kp = if let Some(cur) = &current {
            if msg.receiver_index == cur.local_index { Some(cur.clone()) }
            else if let Some(nxt) = &next {
                if msg.receiver_index == nxt.local_index { Some(nxt.clone()) } else { None }
            } else { None }
        } else {
            if let Some(nxt) = &next {
                if msg.receiver_index == nxt.local_index { Some(nxt.clone()) } else { None }
            } else { None }
        };

        if let Some(kp) = matching_kp {
            if let Some(decrypted) = kp.decrypt_data(&msg) {
                self.update_endpoint(sender);

                if decrypted.len() > 0 {
                    self.rx_bytes.fetch_add(decrypted.len() as u64, Ordering::Relaxed);
                    if let Some(source_ip) = IPPacketUtils::get_source_address(&decrypted) {
                        if self.node.validate_packet_source(source_ip, self) {
                            let _ = self.node.device.write(&decrypted).await;
                        }
                    }
                }

                let is_next = if let Some(n) = &next { n.local_index == kp.local_index } else { false };
                if is_next {
                    debug!("Confirmed next session. Rotating keys.");
                    if let Some(old) = current { self.node.remove_session(old.local_index); }
                    match self.current_key_pair.write() { Ok(mut g) => *g = Some(kp), Err(e) => *e.into_inner() = Some(kp) }
                    match self.next_key_pair.write() { Ok(mut g) => *g = None, Err(e) => *e.into_inner() = None }
                }
            }
        }
        Ok(())
    }

    fn update_handshake_time(&self) {
        self.last_handshake_time.store(now_ms(), Ordering::Relaxed);
    }

    async fn initiate_handshake(&self, cookie: Option<Bytes>) {
        if self.peer_config.endpoint.is_none() {
            return;
        }

        let target_opt = match self.current_endpoint.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };

        if let Some(target) = target_opt {
            let now = now_ms();
            if cookie.is_none() {
                if self.is_handshake_in_progress.load(Ordering::SeqCst) && (now - self.last_handshake_sent_timestamp.load(Ordering::SeqCst) < REKEY_TIMEOUT_MS) {
                    return;
                }
            }

            self.last_handshake_sent_timestamp.store(now, Ordering::SeqCst);
            self.is_handshake_in_progress.store(true, Ordering::SeqCst);

            let local_index = self.node.find_available_index();
            self.node.register_session(local_index, &self.public_key);

            let mut ck = hash(&[PROTOCOL_NAME]);
            let mut hs = hash(&[&ck[..], IDENTIFIER]);
            hs = hash(&[&hs[..], &self.public_key.0]);
            let (ephemeral_private, ephemeral_public) = generate_keypair();
            hs = hash(&[&hs[..], &ephemeral_public.0]);
            ck = kdf1(&ck, &ephemeral_public.0);
            let shared_secret1 = x25519(&ephemeral_private, &self.public_key);
            let (ck1, key1) = kdf2(&ck, &shared_secret1);
            ck = ck1;
            let encrypted_static = chacha20_poly1305_encrypt(&key1, 0, &self.node.server_public_key.0, &hs).expect("Encryption failed");
            hs = hash(&[&hs[..], &encrypted_static]);
            let shared_secret2 = x25519(&self.node.server_private_key, &self.public_key);
            let (ck2, key2) = kdf2(&ck, &shared_secret2);
            ck = ck2;
            let timestamp = tai64n();
            let encrypted_timestamp = chacha20_poly1305_encrypt(&key2, 0, &timestamp, &hs).expect("Encryption failed");

            #[cfg(feature = "amnezia")]
            let wire_header = self.node.random_header(&self.node.amnezia_config.h1);
            #[cfg(not(feature = "amnezia"))]
            let wire_header = 1u32;

            let mut msg = HandshakeInitiationMessage {
                sender_index: local_index,
                unencrypted_ephemeral: ephemeral_public,
                encrypted_static: Bytes::from(encrypted_static),
                encrypted_timestamp: Bytes::from(encrypted_timestamp),
                mac1: Bytes::from(vec![0u8; 16]),
                mac2: Bytes::from(vec![0u8; 16]),
                wire_header,
            };
            
            let secrets = HandshakeSecrets {
                chaining_key: ck,
                hash: hs,
                ephemeral_private,
                local_index,
                remote_ephemeral: None,
                remote_index: 0,
                remote_static: self.public_key.clone(),
            };

            {
                let mut guard = match self.handshake_secrets.write() { Ok(g) => g, Err(e) => e.into_inner() };
                if let Some(old) = guard.as_ref() {
                    self.node.remove_session(old.local_index);
                }
                *guard = Some(secrets);
            }

            match self.last_initiation_message.write() { Ok(mut g) => *g = Some(msg.clone()), Err(e) => *e.into_inner() = Some(msg.clone()) }

            info!("Sending Handshake Initiation to {}", target);

            let mac1_key = hash(&[LABEL_MAC1, &self.public_key.0]);
            msg.mac1 = mac(&mac1_key, &[&msg.bytes_for_macs()]);
            if let Some(c) = cookie {
                msg.mac2 = mac(&c, &[&msg.bytes_for_macs()]);
            }

            #[cfg(not(feature = "amnezia"))]
            {
                self.node.send_udp_packet(msg.to_bytes(), target).await;
            }

            #[cfg(feature = "amnezia")]
            {
                if self.node.amnezia_config.jc > 0 {
                    self.send_junk_packets(target).await;
                }
                self.send_obfuscated_handshake_initiation(msg, target).await;
            }

        }
    }

    fn rotate_keys(&self) {
        let next_opt = match self.next_key_pair.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };
        if let Some(next) = next_opt {
            let current_opt = match self.current_key_pair.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };
            if let Some(current) = current_opt {
                self.node.remove_session(current.local_index);
            }
            match self.current_key_pair.write() { Ok(mut g) => *g = Some(next), Err(e) => *e.into_inner() = Some(next) }
            match self.next_key_pair.write() { Ok(mut g) => *g = None, Err(e) => *e.into_inner() = None }
        }
    }

    fn validate_and_decrypt_initiation(&self, msg: &HandshakeInitiationMessage) -> (Option<HandshakeState>, Option<String>) {
        let mut state = HandshakeState::new(hash(&[PROTOCOL_NAME]), hash(&[&hash(&[PROTOCOL_NAME])[..], IDENTIFIER]));
        state.mix_hash(&self.node.server_public_key.0);
        state.mix_hash(&msg.unencrypted_ephemeral.0);
        state.chaining_key = kdf1(&state.chaining_key, &msg.unencrypted_ephemeral.0);
        let shared1 = x25519(&self.node.server_private_key, &msg.unencrypted_ephemeral);
        let (ck1, key1) = kdf2(&state.chaining_key, &shared1);
        state.chaining_key = ck1;
        let decrypted_static = chacha20_poly1305_decrypt(&key1, 0, &msg.encrypted_static, &state.hash);
        if let Some(dec) = decrypted_static {
            if !constant_time_equals(&dec, &self.public_key.0) { return (None, Some("Wrong static key".to_string())); }
            state.mix_hash(&msg.encrypted_static);
            let shared2 = x25519(&self.node.server_private_key, &self.public_key);
            let (ck2, key2) = kdf2(&state.chaining_key, &shared2);
            state.chaining_key = ck2;
            let timestamp = chacha20_poly1305_decrypt(&key2, 0, &msg.encrypted_timestamp, &state.hash);
            if timestamp.is_none() { return (None, Some("Decryption failed (Timestamp)".to_string())); }
            state.mix_hash(&msg.encrypted_timestamp);
            (Some(state), None)
        } else {
            (None, Some("Decryption failed (Static)".to_string()))
        }
    }

    fn should_initiate_handshake(&self) -> bool {
        if self.peer_config.endpoint.is_none() { return false; }
        if self.is_handshake_in_progress.load(Ordering::SeqCst) { return false; }
        let now = now_ms();
        let elapsed = now - self.last_handshake_sent_timestamp.load(Ordering::SeqCst);
        if elapsed < REKEY_TIMEOUT_MS { return false; }
        let current_kp_opt = match self.current_key_pair.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };
        if current_kp_opt.is_none() { return true; }
        let kp = current_kp_opt.unwrap();
        if (now - kp.created_at) > REKEY_AFTER_TIME_MS { return true; }
        let last_sent = kp.last_packet_sent_timestamp.load(Ordering::Relaxed);
        let last_rcv = self.last_packet_received_timestamp.load(Ordering::Relaxed);
        if last_sent > 0 && (now - last_sent < 60_000) && (now - last_rcv > REKEY_ATTEMPT_TIME_MS) { return true; }
        false
    }

    fn should_send_keepalive(&self) -> bool {
        if self.keepalive_timeout_ms <= 0 { return false; }
        if self.peer_config.endpoint.is_none() { return false; }
        let kp_exists = match self.current_key_pair.read() { Ok(g) => g.is_some(), Err(e) => e.into_inner().is_some() };
        if !kp_exists { return false; }
        let now = now_ms();
        let kp = match self.current_key_pair.read() { Ok(g) => g.clone().unwrap(), Err(e) => e.into_inner().clone().unwrap() };
        let elapsed_sent = now - kp.last_packet_sent_timestamp.load(Ordering::SeqCst);
        elapsed_sent > self.keepalive_timeout_ms
    }

    async fn send_keepalive(&self) {
        let current = match self.current_key_pair.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };
        let endpoint = match self.current_endpoint.read() { Ok(g) => g.clone(), Err(e) => e.into_inner().clone() };

        if let (Some(kp), Some(target)) = (current, endpoint) {
            if let Some(enc) = kp.encrypt_data(&[]) {
                self.send_data_packet(enc, target).await;
            }
        }
    }

    async fn handle_tick_internal(&self) -> Result<(), Box<dyn std::error::Error>> {
        let now = now_ms();

        if self.is_handshake_in_progress.load(Ordering::SeqCst)
            && (now - self.last_handshake_sent_timestamp.load(Ordering::SeqCst) > (REKEY_TIMEOUT_MS * 3))
        {
            info!("Handshake timed out. Resetting to allow retry.");
            self.is_handshake_in_progress.store(false, Ordering::SeqCst);
        }

        {
            let mut current_guard = match self.current_key_pair.write() { Ok(g) => g, Err(e) => e.into_inner() };
            let mut drop_it = false;
            if let Some(kp) = current_guard.clone() {
                if (now - kp.created_at) > REJECT_AFTER_TIME_MS {
                    drop_it = true;
                    self.node.remove_session(kp.local_index);
                }
            }
            if drop_it {
                info!("Session expired.");
                *current_guard = None;
            }
        }

        if self.should_initiate_handshake() { self.initiate_handshake(None).await; }
        if self.should_send_keepalive() { self.send_keepalive().await; }

        Ok(())
    }
}

pub enum PeerEvent {
    UdpPacket(Message, SocketAddr),
    Tick,
    InitHandshake,
}