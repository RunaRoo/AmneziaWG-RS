// src/noise.rs
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{RwLock, Arc};
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use rand::rngs::OsRng;
use rand::RngCore;
use log::{info, warn, error};
use bytes::Bytes;
use crate::cryptography::*;
use crate::message::*;
use crate::peer::{KeyPair, ReplayFilter};
use crate::utils::{LABEL_COOKIE, LABEL_MAC1, PROTOCOL_NAME, IDENTIFIER, constant_time_equals};

#[derive(Clone)]
pub struct HandshakeSecrets {
    pub chaining_key: Bytes,
    pub hash: Bytes,
    pub ephemeral_private: Key,
    // Remote Ephemeral Key (E_remote), needed by Responder to calculate DH(E, E_r).
    pub remote_ephemeral: Option<Key>,
    // Remote Static Key (S_remote).
    pub remote_static: Key,
    pub local_index: u32,
    pub remote_index: u32,
}

#[derive(Clone)]
pub struct Noise {
    pub(crate) local_static_private: Key,
    pub(crate) local_static_public: Key,
    pub(crate) remote_static_public: Key,
    pub(crate) preshared_key: Option<Key>,
    initial_chaining_key: Bytes,
    initial_hash: Bytes,
}

impl Noise {
    pub fn new(local_static_private: Key, remote_static_public: Key, preshared_key: Option<Key>) -> Self {
        let local_static_public = private_to_public_key(&local_static_private);
        let initial_chaining_key = hash(&[PROTOCOL_NAME]);
        let mut initial_hash = hash(&[&initial_chaining_key[..], IDENTIFIER]);
        initial_hash = hash(&[&initial_hash[..], &remote_static_public.0]);

        Self {
            local_static_private,
            local_static_public,
            remote_static_public,
            preshared_key,
            initial_chaining_key: Bytes::from(initial_chaining_key),
            initial_hash: Bytes::from(initial_hash),
        }
    }

    // =========================================================================
    // INITIATOR (CLIENT) LOGIC
    // =========================================================================
    //todo: not fully tested yet

    pub fn create_handshake_initiation(&self, sender_index: u32) -> Option<(HandshakeInitiationMessage, HandshakeSecrets)> {
        let mut ck = self.initial_chaining_key.clone();
        let mut hs = self.initial_hash.clone();

        // 1. Generate Ephemeral Keypair (E_i)
        let (ephemeral_private, ephemeral_public) = generate_keypair();

        // Mix E_i
        hs = hash(&[&hs[..], &ephemeral_public.0]);
        ck = kdf1(&ck, &ephemeral_public.0);

        // 2. Encrypt Static Key (DH(E_i, S_r))
        let shared_secret1 = x25519(&ephemeral_private, &self.remote_static_public);
        let (ck_new, key1) = kdf2(&ck, &shared_secret1);
        ck = ck_new;
        let encrypted_static = chacha20_poly1305_encrypt(&key1, 0, &self.local_static_public.0, &hs)?;
        hs = hash(&[&hs[..], &encrypted_static]);

        // 3. Encrypt Timestamp (DH(S_i, S_r))
        let shared_secret2 = x25519(&self.local_static_private, &self.remote_static_public);
        let (ck_new, key2) = kdf2(&ck, &shared_secret2);
        ck = ck_new;
        let timestamp = tai64n();
        let encrypted_timestamp = chacha20_poly1305_encrypt(&key2, 0, &timestamp, &hs)?;
        hs = hash(&[&hs[..], &encrypted_timestamp]);

        // 4. Calculate MAC1 (using Responder's Static Public)
        let _mac1_key = hash(&[LABEL_MAC1, &self.remote_static_public.0]);
        // Note: Actual MAC1 computation happens in Peer.rs over final bytes

        let msg = HandshakeInitiationMessage {
            sender_index,
            unencrypted_ephemeral: ephemeral_public,
            encrypted_static: Bytes::from(encrypted_static),
            encrypted_timestamp: Bytes::from(encrypted_timestamp),
            mac1: Bytes::from(vec![0; 16]),
            mac2: Bytes::from(vec![0; 16]),
            wire_header: 1,
        };

        let secrets = HandshakeSecrets {
            chaining_key: ck,
            hash: hs,
            ephemeral_private,
            remote_ephemeral: None,
            remote_static: self.remote_static_public.clone(),
            local_index: sender_index,
            remote_index: 0,
        };

        Some((msg, secrets))
    }

    pub fn consume_handshake_response(&self, secrets: &HandshakeSecrets, response: &HandshakeResponseMessage) -> Option<KeyPair> {
        let mut ck = secrets.chaining_key.clone();
        let mut hs = secrets.hash.clone();

        // 1. Mix Responder Ephemeral (E_r)
        hs = hash(&[&hs[..], &response.unencrypted_ephemeral.0]);
        ck = kdf1(&ck, &response.unencrypted_ephemeral.0);

        // 2. Mix Ephemeral-Ephemeral (DH(E_i, E_r))
        let shared_secret1 = x25519(&secrets.ephemeral_private, &response.unencrypted_ephemeral);
        ck = kdf1(&ck, &shared_secret1);

        // 3. Mix Static-Ephemeral (DH(S_i, E_r))
        let shared_secret2 = x25519(&self.local_static_private, &response.unencrypted_ephemeral);
        ck = kdf1(&ck, &shared_secret2);

        // 4. Mix PSK
        let psk_bytes = self.preshared_key.as_ref().map(|k| k.0.clone()).unwrap_or(Bytes::from(vec![0; 32]));
        let (ck3, tau, k) = kdf3(&ck, &psk_bytes);
        ck = ck3;
        hs = hash(&[&hs[..], &tau.0]);

        // 5. Decrypt Empty Payload
        let _decrypted_nothing = chacha20_poly1305_decrypt(&k, 0, &response.encrypted_nothing, &hs)?;

        // 6. Derive Transport Keys
        // kdf2 returns (Bytes, Key)
        let (send_key_bytes, receive_key) = kdf2(&ck, &Bytes::new());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        Some(KeyPair {
            send_key: Key(send_key_bytes),
            recv_key: receive_key, // Already Key
            remote_index: response.sender_index,
            local_index: secrets.local_index,
            created_at: now,
            tx_nonce: AtomicU64::new(0),
            rx_replay_filter: ReplayFilter::new(),
            last_packet_sent_timestamp: AtomicI64::new(0),
        })
    }

    // =========================================================================
    // RESPONDER (SERVER) LOGIC
    // =========================================================================
    //Todo: almost 1 to 1 compatibility with Wireguard/AmneziaWG clients

    pub fn consume_handshake_initiation(&self, msg: &HandshakeInitiationMessage, local_index: u32) -> Option<HandshakeSecrets> {
        let initial_chaining_key = hash(&[PROTOCOL_NAME]);
        let mut initial_hash = hash(&[&initial_chaining_key[..], IDENTIFIER]);
        // Mix Hash with Local Static Public (S_r)
        initial_hash = hash(&[&initial_hash[..], &self.local_static_public.0]);

        let mut ck = initial_chaining_key;
        let mut hs = initial_hash;

        // 1. Mix Initiator Ephemeral (E_i)
        hs = hash(&[&hs[..], &msg.unencrypted_ephemeral.0]);
        ck = kdf1(&ck, &msg.unencrypted_ephemeral.0);

        // 2. Decrypt Initiator Static (DH(E_i, S_r))
        let shared_secret1 = x25519(&self.local_static_private, &msg.unencrypted_ephemeral);
        let (ck1, key1) = kdf2(&ck, &shared_secret1);
        ck = ck1;

        let decrypted_static_bytes = chacha20_poly1305_decrypt(&key1, 0, &msg.encrypted_static, &hs)?;
        let initiator_static = Key(Bytes::from(decrypted_static_bytes.to_vec()));
        hs = hash(&[&hs[..], &msg.encrypted_static]);

        if !constant_time_equals(&initiator_static.0, &self.remote_static_public.0) {
            warn!("Decrypted identity does not match configured peer public key.");
            return None;
        }

        // 3. Decrypt Timestamp (DH(S_i, S_r))
        let shared_secret2 = x25519(&self.local_static_private, &initiator_static);
        let (ck2, key2) = kdf2(&ck, &shared_secret2);
        ck = ck2;

        let _timestamp = chacha20_poly1305_decrypt(&key2, 0, &msg.encrypted_timestamp, &hs)?;
        hs = hash(&[&hs[..], &msg.encrypted_timestamp]);

        Some(HandshakeSecrets {
            chaining_key: ck,
            hash: hs,
            ephemeral_private: Key(Bytes::new()),
            remote_ephemeral: Some(msg.unencrypted_ephemeral.clone()),
            remote_static: initiator_static,
            local_index,
            remote_index: msg.sender_index,
        })
    }

    pub fn create_handshake_response(&self, secrets: &HandshakeSecrets) -> Option<(HandshakeResponseMessage, KeyPair)> {
        let mut ck = secrets.chaining_key.clone();
        let mut hs = secrets.hash.clone();

        // 1. Generate Responder Ephemeral (E_r)
        let (ephemeral_private, ephemeral_public) = generate_keypair();
        hs = hash(&[&hs[..], &ephemeral_public.0]);
        ck = kdf1(&ck, &ephemeral_public.0);

        // 2. Mix Ephemeral-Ephemeral (DH(E_r, E_i))
        let remote_ephemeral = secrets.remote_ephemeral.as_ref()?;
        let shared_secret1 = x25519(&ephemeral_private, remote_ephemeral);
        ck = kdf1(&ck, &shared_secret1);

        // 3. Mix Ephemeral-Static (DH(E_r, S_i))
        let shared_secret2 = x25519(&ephemeral_private, &secrets.remote_static);
        ck = kdf1(&ck, &shared_secret2);

        // 4. Mix PSK
        let psk_bytes = self.preshared_key.as_ref().map(|k| k.0.clone()).unwrap_or(Bytes::from(vec![0; 32]));
        let (ck3, tau, k) = kdf3(&ck, &psk_bytes);
        ck = ck3;
        hs = hash(&[&hs[..], &tau.0]);

        // 5. Encrypt Empty Payload
        let encrypted_nothing = chacha20_poly1305_encrypt(&k, 0, &[], &hs)?;
        hs = hash(&[&hs[..], &encrypted_nothing]);

        let msg = HandshakeResponseMessage {
            sender_index: secrets.local_index,
            receiver_index: secrets.remote_index,
            unencrypted_ephemeral: ephemeral_public,
            encrypted_nothing: Bytes::from(encrypted_nothing),
            mac1: Bytes::from(vec![0; 16]),
            mac2: Bytes::from(vec![0; 16]),
            wire_header: 2,
        };

        // 6. Derive Transport Keys
        // kdf2 returns (Bytes, Key)
        let (recv_key_bytes, send_key) = kdf2(&ck, &Bytes::new());
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as i64;

        let key_pair = KeyPair {
            send_key, // Already Key
            recv_key: Key(recv_key_bytes), // Bytes -> Key
            remote_index: secrets.remote_index,
            local_index: secrets.local_index,
            created_at: now,
            tx_nonce: AtomicU64::new(0),
            rx_replay_filter: ReplayFilter::new(),
            last_packet_sent_timestamp: AtomicI64::new(0),
        };

        Some((msg, key_pair))
    }
}

// =========================================================================
// COOKIE MECHANISM
// =========================================================================

pub struct CookieGenerator {
    local_static_public: Key,
    mac1_key: RwLock<Bytes>,
    mac2_key: RwLock<Bytes>,
    last_key_rotation: AtomicI64,
}

impl CookieGenerator {
    pub fn new(local_static_public: Key) -> Self {
        let mut mac1_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut mac1_key);
        let mut mac2_key = vec![0u8; 32];
        OsRng.fill_bytes(&mut mac2_key);
        Self {
            local_static_public,
            mac1_key: RwLock::new(Bytes::from(mac1_key)),
            mac2_key: RwLock::new(Bytes::from(mac2_key)),
            last_key_rotation: AtomicI64::new(Instant::now().elapsed().as_millis() as i64),
        }
    }

    fn rotate_keys_if_needed(&self) {
        let now = Instant::now().elapsed().as_millis() as i64;
        if now - self.last_key_rotation.load(Ordering::SeqCst) > 120_000 {
            let mut mac1_guard = self.mac1_key.write().unwrap();
            let mut mac2_guard = self.mac2_key.write().unwrap();
            *mac2_guard = mac1_guard.clone();
            let mut new_key = vec![0u8; 32];
            OsRng.fill_bytes(&mut new_key);
            *mac1_guard = Bytes::from(new_key);
            self.last_key_rotation.store(now, Ordering::SeqCst);
            info!("Cookie MAC keys rotated.");
        }
    }

    pub fn create_cookie_reply(&self, initiation_message: &HandshakeInitiationMessage, sender_address: &[u8]) -> Option<CookieReplyMessage> {
        self.rotate_keys_if_needed();
        let mut nonce = vec![0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        let mac1_guard = self.mac1_key.read().unwrap();
        let cookie = mac(&mac1_guard, &[sender_address]);

        let cookie_key = Key(hash(&[LABEL_COOKIE, &self.local_static_public.0]));
        let encrypted_cookie = xchacha20_poly1305_encrypt(&cookie_key, &nonce, &cookie, &initiation_message.mac1)?;

        Some(CookieReplyMessage {
            receiver_index: initiation_message.sender_index,
            nonce: Bytes::from(nonce),
            encrypted_cookie,
            wire_header: 3
        })
    }

    pub fn consume_cookie(&self, initiation_message: &HandshakeInitiationMessage, sender_address: &[u8]) -> bool {
        self.rotate_keys_if_needed();
        if initiation_message.mac2.iter().all(|&b| b == 0) {
            return false;
        }
        let mac1_guard = self.mac1_key.read().unwrap();
        let expected_cookie1 = mac(&mac1_guard, &[sender_address]);
        let expected_mac2_from_cookie1 = mac(&expected_cookie1, &[&initiation_message.bytes_for_macs()]);
        if constant_time_equals(&initiation_message.mac2, &expected_mac2_from_cookie1) {
            return true;
        }
        let mac2_guard = self.mac2_key.read().unwrap();
        let expected_cookie2 = mac(&mac2_guard, &[sender_address]);
        let expected_mac2_from_cookie2 = mac(&expected_cookie2, &[&initiation_message.bytes_for_macs()]);
        constant_time_equals(&initiation_message.mac2, &expected_mac2_from_cookie2)
    }
}

pub struct HandshakeState {
    pub chaining_key: Bytes,
    pub hash: Bytes,
}

impl HandshakeState {
    pub fn new(initial_chaining: Bytes, initial_hash: Bytes) -> Self {
        Self { chaining_key: initial_chaining, hash: initial_hash }
    }
    pub fn mix_hash(&mut self, data: &[u8]) {
        self.hash = hash(&[&self.hash[..], data]);
    }
}