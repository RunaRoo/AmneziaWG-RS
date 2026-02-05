// src/cryptography.rs
use base64::{engine::general_purpose, Engine as _};
use blake2::{Blake2s256, Digest};
use bytes::{BufMut, Bytes, BytesMut};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, XChaCha20Poly1305, XNonce,
};
use digest::{Mac, KeyInit as MacKeyInit};
use hmac::SimpleHmac;
use rand::rngs::OsRng;
use rand::RngCore;
use std::time::SystemTime;
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret as XStaticSecret};
use blake2::digest::consts::U16;

pub const AUTH_TAG_LENGTH: usize = 16;
pub const KEY_LENGTH: usize = 32;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Key(pub Bytes);

impl Key {
    pub fn from_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), KEY_LENGTH);
        Key(Bytes::copy_from_slice(slice))
    }

    // SAFE: Returns Result instead of panicking
    pub fn try_from_base64(s: &str) -> Result<Self, String> {
        let decoded = general_purpose::STANDARD
            .decode(s)
            .map_err(|e| format!("Base64 decode error: {}", e))?;

        if decoded.len() != KEY_LENGTH {
            return Err(format!("Invalid key length: expected {}, got {}", KEY_LENGTH, decoded.len()));
        }
        Ok(Key(Bytes::from(decoded)))
    }

    // Keep for backward compatibility but use expect() with clear message
    pub fn from_base64(s: &str) -> Self {
        Self::try_from_base64(s).expect("CRITICAL: Invalid Base64 Key in Config")
    }

    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.0)
    }
}

pub fn generate_keypair() -> (Key, Key) {
    let mut private_bytes = [0u8; KEY_LENGTH];
    OsRng.fill_bytes(&mut private_bytes);
    let private = XStaticSecret::from(private_bytes);
    let public = XPublicKey::from(&private);

    (
        Key::from_slice(private.to_bytes().as_slice()),
        Key::from_slice(public.as_bytes()),
    )
}

pub fn private_to_public_key(private: &Key) -> Key {
    let secret: [u8; 32] = private.0.as_ref().try_into().unwrap(); // Safe if Key is always 32
    let static_secret = XStaticSecret::from(secret);
    let public = XPublicKey::from(&static_secret);
    Key::from_slice(public.as_bytes())
}

pub fn x25519(private: &Key, public: &Key) -> Bytes {
    let secret_bytes: [u8; 32] = private.0.as_ref().try_into().unwrap();
    let public_bytes: [u8; 32] = public.0.as_ref().try_into().unwrap();

    let secret = XStaticSecret::from(secret_bytes);
    let public_key = XPublicKey::from(public_bytes);

    let shared = secret.diffie_hellman(&public_key);
    Bytes::copy_from_slice(shared.as_bytes())
}

// SAFE: Returns Option<Bytes> on failure instead of panic
pub fn chacha20_poly1305_encrypt(key: &Key, counter: u64, plaintext: &[u8], aad: &[u8]) -> Option<Bytes> {
    let mut nonce_bytes = [0u8; 12];

    // WireGuard uses a 64-bit counter padded to 96 bits (12 bytes) for the nonce
    nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).ok()?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher.encrypt(&nonce_bytes.into(), payload).ok().map(Into::into)
}

pub fn chacha20_poly1305_decrypt(key: &Key, counter: u64, ciphertext: &[u8], aad: &[u8]) -> Option<Bytes> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&counter.to_le_bytes());

    let cipher = ChaCha20Poly1305::new_from_slice(&key.0).ok()?;
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    cipher.decrypt(&nonce_bytes.into(), payload).ok().map(Into::into)
}

pub fn xchacha20_poly1305_encrypt(key: &Key, nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Option<Bytes> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).ok()?;
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    if nonce.len() != 24 { return None; }
    cipher.encrypt(XNonce::from_slice(nonce), payload).ok().map(Into::into)
}

pub fn xchacha20_poly1305_decrypt(key: &Key, nonce: &[u8], ciphertext: &[u8], aad: &[u8]) -> Option<Bytes> {
    let cipher = XChaCha20Poly1305::new_from_slice(&key.0).ok()?;
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    if nonce.len() != 24 { return None; }
    cipher.decrypt(XNonce::from_slice(nonce), payload).ok().map(Into::into)
}

pub fn hash(inputs: &[&[u8]]) -> Bytes {
    let mut hasher = Blake2s256::new();
    for input in inputs {
        hasher.update(*input);
    }
    hasher.finalize().to_vec().into()
}

pub fn mac(key: &[u8], inputs: &[&[u8]]) -> Bytes {
    let mut mac = blake2::Blake2sMac::<U16>::new_with_salt_and_personal(key, &[], &[]).unwrap();
    for input in inputs {
        mac.update(*input);
    }
    mac.finalize().into_bytes().to_vec().into()
}

pub fn hmac(key: &[u8], inputs: &[&[u8]]) -> Bytes {
    let mut mac = <SimpleHmac<Blake2s256> as MacKeyInit>::new_from_slice(key).expect("HMAC key init failed");
    for input in inputs {
        mac.update(*input);
    }
    mac.finalize().into_bytes().to_vec().into()
}

pub fn kdf1(ck: &[u8], input: &[u8]) -> Bytes {
    let temp = hmac(ck, &[input]);
    hmac(&temp, &[&[1]])
}

pub fn kdf2(ck: &[u8], input: &[u8]) -> (Bytes, Key) {
    let temp = hmac(ck, &[input]);
    let key1 = hmac(&temp, &[&[1]]);
    let key2 = hmac(&temp, &[&key1[..], &[2]]);
    (key1, Key(Bytes::from(key2)))
}

pub fn kdf3(ck: &[u8], input: &[u8]) -> (Bytes, Key, Key) {
    let temp = hmac(ck, &[input]);
    let key1 = hmac(&temp, &[&[1]]);
    let key2 = hmac(&temp, &[&key1[..], &[2]]);
    let key3 = hmac(&temp, &[&key2[..], &[3]]);
    (key1, Key(Bytes::from(key2)), Key(Bytes::from(key3)))
}

pub fn tai64n() -> Bytes {
    let duration = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let seconds = duration.as_secs() + 0x400000000000000a;
    let nanos = duration.subsec_nanos();
    let mut buf = BytesMut::with_capacity(12);
    buf.put_u64(seconds);
    buf.put_u32(nanos);
    buf.freeze()
}