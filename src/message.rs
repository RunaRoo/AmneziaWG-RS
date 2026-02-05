// src/message.rs
use bytes::{Buf, BufMut, Bytes, BytesMut};
use crate::cryptography::{Key, AUTH_TAG_LENGTH, KEY_LENGTH};

#[derive(Clone)]
pub enum Message {
    HandshakeInitiation(HandshakeInitiationMessage),
    HandshakeResponse(HandshakeResponseMessage),
    CookieReply(CookieReplyMessage),
    Data(DataMessage),
}

impl Message {
    // Attempts to parse a Standard WireGuard message.
    // Returns None if the message type is unknown (Which can indicate AmneziaWG obfuscated packet)
    pub fn from_bytes(bytes: Bytes) -> Option<Self> {
        if bytes.len() < 4 {
            return None;
        }

        //little-endian u32
        // Type 1: Initiation
        // Type 2: Response
        // Type 3: Cookie Reply
        // Type 4: Data
        // This is first byte
        let type_id = bytes[0];

        match type_id {
            1 => Some(Message::HandshakeInitiation(HandshakeInitiationMessage::from_bytes(&bytes))),
            2 => Some(Message::HandshakeResponse(HandshakeResponseMessage::from_bytes(&bytes))),
            3 => Some(Message::CookieReply(CookieReplyMessage::from_bytes(&bytes))),
            4 => Some(Message::Data(DataMessage::from_bytes(&bytes))),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct HandshakeInitiationMessage {
    pub sender_index: u32,
    pub unencrypted_ephemeral: Key,
    pub encrypted_static: Bytes,
    pub encrypted_timestamp: Bytes,
    pub mac1: Bytes,
    pub mac2: Bytes,
    // The actual header value used on the wire (Standard 1 or Amnezia Magic H1).
    pub wire_header: u32,
}

impl HandshakeInitiationMessage {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(148);
        buf.put_u32_le(self.wire_header);
        buf.put_u32_le(self.sender_index);
        buf.put_slice(&self.unencrypted_ephemeral.0);
        buf.put_slice(&self.encrypted_static);
        buf.put_slice(&self.encrypted_timestamp);
        buf.put_slice(&self.mac1);
        buf.put_slice(&self.mac2);
        buf.freeze()
    }

    pub fn bytes_for_macs(&self) -> Bytes {
        // MAC1 covers everything up to the MAC fields (148 - 16 - 16 = 116 bytes)
        self.to_bytes().slice(..116)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut cursor = bytes;

        let wire_header = cursor.get_u32_le();

        let sender_index = cursor.get_u32_le();
        let mut ephemeral = [0; KEY_LENGTH];
        cursor.copy_to_slice(&mut ephemeral);
        let mut static_enc = [0; 48];
        cursor.copy_to_slice(&mut static_enc);
        let mut timestamp = [0; 28];
        cursor.copy_to_slice(&mut timestamp);
        let mut mac1 = [0; 16];
        cursor.copy_to_slice(&mut mac1);
        let mut mac2 = [0; 16];
        cursor.copy_to_slice(&mut mac2);

        Self {
            sender_index,
            unencrypted_ephemeral: Key::from_slice(&ephemeral),
            encrypted_static: Bytes::from(static_enc.to_vec()),
            encrypted_timestamp: Bytes::from(timestamp.to_vec()),
            mac1: Bytes::from(mac1.to_vec()),
            mac2: Bytes::from(mac2.to_vec()),
            wire_header,
        }
    }
}

#[derive(Clone)]
pub struct HandshakeResponseMessage {
    pub sender_index: u32,
    pub receiver_index: u32,
    pub unencrypted_ephemeral: Key,
    pub encrypted_nothing: Bytes,
    pub mac1: Bytes,
    pub mac2: Bytes,
    // The actual header value used on the wire (Standard 2 or Amnezia Magic H2).
    pub wire_header: u32,
}

impl HandshakeResponseMessage {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(92);
        buf.put_u32_le(self.wire_header);
        buf.put_u32_le(self.sender_index);
        buf.put_u32_le(self.receiver_index);
        buf.put_slice(&self.unencrypted_ephemeral.0);
        buf.put_slice(&self.encrypted_nothing);
        buf.put_slice(&self.mac1);
        buf.put_slice(&self.mac2);
        buf.freeze()
    }

    pub fn bytes_for_macs(&self) -> Bytes {
        // MAC1 covers header -> encrypted_nothing (92 - 16 - 16 = 60 bytes)
        self.to_bytes().slice(..60)
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut cursor = bytes;

        let wire_header = cursor.get_u32_le();

        let sender_index = cursor.get_u32_le();
        let receiver_index = cursor.get_u32_le();
        let mut ephemeral = [0; KEY_LENGTH];
        cursor.copy_to_slice(&mut ephemeral);
        let mut nothing = [0; AUTH_TAG_LENGTH];
        cursor.copy_to_slice(&mut nothing);
        let mut mac1 = [0; 16];
        cursor.copy_to_slice(&mut mac1);
        let mut mac2 = [0; 16];
        cursor.copy_to_slice(&mut mac2);

        Self {
            sender_index,
            receiver_index,
            unencrypted_ephemeral: Key::from_slice(&ephemeral),
            encrypted_nothing: Bytes::from(nothing.to_vec()),
            mac1: Bytes::from(mac1.to_vec()),
            mac2: Bytes::from(mac2.to_vec()),
            wire_header,
        }
    }
}

#[derive(Clone)]
pub struct CookieReplyMessage {
    pub receiver_index: u32,
    pub nonce: Bytes,
    pub encrypted_cookie: Bytes,
    // The actual header value used on the wire (Standard 3 or Amnezia Magic H3).
    pub wire_header: u32,
}

impl CookieReplyMessage {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(64);

        buf.put_u32_le(self.wire_header);

        buf.put_u32_le(self.receiver_index);
        buf.put_slice(&self.nonce);
        buf.put_slice(&self.encrypted_cookie);
        buf.freeze()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut cursor = bytes;

        //Read the specific wire header here
        let wire_header = cursor.get_u32_le();

        let receiver_index = cursor.get_u32_le();
        let mut nonce = [0; 24];
        cursor.copy_to_slice(&mut nonce);
        let mut cookie = [0; 16 + AUTH_TAG_LENGTH];
        cursor.copy_to_slice(&mut cookie);

        Self {
            receiver_index,
            nonce: Bytes::from(nonce.to_vec()),
            encrypted_cookie: Bytes::from(cookie.to_vec()),
            wire_header,
        }
    }
}

#[derive(Clone)]
pub struct DataMessage {
    pub receiver_index: u32,
    pub counter: u64,
    pub encrypted_data: Bytes,
    // The actual header value used on the wire (Standard 4 or Amnezia Magic H4).
    pub wire_header: u32,
}

impl DataMessage {
    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(16 + self.encrypted_data.len());
        
        buf.put_u32_le(self.wire_header);

        buf.put_u32_le(self.receiver_index);
        buf.put_u64_le(self.counter);
        buf.put_slice(&self.encrypted_data);
        buf.freeze()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut cursor = bytes;
        
        let wire_header = cursor.get_u32_le();

        let receiver_index = cursor.get_u32_le();
        let counter = cursor.get_u64_le();
        let remaining = cursor.remaining();
        let mut data = vec![0u8; remaining];
        cursor.copy_to_slice(&mut data);

        Self {
            receiver_index,
            counter,
            encrypted_data: Bytes::from(data),
            wire_header,
        }
    }
}