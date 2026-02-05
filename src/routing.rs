// src/routing.rs
use ipnet::IpNet;
use patricia_tree::PatriciaMap;
use std::net::IpAddr;
use std::sync::RwLock;

#[derive(Clone, Debug)]
pub struct Cidr {
    pub address: IpAddr,
    pub prefix: u8,
}

impl Cidr {
    pub fn from_string(s: &str) -> Self {
        let net: IpNet = s.parse().expect("Invalid CIDR format");
        Cidr {
            address: net.addr(),
            prefix: net.prefix_len(),
        }
    }

    // Converts the CIDR into a binary string representation (e.g., "11000000...")
    // used as the key for the Patricia Trie.
    pub fn to_bit_string(&self) -> String {
        let bytes = match self.address {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };
        let mut bit_str = String::with_capacity(bytes.len() * 8);
        for byte in bytes {
            bit_str.push_str(&format!("{:08b}", byte));
        }
        // Slice to the prefix length
        bit_str[0..self.prefix as usize].to_string()
    }
}

pub struct RoutingTable<T> {
    ipv4: RwLock<PatriciaMap<T>>,
    ipv6: RwLock<PatriciaMap<T>>,
}

impl<T: Clone> RoutingTable<T> {
    pub fn new() -> Self {
        Self {
            ipv4: RwLock::new(PatriciaMap::new()),
            ipv6: RwLock::new(PatriciaMap::new()),
        }
    }

    pub fn insert(&self, cidr: &Cidr, value: T) {
        let key = cidr.to_bit_string();
        let mut guard = if cidr.address.is_ipv4() {
            self.ipv4.write().unwrap()
        } else {
            self.ipv6.write().unwrap()
        };
        guard.insert(key, value);
    }

    pub fn remove(&self, cidr: &Cidr) {
        let key = cidr.to_bit_string();
        let mut guard = if cidr.address.is_ipv4() {
            self.ipv4.write().unwrap()
        } else {
            self.ipv6.write().unwrap()
        };
        guard.remove(&key);
    }

    pub fn find_best_match(&self, addr: IpAddr) -> Option<T> {
        // Create a full-length prefix for the destination address to search the trie
        let full_prefix = if addr.is_ipv4() { 32 } else { 128 };
        let search_cidr = Cidr {
            address: addr,
            prefix: full_prefix,
        };
        let key = search_cidr.to_bit_string();

        let guard = if addr.is_ipv4() {
            self.ipv4.read().unwrap()
        } else {
            self.ipv6.read().unwrap()
        };

        // get_longest_common_prefix returns the value associated with the longest prefix of `key`
        // that exists in the map. This effectively performs Longest Prefix Match (LPM).
        guard.get_longest_common_prefix(&key).map(|(_k, v)| v.clone())
    }

    pub fn clear(&self) {
        self.ipv4.write().unwrap().clear();
        self.ipv6.write().unwrap().clear();
    }

    pub fn size(&self) -> usize {
        self.ipv4.read().unwrap().len() + self.ipv6.read().unwrap().len()
    }
}