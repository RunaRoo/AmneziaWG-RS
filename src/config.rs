// src/config.rs
// src/config.rs
use crate::routing::Cidr;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

#[derive(Clone)]
pub struct InterfaceConfig {
    pub private_key: String,
    pub addresses: Vec<Cidr>,
    pub listen_port: Option<u16>,
    pub dns_servers: Vec<IpAddr>,
    pub post_up: Vec<String>,
    pub post_down: Vec<String>,
    pub mtu: u32,

    pub awg_jc: u32,
    pub awg_jmin: u32,
    pub awg_jmax: u32,
    pub awg_s1: u32,
    pub awg_s2: u32,
    pub awg_h1: String,
    pub awg_h2: String,
    pub awg_h3: String,
    pub awg_h4: String,
}

#[derive(Clone)]
pub struct PeerConfig {
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub allowed_ips: Vec<Cidr>,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u32>,
}

fn parse_cidrs(values: Option<&Vec<String>>) -> Vec<Cidr> {
    values
        .map(|v| {
            v.iter()
                .flat_map(|s| s.split(','))
                .map(|s| Cidr::from_string(s.trim()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_endpoint(s: &str) -> Option<SocketAddr> {
    if let Ok(addr) = SocketAddr::from_str(s) {
        return Some(addr);
    }
    s.to_socket_addrs().ok().and_then(|mut iter| iter.next())
}

pub fn parse(file_path: &Path) -> io::Result<(InterfaceConfig, Vec<PeerConfig>)> {
    let file = File::open(file_path)?;
    let lines = BufReader::new(file).lines();
    let mut interface_props: HashMap<String, Vec<String>> = HashMap::new();
    let mut peer_props_list: Vec<HashMap<String, Vec<String>>> = Vec::new();
    let mut current_props: Option<&mut HashMap<String, Vec<String>>> = None;

    for line in lines {
        let line = line?.trim().to_string();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.to_lowercase() == "[interface]" {
            current_props = Some(&mut interface_props);
        } else if line.to_lowercase() == "[peer]" {
            peer_props_list.push(HashMap::new());
            current_props = peer_props_list.last_mut();
        } else if line.contains('=') && current_props.is_some() {
            let parts: Vec<&str> = line.splitn(2, '=').map(|s| s.trim()).collect();
            if parts.len() == 2 {
                let key = parts[0].to_lowercase();
                let value = parts[1].to_string();
                if let Some(props) = current_props.as_mut() {
                    props.entry(key).or_insert(Vec::new()).push(value);
                }
            }
        }
    }

    let private_key = interface_props
        .get("privatekey")
        .and_then(|v| v.first().cloned())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing PrivateKey"))?;

    let iface_config = InterfaceConfig {
        private_key,
        addresses: parse_cidrs(interface_props.get("address")),
        listen_port: interface_props
            .get("listenport")
            .and_then(|v| v.first().and_then(|s| s.parse().ok())),
        dns_servers: interface_props
            .get("dns")
            .map(|dns| {
                dns.iter()
                    .flat_map(|d| d.split(',').map(|s| IpAddr::from_str(s.trim()).unwrap()))
                    .collect()
            })
            .unwrap_or_default(),
        post_up: interface_props.get("postup").cloned().unwrap_or_default(),
        post_down: interface_props.get("postdown").cloned().unwrap_or_default(),
        mtu: interface_props
            .get("mtu")
            .and_then(|v| v.first().and_then(|s| s.parse().ok()))
            .unwrap_or(1420),

        // AmneziaWG Parameters
        // Default values for vanilla WG compatibility
        awg_jc: interface_props
            .get("jc")
            .or(interface_props.get("awgjc"))
            .and_then(|v| v.first().and_then(|s| s.parse().ok()))
            .unwrap_or(0),
        awg_jmin: interface_props
            .get("jmin")
            .or(interface_props.get("awgjmin"))
            .and_then(|v| v.first().and_then(|s| s.parse().ok()))
            .unwrap_or(0),
        awg_jmax: interface_props
            .get("jmax")
            .or(interface_props.get("awgjmax"))
            .and_then(|v| v.first().and_then(|s| s.parse().ok()))
            .unwrap_or(0),
        awg_s1: interface_props
            .get("s1")
            .or(interface_props.get("awgs1"))
            .and_then(|v| v.first().and_then(|s| s.parse().ok()))
            .unwrap_or(0),
        awg_s2: interface_props
            .get("s2")
            .or(interface_props.get("awgs2"))
            .and_then(|v| v.first().and_then(|s| s.parse().ok()))
            .unwrap_or(0),
        awg_h1: interface_props
            .get("h1")
            .or(interface_props.get("awgh1"))
            .and_then(|v| v.first().cloned())
            .unwrap_or("1-1".to_string()), // standard is 0x01000000 le = 1
        awg_h2: interface_props
            .get("h2")
            .or(interface_props.get("awgh2"))
            .and_then(|v| v.first().cloned())
            .unwrap_or("2-2".to_string()),
        awg_h3: interface_props
            .get("h3")
            .or(interface_props.get("awgh3"))
            .and_then(|v| v.first().cloned())
            .unwrap_or("3-3".to_string()),
        awg_h4: interface_props
            .get("h4")
            .or(interface_props.get("awgh4"))
            .and_then(|v| v.first().cloned())
            .unwrap_or("4-4".to_string()),
    };

    let peer_configs = peer_props_list
        .into_iter()
        .map(|props| {
            let public_key = props
                .get("publickey")
                .and_then(|v| v.first().cloned())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing PublicKey"))?;
            Ok(PeerConfig {
                public_key,
                preshared_key: props.get("presharedkey").and_then(|v| v.first().cloned()),
                allowed_ips: parse_cidrs(props.get("allowedips")),
                endpoint: props
                    .get("endpoint")
                    .and_then(|v| v.first().and_then(|s| parse_endpoint(s))),
                persistent_keepalive: props
                    .get("persistentkeepalive")
                    .and_then(|v| v.first().and_then(|s| s.parse().ok())),
            })
        })
        .collect::<io::Result<Vec<_>>>()?;

    Ok((iface_config, peer_configs))
}