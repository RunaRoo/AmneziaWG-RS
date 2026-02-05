# 🦀 Wireguard-W-RS

A high-performance, pure Rust implementation of the WireGuard® and AmneziaWG protocols.

Wireguard-W-RS is a lightweight, standalone VPN server designed for efficiency and stealth. Built entirely in Rust using the smol async runtime, it offers a memory-safe alternative to C-based implementations with minimal resource footprint.

Ideally suited for low-end VPS environments or embedded systems, it supports both standard WireGuard clients and AmneziaWG obfuscation to bypass Deep Packet Inspection (DPI) 🛡️.

## ✨ Key Features

- **Pure Rust Architecture**: Built for memory safety and concurrency without legacy baggage.

- **Protocol Support**:
  - Standard WireGuard: Fully compatible with official clients.
  - AmneziaWG (v1): Native support for packet obfuscation (requires `--features amnezia`).

- **Ultra-Lightweight**:
  - Binary size: ~2MB (static build).
  - Memory usage: ~4-5MB RAM under normal load.

- **Asynchronous Core**: Powered by the smol runtime for high-throughput, non-blocking I/O.

- **Portable & Standalone**:
  - Zero external dependencies.
  - Excellent support for linux-musl compilation to avoid glibc version conflicts on older systems.

- **Observability**: Built-in real-time statistics dumping and file-based logging.

⚠️ **Note**: This software is primarily designed and tested as a Server. Client mode is experimental. Windows support is currently stubbed; Linux is the target platform.

## 🛠️ Installation & Building

### Prerequisites

You will need the Rust toolchain installed.

### 1. Standard Build (Vanilla WireGuard)

If you require only standard WireGuard protocol support:

cargo build --release

# --- Standard WireGuard Settings ---

PrivateKey = YOUR_SERVER_PRIVATE_KEY

ListenPort = 51820

Address = 10.0.0.1/24

MTU = 1420

PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE

# --- AmneziaWG Obfuscation Settings (Optional) ---

# These values mimic the AmneziaWG v1 protocol spec

Jc = 4            # Junk Packet Count (random dummy packets to send)

Jmin = 40         # Minimum size of junk packets

Jmax = 70         # Maximum size of junk packets

S1 = 0            # Init Packet Padding bytes

S2 = 0            # Response Packet Padding bytes

H1 = 1            # Magic Header for Handshake Initiation

H2 = 2            # Magic Header for Handshake Response

H3 = 3            # Magic Header for Cookie Reply

H4 = 4            # Magic Header for Data Transport

[Peer]

PublicKey = CLIENT_PUBLIC_KEY

PresharedKey = Optional PSK

AllowedIPs = 10.0.0.2/32

[Peer]

AmneziaWG Client

PublicKey = CLIENT_2_PUBLIC_KEY

AllowedIPs = 10.0.0.3/32

PresharedKey = OPTIONAL_PSK

# 🚀 Usage:
Wireguard-W-RS is a single-binary application.Command Line Interface./wireguard-w-rs [FLAGS] [CONFIG_PATH] [COMMAND]

Flags--log-level <LEVEL>: Set verbosity (error, warn, info, debug, trace). Default: info.

--log-to-file <PATH>: Append logs to a specific file in addition to stdout.

--print-stats: Enable periodic writing of traffic statistics to stats.interface_name.txt.

Utility Commands

genkey: Generate a new Curve25519 pkeypair (Private + Public).

pubkey: Calculate the public key from a private key (passed via stdin).

genpsk: Generate a preshared key.

# Run 

ExamplesStart the server (looks for wg0.conf by default):

./wireguard-w-rs

Start with specific config and logging:

./wireguard-w-rs --log-level debug --log-to-file /var/log/wg.log /etc/wireguard/my_vpn.conf

# Generate Keys:

Generate PKeypair

./wireguard-w-rs genkey 


# 📊 Monitoring

When running with --print-stats, the server generates a file named stats.interface_name.txt in the

 working directory. This file updates every 5 seconds.Sample Output:interface: wg0

  public key: SERVER_PUBKEY

  Listening Port: Server Listen Port

peer: PEER_PUBKEY

  endpoint: 203.0.113.45:12345

  allowed ips: 10.0.0.2/32

  latest handshake: 45 seconds ago (45s)

  transfer: 1.50 MB received, 12.30 MB sent

# 🏗️ Architecture 

Networking: Uses the TUN device interface via libc ioctls on Linux

Cryptography: Implements x25519-dalek for key exchange, chacha20poly1305 for encryption, and blake2 for hashing.

Routing: Features an efficient N-Patricia Tree implementation for fast IP lookup.

# Disclaimer

This project is an independent implementation and is not affiliated with the official WireGuard 

project. Main Idea is create light and efficient AWG server with possible compilation for OpenWRT routers.

# Enjoy your secure connection and don't let opsec or DPI playing around with your data! ☕
