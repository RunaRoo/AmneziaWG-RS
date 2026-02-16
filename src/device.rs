// src/device.rs
use async_trait::async_trait;
use log::{debug, info, warn};
use std::io;
use std::sync::Arc;
use std::process::Command;

use crate::config::{InterfaceConfig, PeerConfig};

// =========================================================================
// 1. TRAIT DEFINITION
// =========================================================================

//Manual tun handling
//We might use "tun" crate here
//

#[async_trait]
pub trait TunDevice: Send + Sync {
    fn name(&self) -> &str;
    fn mtu(&self) -> u32;

    /// Reads a packet from the TUN interface.
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Writes a packet to the TUN interface.
    async fn write(&self, buf: &[u8]) -> io::Result<()>;

    /// Brings the interface UP, assigns IP, and adds routes.
    fn up(&self, peers: &[PeerConfig]) -> io::Result<()>;

    /// Brings the interface DOWN.
    fn down(&self) -> io::Result<()>;

    /// Executes a shell command (Required for hooks).
    fn run_command(&self, command: &str) -> io::Result<()>;
}

// Implement TunDevice for Arc<T> automatically.
#[async_trait]
impl<T: TunDevice + ?Sized> TunDevice for Arc<T> {
    fn name(&self) -> &str { (**self).name() }
    fn mtu(&self) -> u32 { (**self).mtu() }
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> { (**self).read(buf).await }
    async fn write(&self, buf: &[u8]) -> io::Result<()> { (**self).write(buf).await }
    fn up(&self, peers: &[PeerConfig]) -> io::Result<()> { (**self).up(peers) }
    fn down(&self) -> io::Result<()> { (**self).down() }
    fn run_command(&self, command: &str) -> io::Result<()> { (**self).run_command(command) }
}

// =========================================================================
// 2. LINUX IMPLEMENTATION
// =========================================================================

#[cfg(target_os = "linux")]
pub use linux::LinuxTunDevice;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use smol::Async;
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::os::unix::io::{FromRawFd, RawFd};
    use libc::{c_char, c_short, c_ulong, c_int, IFF_TUN, IFF_NO_PI, O_RDWR, O_NONBLOCK, IFNAMSIZ};
    use std::mem;

    // Use qualified paths for Read/Write to avoid conflicts with AsyncReadExt
    use std::io::{Read, Write};

    const TUNSETIFF: c_ulong = 0x400454ca;

    #[repr(C)]
    struct ifreq {
        ifr_name: [u8; IFNAMSIZ],
        ifr_flags: c_short,
    }

    pub struct LinuxTunDevice {
        file: Async<File>,
        name: String,
        mtu: u32,
        config: InterfaceConfig,
    }

    impl LinuxTunDevice {
        pub fn new(name: &str, config: InterfaceConfig) -> io::Result<Self> {
            let (file, actual_name) = create_tun_interface(name)?;

            // Async::new works on Linux because File implements AsFd
            let async_file = Async::new(file)?;

            info!("Created TUN device: {}", actual_name);

            Ok(Self {
                file: async_file,
                name: actual_name,
                mtu: config.mtu,
                config,
            })
        }

        fn execute_hooks(&self, hooks: &[String], phase: &str) {
            for hook in hooks {
                info!("Executing {} hook: {}", phase, hook);
                if let Err(e) = self.run_shell_command(hook) {
                    warn!("Failed to execute {} hook '{}': {}", phase, hook, e);
                }
            }
        }

        fn run_shell_command(&self, cmd: &str) -> io::Result<()> {
            let output = Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .env("WG_INTERFACE", &self.name)
                .output()?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("Command failed: {}", stderr.trim()),
                ));
            }
            Ok(())
        }
    }

    #[async_trait]
    impl TunDevice for LinuxTunDevice {
        fn name(&self) -> &str {
            &self.name
        }

        fn mtu(&self) -> u32 {
            self.mtu
        }

        async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            // FIX: Use read_with to read via shared reference (&self)
            // On Linux, &File implements Read, so we can read without &mut self.file
            self.file.read_with(|f| {
                let mut f_ref = f; // Create a mutable reference to the shared ref
                f_ref.read(buf)
            }).await
        }

        async fn write(&self, buf: &[u8]) -> io::Result<()> {
            // FIX: Use write_with for shared reference writing
            self.file.write_with(|f| {
                let mut f_ref = f;
                f_ref.write(buf)
            }).await.map(|_| ())
        }

        fn up(&self, peers: &[PeerConfig]) -> io::Result<()> {
            info!("Bringing up interface {}", self.name);

            for addr in &self.config.addresses {
                info!("Assigning address {}/{} to {}", addr.address, addr.prefix, self.name);
                self.run_shell_command(&format!(
                    "ip address add {}/{} dev {}",
                    addr.address, addr.prefix, self.name
                ))?;
            }

            self.run_shell_command(&format!("ip link set dev {} mtu {}", self.name, self.mtu))?;
            self.run_shell_command(&format!("ip link set dev {} up", self.name))?;

            info!("Adding routes for {} peers...", peers.len());
            for peer in peers {
                for allowed in &peer.allowed_ips {
                    let route_target = format!("{}/{}", allowed.address, allowed.prefix);
                    debug!("Adding route: {} dev {}", route_target, self.name);
                    let _ = self.run_shell_command(&format!(
                        "ip route replace {} dev {}",
                        route_target, self.name
                    ));
                }
            }

            self.execute_hooks(&self.config.post_up, "PostUp");
            Ok(())
        }

        fn down(&self) -> io::Result<()> {
            info!("Bringing down interface {}", self.name);
            self.execute_hooks(&self.config.post_down, "PostDown");
            let _ = self.run_shell_command(&format!("ip link set dev {} down", self.name));
            Ok(())
        }

        fn run_command(&self, command: &str) -> io::Result<()> {
            self.run_shell_command(command)
        }
    }

    fn create_tun_interface(name: &str) -> io::Result<(File, String)> {
        let path = CString::new("/dev/net/tun").expect("CString::new failed");
        
        // Open the clone device
        let fd = unsafe { libc::open(path.as_ptr(), O_RDWR | O_NONBLOCK) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // Prepare ifreq structure
        let mut ifr: ifreq = unsafe { mem::zeroed() };
        ifr.ifr_flags = (IFF_TUN | IFF_NO_PI) as c_short;

        let name_bytes = name.as_bytes();
        if name_bytes.len() >= IFNAMSIZ {
            unsafe { libc::close(fd) }; // Don't forget to close fd on error
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Interface name too long"));
        }
        
        // Copy name bytes safely
        for (i, &byte) in name_bytes.iter().enumerate() {
            ifr.ifr_name[i] = byte;
        }

        let res = unsafe { libc::ioctl(fd, TUNSETIFF as libc::c_int, &mut ifr) };
        
        if res < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }

        let actual_name = unsafe {
            CStr::from_ptr(ifr.ifr_name.as_ptr() as *const c_char)
                .to_string_lossy()
                .into_owned()
        };

        // Wrap raw fd in File
        let file = unsafe { File::from_raw_fd(fd) };
        
        Ok((file, actual_name))
    }

// =========================================================================
// 3. WINDOWS STUB
// =========================================================================

//Just to shut up compiler on windows
//Currently this implementation is Linux only

//Compile with "musl" if have "glibc" error

//We might compile for OpenWRT routers or etc

#[cfg(target_os = "windows")]
pub struct LinuxTunDevice;

#[cfg(target_os = "windows")]
impl LinuxTunDevice {
    pub fn new(_name: &str, _config: InterfaceConfig) -> io::Result<Self> {
        Err(io::Error::new(io::ErrorKind::Other, "LinuxTunDevice not supported on Windows"))
    }
}

#[cfg(target_os = "windows")]
#[async_trait]
impl TunDevice for LinuxTunDevice {
    fn name(&self) -> &str { "none" }
    fn mtu(&self) -> u32 { 0 }
    async fn read(&self, _buf: &mut [u8]) -> io::Result<usize> { Ok(0) }
    async fn write(&self, _buf: &[u8]) -> io::Result<()> { Ok(()) }
    fn up(&self, _peers: &[PeerConfig]) -> io::Result<()> { Ok(()) }
    fn down(&self) -> io::Result<()> { Ok(()) }
    fn run_command(&self, _command: &str) -> io::Result<()> { Ok(()) }
}

// /////
//Legacy Linux Implementation
// /////
/*
// src/device.rs
use async_trait::async_trait;
use libc::{
    self, c_char, c_int, c_short, c_ulong, c_void, fcntl, ioctl, F_GETFL, F_SETFL,
    IFNAMSIZ, O_NONBLOCK, O_RDWR,
};
use log::{debug, error, info, warn};
use smol::Async;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::mem;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::{FromRawFd, RawFd};
use std::process::Command;

use crate::config::{InterfaceConfig, PeerConfig};

// =========================================================================
// PLATFORM SPECIFIC CONSTANTS & STRUCTS
// =========================================================================

#[cfg(target_os = "linux")]
mod os_defs {
    use super::*;
    pub const IFF_TUN: c_short = 0x0001;
    pub const IFF_NO_PI: c_short = 0x1000;
    pub const TUNSETIFF: c_ulong = 0x400454ca;

    #[repr(C)]
    pub struct ifreq {
        pub ifr_name: [u8; IFNAMSIZ],
        pub ifr_flags: c_short,
    }
}

#[cfg(target_os = "macos")]
mod os_defs {
    use super::*;
    pub const PF_SYSTEM: c_int = 32;
    pub const SYSPROTO_CONTROL: c_int = 2;
    pub const AF_SYS_CONTROL: c_short = 2;
    pub const AF_INET: u8 = 2;
    pub const AF_INET6: u8 = 30;
    pub const CTLIOCGINFO: c_ulong = 0xc0644e03;
    pub const UTUN_OPT_IFNAME: c_int = 2;
    pub const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";

    #[repr(C)]
    pub struct ctl_info {
        pub ctl_id: u32,
        pub ctl_name: [u8; 96],
    }

    #[repr(C)]
    pub struct sockaddr_ctl {
        pub sc_len: u8,
        pub sc_family: u8,
        pub ss_sysaddr: u16,
        pub sc_id: u32,
        pub sc_unit: u32,
        pub sc_reserved: [u32; 5],
    }
}

#[cfg(target_os = "linux")]
use os_defs::*;

#[cfg(target_os = "macos")]
use os_defs::*;

// =========================================================================
// TRAIT & MAIN STRUCT
// =========================================================================

#[async_trait]
pub trait TunDevice: Send + Sync {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize>;
    async fn write(&self, data: &[u8]) -> io::Result<usize>;
    fn up(&self, peers: &[PeerConfig]) -> io::Result<()>;
    fn down(&self) -> io::Result<()>;
    fn name(&self) -> &str;
    fn mtu(&self) -> u32;
}

// Backward compatibility alias
pub type LinuxTunDevice = NativeTunDevice;

pub struct NativeTunDevice {
    inner: Async<File>,
    name: String,
    mtu: u32,
    config: InterfaceConfig,
}

impl NativeTunDevice {
    pub fn new(name: &str, config: &InterfaceConfig) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Self::new_linux(name, config)
        }
        #[cfg(target_os = "macos")]
        {
            Self::new_macos(name, config)
        }
        #[cfg(target_os = "freebsd")]
        {
            Self::new_freebsd(name, config)
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported, "OS not supported"))
        }
    }

    // --- LINUX CONSTRUCTOR ---
    #[cfg(target_os = "linux")]
    fn new_linux(name: &str, config: &InterfaceConfig) -> io::Result<Self> {
        let fd = unsafe { libc::open(b"/dev/net/tun\0".as_ptr() as *const c_char, O_RDWR) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_flags: IFF_TUN | IFF_NO_PI,
        };
        let name_bytes = name.as_bytes();
        let len = std::cmp::min(name_bytes.len(), IFNAMSIZ - 1);
        ifr.ifr_name[..len].copy_from_slice(&name_bytes[..len]);

        if unsafe { ioctl(fd, TUNSETIFF, &mut ifr as *mut _ as *mut c_void) } < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        let real_name = unsafe { CStr::from_ptr(ifr.ifr_name.as_ptr() as *const c_char) }
            .to_str()
            .unwrap_or(name)
            .to_string();

        Self::configure_nonblocking(fd)?;
        let file = unsafe { File::from_raw_fd(fd) };

        Ok(Self {
            inner: Async::new(file)?,
            name: real_name,
            mtu: config.mtu,
            config: config.clone(),
        })
    }

    // --- MACOS CONSTRUCTOR ---
    #[cfg(target_os = "macos")]
    fn new_macos(requested_name: &str, config: &InterfaceConfig) -> io::Result<Self> {
        let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let ctl_name_bytes = UTUN_CONTROL_NAME.as_bytes();
        for (i, &b) in ctl_name_bytes.iter().enumerate() {
            info.ctl_name[i] = b;
        }

        if unsafe { ioctl(fd, CTLIOCGINFO, &mut info as *mut _ as *mut c_void) } < 0 {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        let sc_unit: u32 = if requested_name.starts_with("utun") {
            requested_name
                .strip_prefix("utun")
                .and_then(|s| s.parse::<u32>().ok())
                .map(|u| u + 1)
                .unwrap_or(0)
        } else {
            0
        };

        let addr = sockaddr_ctl {
            sc_len: mem::size_of::<sockaddr_ctl>() as u8,
            sc_family: AF_SYS_CONTROL as u8,
            ss_sysaddr: SYSPROTO_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit,
            sc_reserved: [0; 5],
        };

        if unsafe {
            libc::connect(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<sockaddr_ctl>() as u32,
            )
        } < 0
        {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        let mut name_buf = [0u8; 64];
        let mut len: u32 = 64;
        if unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name_buf.as_mut_ptr() as *mut c_void,
                &mut len,
            )
        } < 0
        {
            unsafe { libc::close(fd) };
            return Err(io::Error::last_os_error());
        }

        let real_name = unsafe { CStr::from_ptr(name_buf.as_ptr() as *const c_char) }
            .to_string_lossy()
            .into_owned();

        if real_name.is_empty() {
            unsafe { libc::close(fd) };
            return Err(io::Error::new(io::ErrorKind::Other, "Failed to get utun name"));
        }

        info!("Opened utun device: {}", real_name);

        Self::configure_nonblocking(fd)?;
        let file = unsafe { File::from_raw_fd(fd) };

        Ok(Self {
            inner: Async::new(file)?,
            name: real_name,
            mtu: config.mtu,
            config: config.clone(),
        })
    }

    // --- FREEBSD CONSTRUCTOR ---
    #[cfg(target_os = "freebsd")]
    fn new_freebsd(name: &str, config: &InterfaceConfig) -> io::Result<Self> {
        let _ = Command::new("kldload").arg("if_tun").output();
        if !std::path::Path::new(&format!("/dev/{}", name)).exists() {
            let _ = Command::new("ifconfig").args([name, "create"]).output();
        }

        let path_str = format!("/dev/{}", name);
        let path = CString::new(path_str.clone()).unwrap();

        let fd = unsafe { libc::open(path.as_ptr(), O_RDWR) };
        if fd < 0 {
            error!("Failed to open {}", path_str);
            return Err(io::Error::last_os_error());
        }

        Self::configure_nonblocking(fd)?;
        let file = unsafe { File::from_raw_fd(fd) };

        Ok(Self {
            inner: Async::new(file)?,
            name: name.to_string(),
            mtu: config.mtu,
            config: config.clone(),
        })
    }

    fn configure_nonblocking(fd: RawFd) -> io::Result<()> {
        unsafe {
            let flags = fcntl(fd, F_GETFL);
            if flags < 0 {
                return Err(io::Error::last_os_error());
            }
            if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    fn execute_hooks(&self, hooks: &[String], hook_type: &str) {
        for cmd in hooks {
            info!("Executing {} hook: {}", hook_type, cmd);
            let cmd_processed = cmd.replace("%i", &self.name);
            let _ = Command::new("sh").arg("-c").arg(&cmd_processed).output();
        }
    }
}

// =========================================================================
// TRAIT IMPLEMENTATION
// =========================================================================

#[async_trait]
impl TunDevice for NativeTunDevice {
    async fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        #[cfg(target_os = "macos")]
        {
            // macOS utun includes 4-byte protocol family header
            let mut internal_buf = vec![0u8; buf.len() + 4];
            let n = self.inner.read_with(|mut f| f.read(&mut internal_buf)).await?;
            if n <= 4 { return Ok(0); }
            buf[..n - 4].copy_from_slice(&internal_buf[4..n]);
            Ok(n - 4)
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.inner.read_with(|mut f| f.read(buf)).await
        }
    }

    async fn write(&self, data: &[u8]) -> io::Result<usize> {
        #[cfg(target_os = "macos")]
        {
            // macOS utun requires prepending 4-byte protocol family
            if data.is_empty() { return Ok(0); }
            let version = data[0] >> 4;
            let family: u32 = if version == 6 { AF_INET6 as u32 } else { AF_INET as u32 };
            let header = family.to_ne_bytes();

            let mut packet = Vec::with_capacity(4 + data.len());
            packet.extend_from_slice(&header);
            packet.extend_from_slice(data);

            let n = self.inner.write_with(|mut f| f.write(&packet)).await?;
            if n >= 4 { Ok(n - 4) } else { Ok(0) }
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.inner.write_with(|mut f| f.write(data)).await
        }
    }

    fn up(&self, peers: &[PeerConfig]) -> io::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.up_linux(peers)
        }
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            self.up_bsd(peers)
        }
    }

    fn down(&self) -> io::Result<()> {
        self.execute_hooks(&self.config.post_down, "PostDown");

        #[cfg(target_os = "linux")]
        Command::new("ip").args(["link", "set", "dev", &self.name, "down"]).output()?;

        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        Command::new("ifconfig").args([&self.name, "down"]).output()?;

        #[cfg(target_os = "freebsd")]
        Command::new("ifconfig").args([&self.name, "destroy"]).output().ok();

        Ok(())
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn mtu(&self) -> u32 {
        self.mtu
    }
}

// =========================================================================
// PLATFORM SPECIFIC HELPERS (WITH ROUTING FIXES)
// =========================================================================

impl NativeTunDevice {
    // ---------------------------------------------------------------------
    // EXCLUDE ROUTE: Prevents the "Routing Loop" by pinning endpoint traffic
    // to the physical gateway.
    // ---------------------------------------------------------------------
    fn exclude_route(&self, endpoint: &Option<SocketAddr>) {
        if let Some(addr) = endpoint {
            let ip = addr.ip().to_string();
            info!("Ensuring route for VPN Endpoint {} goes through physical interface...", ip);

            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            {
                // 1. Get current physical interface for this IP
                // Command: route -n get <IP>
                let output = Command::new("route").args(["-n", "get", &ip]).output();
                if let Ok(out) = output {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    // Parse output looking for "interface: en0"
                    if let Some(line) = stdout.lines().find(|l| l.contains("interface:")) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(iface) = parts.last() {
                            info!("Detected physical interface for endpoint: {}", iface);
                            // 2. Add explicit route
                            // Command: route -n add -host <IP> -interface <IFACE>
                            let _ = Command::new("route")
                                .args(["-n", "add", "-host", &ip, "-interface", iface])
                                .output();
                        }
                    }
                }
            }

            #[cfg(target_os = "linux")]
            {
                // 1. Query the kernel for the current route to the endpoint
                // Command: ip route get <IP>
                let output = Command::new("ip")
                    .args(["route", "get", &ip])
                    .output();

                if let Ok(out) = output {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    // Output format usually: "1.2.3.4 via 192.168.1.1 dev eth0 src ..."

                    let parts: Vec<&str> = stdout.split_whitespace().collect();
                    let mut gateway = None;
                    let mut device = None;

                    // Simple parser for "via <GATEWAY>" and "dev <DEVICE>"
                    for (i, part) in parts.iter().enumerate() {
                        if *part == "via" && i + 1 < parts.len() {
                            gateway = Some(parts[i+1]);
                        }
                        if *part == "dev" && i + 1 < parts.len() {
                            device = Some(parts[i+1]);
                        }
                    }

                    // 2. Add a specific /32 route for the endpoint via that physical gateway/device
                    // This "pins" the traffic to the physical interface, bypassing the tunnel.
                    if let Some(dev) = device {
                        info!("Detected physical route for endpoint: dev {} via {:?}", dev, gateway);

                        let mut args = vec!["route", "add", &ip, "dev", dev];
                        if let Some(gw) = gateway {
                            args.push("via");
                            args.push(gw);
                        }

                        // Execute: ip route add <IP> via <GW> dev <DEV>
                        let _ = Command::new("ip").args(&args).output();
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn up_linux(&self, peers: &[PeerConfig]) -> io::Result<()> {
        // 1. Address
        for addr in &self.config.addresses {
            Command::new("ip")
                .args(["address", "add", &format!("{}/{}", addr.address, addr.prefix), "dev", &self.name])
                .output()?;
        }
        // 2. Link Up
        Command::new("ip").args(["link", "set", "dev", &self.name, "mtu", &self.mtu.to_string()]).output()?;
        Command::new("ip").args(["link", "set", "dev", &self.name, "up"]).output()?;

        // 3. Routes
        for peer in peers {
            // FIX: Exclude endpoint to prevent loops
            self.exclude_route(&peer.endpoint);

            for allowed in &peer.allowed_ips {
                let route_target = format!("{}/{}", allowed.address, allowed.prefix);
                let _ = Command::new("ip").args(["route", "add", &route_target, "dev", &self.name]).output();
            }
        }
        self.execute_hooks(&self.config.post_up, "PostUp");
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    fn up_bsd(&self, peers: &[PeerConfig]) -> io::Result<()> {
        // 1. MTU
        Command::new("ifconfig").args([&self.name, "mtu", &self.mtu.to_string()]).output()?;

        // 2. Addresses (With explicit Netmask)
        for addr in &self.config.addresses {
            match addr.address {
                IpAddr::V4(v4) => {
                    // Calculate Mask
                    let mask_bit = if addr.prefix >= 32 { 0 } else { 32 - addr.prefix };
                    let mask_u32 = if mask_bit == 32 { 0 } else { (!0u32) << mask_bit };
                    let mask = Ipv4Addr::from(mask_u32);

                    let _ = Command::new("ifconfig")
                        .args([
                            &self.name,
                            "inet",
                            &v4.to_string(),
                            &v4.to_string(), // Dest (P2P self)
                            "netmask",
                            &mask.to_string(),
                            "alias",
                        ])
                        .output()?;
                }
                IpAddr::V6(v6) => {
                    let _ = Command::new("ifconfig")
                        .args([
                            &self.name,
                            "inet6",
                            &v6.to_string(),
                            "prefixlen",
                            &addr.prefix.to_string(),
                            "alias",
                        ])
                        .output()?;
                }
            }
        }

        // 3. Up
        Command::new("ifconfig").args([&self.name, "up"]).output()?;

        // 4. Routes
        for peer in peers {
            // FIX: Exclude endpoint to prevent loops (Vital for 0.0.0.0/0)
            self.exclude_route(&peer.endpoint);

            for allowed in &peer.allowed_ips {
                let family = if allowed.address.is_ipv4() { "-inet" } else { "-inet6" };

                if allowed.prefix == 0 {
                    // Route Splitting to avoid overwriting default gateway
                    info!("Splitting default route (0/0) to prevent leaks");
                    if allowed.address.is_ipv4() {
                        let _ = Command::new("route").args(["-n", "add", family, "0.0.0.0/1", "-interface", &self.name]).output();
                        let _ = Command::new("route").args(["-n", "add", family, "128.0.0.0/1", "-interface", &self.name]).output();
                    } else {
                        let _ = Command::new("route").args(["-n", "add", family, "::/1", "-interface", &self.name]).output();
                        let _ = Command::new("route").args(["-n", "add", family, "8000::/1", "-interface", &self.name]).output();
                    }
                } else {
                    let net = format!("{}/{}", allowed.address, allowed.prefix);
                    let _ = Command::new("route")
                        .args(["-n", "add", family, &net, "-interface", &self.name])
                        .output();
                }
            }
        }

        self.execute_hooks(&self.config.post_up, "PostUp");
        Ok(())
    }
}


 */
