pub mod config;
pub mod cryptography;
pub mod device;
pub mod message;
pub mod noise;
pub mod peer;
pub mod routing;
pub mod utils;
pub mod node;

use config::parse;
use device::{TunDevice, LinuxTunDevice};
use node::Node;
use std::env;
use std::sync::{Arc, Mutex};
use log::{error, info, LevelFilter};
use std::io::Write;
use cryptography::{generate_keypair, Key};
use std::fs::{File, OpenOptions};
use smol::Executor;
use num_cpus;

// Struct for dual writing (Stdout + File)
struct TeeWriter {
    file: Option<Arc<Mutex<File>>>,
}

impl Write for TeeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let stdout_len = std::io::stdout().write(buf)?;
        if let Some(file_mutex) = &self.file {
            if let Ok(mut f) = file_mutex.lock() {
                let _ = f.write_all(buf);
            }
        }
        Ok(stdout_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stdout().flush();
        if let Some(file_mutex) = &self.file {
            if let Ok(mut f) = file_mutex.lock() {
                let _ = f.flush();
            }
        }
        Ok(())
    }
}

// Helper for buffer size parsing
fn parse_buffer_size(s: &str) -> u64 {
    let lower = s.to_lowercase();
    let cleaned: String = lower.chars().filter(|c| c.is_ascii_digit() || *c == '.').collect();
    let num: f64 = cleaned.parse().unwrap_or(32.0);

    if lower.contains('g') {
        (num * 1024.0 * 1024.0 * 1024.0) as u64
    } else if lower.contains('m') {
        (num * 1024.0 * 1024.0) as u64
    } else if lower.contains('k') {
        (num * 1024.0) as u64
    } else {
        (num * 1024.0 * 1024.0) as u64
    }
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = env::args().collect();

    // Default values
    let mut config_path = "wg0.conf".to_string();
    let mut log_level = LevelFilter::Info;
    let mut log_file_path: Option<String> = None;
    let mut print_stats = false;
    let mut command: Option<String> = None;

    // Multi-thread defaults
    let mut num_threads: usize = num_cpus::get().min(16);
    let mut buffer_size: u64 = 32 * 1024 * 1024; // 32 MiB default

    // --- Argument Parsing ---
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--log-level" => {
                if i + 1 < args.len() {
                    log_level = match args[i+1].to_lowercase().as_str() {
                        "error" => LevelFilter::Error,
                        "warn" => LevelFilter::Warn,
                        "info" => LevelFilter::Info,
                        "debug" => LevelFilter::Debug,
                        "trace" => LevelFilter::Trace,
                        _ => LevelFilter::Info,
                    };
                    i += 2;
                } else { i += 1; }
            }
            "--log-to-file" => {
                if i + 1 < args.len() {
                    log_file_path = Some(args[i+1].clone());
                    i += 2;
                } else { i += 1; }
            }
            "--print-stats" => {
                print_stats = true;
                i += 1;
            }
            "--threads" => {
                if i + 1 < args.len() {
                    num_threads = args[i+1].parse().unwrap_or(num_threads).max(1);
                    i += 2;
                } else { i += 1; }
            }
            "--buffer-size" => {
                if i + 1 < args.len() {
                    buffer_size = parse_buffer_size(&args[i+1]);
                    i += 2;
                } else { i += 1; }
            }
            cmd if !cmd.starts_with("-") && command.is_none() && (cmd == "genkey" || cmd == "pubkey" || cmd == "genpsk") => {
                command = Some(cmd.to_string());
                i += 1;
            }
            val if !val.starts_with("-") => {
                config_path = val.to_string();
                i += 1;
            }
            _ => { i += 1; }
        }
    }

    // Command Handling
    if let Some(cmd) = command {
        match cmd.as_str() {
            "genkey" | "genpsk" => {
                let (priv_key, _) = generate_keypair();
                println!("{}", priv_key.to_base64());
                return Ok(());
            }
            "pubkey" => {
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let trimmed = input.trim();
                if let Ok(priv_key) = Key::try_from_base64(trimmed) {
                    let pub_key = cryptography::private_to_public_key(&priv_key);
                    println!("{}", pub_key.to_base64());
                } else {
                    eprintln!("Invalid private key format");
                    std::process::exit(1);
                }
                return Ok(());
            }
            _ => {}
        }
    }

    // Log Setup
    let log_file = if let Some(path) = log_file_path {
        Some(Arc::new(Mutex::new(
            OpenOptions::new().create(true).append(true).open(path)?,
        )))
    } else { None };

    let logger = Box::new(TeeWriter { file: log_file });

    env_logger::Builder::new()
        .filter_level(log_level)
        .format(|buf, record| {
            writeln!(
                buf,
                "[{}] {}: {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .target(env_logger::Target::Pipe(logger))
        .init();

    info!("WireGuard-W-RS (Linux Only)");
    info!("Scale Settings: threads={}, buffer_limit={} MiB", num_threads, buffer_size / (1024 * 1024));

    // --- Multi-threaded Executor Setup ---
    let executor = Arc::new(Executor::new());

    for n in 0..num_threads.saturating_sub(1) {
        let ex = executor.clone();
        std::thread::Builder::new()
            .name(format!("worker-{}", n))
            .spawn(move || {
                smol::block_on(ex.run(std::future::pending::<()>()))
            })?;
    }

    smol::block_on(executor.run(async {
        let path_obj = std::path::Path::new(&config_path);

        let interface_name = path_obj
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("wg0")
            .to_string();

        if !path_obj.exists() {
            error!("Configuration file not found: {}", config_path);
            print_help();
            return Ok(());
        }

        let (iface_config, peer_configs) = match parse(path_obj) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Failed to parse configuration: {}", e);
                return Ok(());
            }
        };

        let device = Arc::new(LinuxTunDevice::new(&interface_name, iface_config.clone())?);
        device.up(&peer_configs)?;

        let node = Node::new(
            iface_config,
            peer_configs,
            device.clone(),
            print_stats,
            num_threads,
            buffer_size
        ).await;

        #[cfg(feature = "amnezia")]
        info!("AmneziaWG features enabled");

        node.start().await;

        let (ctrlc_tx, ctrlc_rx) = smol::channel::bounded(1);
        ctrlc::set_handler(move || {
            let _ = ctrlc_tx.try_send(());
        }).expect("Error setting Ctrl-C handler");

        info!("Interface {} up. Listening...", device.name());

        let _ = ctrlc_rx.recv().await;

        info!("Shutting down interface...");
        let _ = device.down();

        Ok::<(), std::io::Error>(())
    }))
}

fn print_help() {
    println!("Usage: wireguard-w-rs [FLAGS] [CONFIG_PATH] [COMMAND]");
    println!();
    println!("Flags:");
    println!("  --log-level <LEVEL>     Set log level (error, warn, info, debug, trace). Default: info");
    println!("  --log-to-file <PATH>    Write logs to specified file in addition to stdout");
    println!("  --print-stats           Periodically write peer statistics to stats.txt");
    println!("  --threads <NUM>         Number of worker threads for parallel crypto (Default: CPU count)");
    println!("  --buffer-size <SIZE>    Global memory limit for packet buffers (e.g. 512m, 1g). Default: 32m");
    println!("  -h, --help              Print this help screen");
    println!();
    println!("Commands:");
    println!("  genkey                  Generate a new private key");
    println!("  genpsk                  Generate a new preshared key");
    println!("  pubkey                  Read private key from stdin and output public key");
}