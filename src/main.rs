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
use device::{LinuxTunDevice, TunDevice};
use node::Node;
use std::env;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use log::{error, info, LevelFilter};
use std::io::Write;
use cryptography::{generate_keypair, Key};
use std::fs::{File, OpenOptions};

//Struct for dual writing (Stdout + File)
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
        std::io::stdout().flush()?;
        if let Some(file_mutex) = &self.file {
            if let Ok(mut f) = file_mutex.lock() {
                f.flush()?;
            }
        }
        Ok(())
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

    // --- Argument Parsing ---
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
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
                } else {
                    i += 1;
                }
            }
            "--log-to-file" => {
                if i + 1 < args.len() {
                    log_file_path = Some(args[i+1].clone());
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--print-stats" => {
                print_stats = true;
                i += 1;
            }
            cmd if !cmd.starts_with("-") && command.is_none() && (cmd == "genkey" || cmd == "pubkey" || cmd == "genpsk") => {
                command = Some(cmd.to_string());
                i += 1;
            }
            val if !val.starts_with("-") => {
                config_path = val.to_string();
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }

    //Command Handling
    if let Some(cmd) = command {
        match cmd.as_str() {
            "genkey" => {
                let (priv_key, _) = generate_keypair();
                println!("{}", priv_key.to_base64());
                return Ok(());
            }
            "genpsk" => {
                let (priv_key, _) = generate_keypair();
                //32-byte random value
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

    //Log Setup
    let log_file = if let Some(path) = log_file_path {
        Some(Arc::new(Mutex::new(
            OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?,
        )))
    } else {
        None
    };

    let logger = Box::new(TeeWriter { file: log_file });

    // Initialize Logger
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

    //Config Loader
    info!("Loading configuration from {}", config_path);
    let path_obj = std::path::Path::new(&config_path);
    //Todo Implement "Headless" mode with (WG/AWG tools) compatibility?

    //Extract interface name from filename ("myvpn.conf" -> "myvpn")
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

    let (iface_config, peer_configs) = match parse((&config_path).as_ref()) {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("Failed to parse configuration: {}", e);
            return Ok(());
        }
    };

    info!("Interface config loaded. MTU: {}. Desired Name: {}", iface_config.mtu, interface_name);

    //Async Runtime
    //todo smol better than tokyo (Light, no C++ compile required)
    smol::block_on(async {
        // Handle Ctrl+C
        let (ctrlc_tx, ctrlc_rx) = smol::channel::bounded(1);
        ctrlc::set_handler(move || {
            let _ = ctrlc_tx.try_send(());
        }).expect("Error setting Ctrl-C handler");
        //todo it should handle OS signals (SIGTERM and etc)

        let device = Arc::new(LinuxTunDevice::new(&interface_name, iface_config.clone())?);

        // Bring interface up (Apply IP, MTU, etc.)
        device.up(&peer_configs)?;

        info!("Interface {} is UP. MTU: {}", device.name(), device.mtu());
        if print_stats {
            info!("Stats dumping enabled. Writing to stats.txt every 5s.");
            //todo write 5s better than wright every tick
        }

        let node = Node::new(iface_config, peer_configs, device.clone(), print_stats).await;

        info!("WireGuard-W-RS started. Listening for packets...");
        //Hello Varesa!

        #[cfg(feature = "amnezia")]
        info!("AmneziaWG Features Enabled");

        node.start().await;

        // Wait for shutdown signal
        let _ = ctrlc_rx.recv().await;

        info!("Received shutdown signal. Bringing interface down...");
        if let Err(e) = device.down() {
            error!("Failed to bring down device: {}", e);
        } else {
            info!("Interface brought down successfully.");
        }

        Ok(())
    })
}

fn print_help() {
    println!("Usage: wireguard-w-rs [FLAGS] [CONFIG_PATH] [COMMAND]");
    println!();
    println!("Flags:");
    println!("  --log-level <LEVEL>     Set log level (error, warn, info, debug, trace). Default: info");
    println!("  --log-to-file <PATH>    Write logs to specified file (in addition to stdout)");
    println!("  --print-stats           Enable periodical writing of stats to 'stats.txt'");
    println!();
    println!("Commands:");
    println!("  genkey                  Generate a new private key");
    println!("  genpsk                  Generate a new preshared key");
    println!("  pubkey                  Convert private key (stdin) to public key");
}