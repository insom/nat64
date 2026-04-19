mod checksum;
mod config;
mod nat64;
mod tun;

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io::ErrorKind;

const RECV_BUF_SIZE: usize = 65536;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args: Vec<String> = std::env::args().collect();
    let config_path = match args.get(1) {
        Some(p) => p.as_str(),
        None => {
            eprintln!("Usage: {} <config-file>", args[0]);
            std::process::exit(1);
        }
    };

    log::info!("Loading configuration from {}", config_path);
    let cfg = match config::Config::load(config_path) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Configuration error: {}", e);
            std::process::exit(1);
        }
    };

    log::info!(
        "NAT64 prefix: {:?}/96, local IPv4: {}, TUN device: {}",
        cfg.prefix,
        cfg.ipv4_addr,
        cfg.tun_device
    );
    log::info!("Static mappings: {} entries", cfg.map4to6.len());
    for (v4, v6) in &cfg.map4to6 {
        log::info!("  {} <-> {}", v4, v6);
    }

    let mut tun = match tun::TunDevice::open(&cfg.tun_device) {
        Ok(t) => t,
        Err(e) => {
            log::error!("Cannot open TUN device '{}': {}", cfg.tun_device, e);
            std::process::exit(1);
        }
    };

    log::info!(
        "TUN device '{}' ready, MTU={}, entering packet loop",
        tun.name(),
        tun.mtu
    );

    let mut recv_buf = vec![0u8; RECV_BUF_SIZE];
    let mut stats = Stats::default();

    loop {
        let fd = unsafe { std::os::unix::io::BorrowedFd::borrow_raw(tun.fd()) };
        let mut pollfd = [PollFd::new(fd, PollFlags::POLLIN)];

        match poll(&mut pollfd, PollTimeout::from(1000u16)) {
            Ok(0) => continue, // timeout
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => {
                log::error!("poll error: {}", e);
                break;
            }
        }

        loop {
            match tun.read_packet(&mut recv_buf) {
                Ok(0) => break,
                Ok(n) => {
                    let packet = &recv_buf[..n];
                    handle_packet(&cfg, &mut tun, packet, &mut stats);
                }
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    log::error!("TUN read error: {}", e);
                    break;
                }
            }
        }
    }
}

#[derive(Default)]
struct Stats {
    pkts_4to6: u64,
    pkts_6to4: u64,
    errors: u64,
}

fn handle_packet(
    cfg: &config::ParsedConfig,
    tun: &mut tun::TunDevice,
    packet: &[u8],
    stats: &mut Stats,
) {
    let version = match nat64::detect_ip_version(packet) {
        Some(v) => v,
        None => {
            log::trace!("Dropping packet: cannot detect IP version");
            stats.errors += 1;
            return;
        }
    };

    let result = match version {
        4 => {
            let r = nat64::translate_4to6(cfg, packet);
            if r.is_ok() {
                stats.pkts_4to6 += 1;
                if stats.pkts_4to6.is_multiple_of(1000) {
                    log::info!(
                        "Stats: 4→6: {}, 6→4: {}, errors: {}",
                        stats.pkts_4to6,
                        stats.pkts_6to4,
                        stats.errors
                    );
                }
            }
            r
        }
        6 => {
            let r = nat64::translate_6to4(cfg, packet);
            if r.is_ok() {
                stats.pkts_6to4 += 1;
            }
            r
        }
        _ => {
            log::trace!("Dropping packet: unsupported IP version {}", version);
            stats.errors += 1;
            return;
        }
    };

    match result {
        Ok(translated) => {
            if let Err(e) = tun.write_packet(&translated.data) {
                log::warn!("TUN write error: {}", e);
                stats.errors += 1;
            }
        }
        Err(nat64::TranslateError::AddressNotMapped) => {
            log::trace!("Address not mapped, dropping packet");
            stats.errors += 1;
        }
        Err(e) => {
            log::debug!("Translation error: {:?}", e);
            stats.errors += 1;
        }
    }
}
