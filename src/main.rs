use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::{fmt, fs, path, process};

use base64;
use chrono::Local;
use clap::{App, Arg, ArgGroup};
use colored::Colorize;
use ipnet::Ipv4Net;
use itertools::Itertools;
use rand_core::{OsRng, RngCore};
use rpassword::prompt_password_stdout;
use secrecy::{ExposeSecret, Secret};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

mod validate;
mod ranges;

enum HzErr {
    CalcComb,
    DirErr,
    FileErr,
    FileExists,
    GenKeyPair,
    GenPSK,
    ParseIP,
    ParseU16,
    ParseSubnet,
    U16Range,
    TooFewIPs,
    UserCancel,
    UserInput,
    UserPrompt,
}

impl fmt::Display for HzErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CalcComb => write!(f, "Error host calculating pair combinations."),
            Self::DirErr => write!(f, "Error creating directory for configuration files."),
            Self::FileErr => write!(f, "Error creating file."),
            Self::FileExists => write!(f, "Error: file already exists."),
            Self::GenKeyPair => write!(f, "Error generating keypair."),
            Self::GenPSK => write!(f, "Error generating preshared key."),
            Self::ParseIP => write!(f, "Error parsing IP address."),
            Self::ParseU16 => write!(f, "Error parsing integer."),
            Self::ParseSubnet => write!(f, "Error parsing subnet."),
            Self::U16Range => write!(f, "Error parsing integer."),
            Self::TooFewIPs => write!(f, "Too few IPs in specified subnet."),
            Self::UserCancel => write!(f, "User cancelled."),
            Self::UserInput => write!(f, "Unable to interpret input."),
            Self::UserPrompt => write!(f, "Encountered error at user prompt."),
        }
    }
}

struct HostConfig {
    endpoint_addr: SocketAddrV4,
    priv_addr: Ipv4Addr,
    priv_key: Secret<String>,
    pub_key: String,
    peers: Vec<HostPeer>,
}

impl HostConfig {
    fn push_peer(&mut self, other: HostPeer) {
        self.peers.push(other);
    }
}

#[derive(Clone)]
struct HostPeer {
    endpoint_addr: SocketAddrV4,
    priv_addr: Ipv4Addr,
    pub_key: String,
    preshared_key: Secret<String>,
    keepalive: u16,
}

impl PartialEq for HostPeer {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint_addr == other.endpoint_addr
    }
}

fn check_and_create_conf_dir(dir_name: &str) -> Result<PathBuf, String> {
    let time = time_now();
    let path = path::Path::new(dir_name).join(time);

    if let Err(e) = fs::DirBuilder::new().recursive(true).create(&path) {
        println!("{}", e);
        return Err(HzErr::DirErr.to_string());
    }

    Ok(path)
}

fn check_and_create_conf_file(
    dir: &PathBuf,
    file: &str,
    text: &Secret<String>,
) -> Result<String, String> {
    let path = Path::new(dir).join(file);

    if path.exists() {
        return Err(HzErr::FileExists.to_string());
    } else if fs::write(path, text.expose_secret()).is_err() {
        return Err(HzErr::FileErr.to_string());
    }

    Ok(file.to_string())
}

fn create_config_files(
    config_text: &Secret<String>,
    host_id: SocketAddrV4,
) -> Result<(PathBuf, String), String> {
    let filename = host_id.ip().to_string().replace(".", "") + "-wg0.conf";
    println!("{}", filename);

    let dir = match check_and_create_conf_dir("haze_configs") {
        Ok(d) => d,
        Err(e) => return Err(e),
    };

    let file = match check_and_create_conf_file(&dir, &filename, &config_text) {
        Ok(f) => f,
        Err(e) => return Err(e),
    };

    Ok((dir, file))
}

fn confirmation_display(host_configs: &[HostConfig]) -> Result<(), String> {
    for (i, host) in host_configs.iter().enumerate() {
        println!("\n\n{:^80}", format!("[ Host {} ]", i + 1).bold());
        println!(
            "Public address: {:<48}Private address: {:<22}",
            hl_one(&host.endpoint_addr),
            hl_one(&host.priv_addr)
        );
        println!(
            "Public key: {:<40}\nPrivate key: {:<40}",
            hl_one(&host.pub_key),
            hl_one(&"** Hidden** ")
        );

        for (i, peer) in host.peers.iter().enumerate() {
            println!("\n\t{}", format!("[ Peer {} ]", i + 1).bold());
            println!(
                "\tPublic address: {:<40}Private address: {}\n\tPublic key: {:<40}\n\tPreshared key: {:<40}",
                hl_two(&peer.endpoint_addr),
                hl_two(&peer.priv_addr),
                hl_two(&peer.pub_key),
                hl_two(&"** Hidden **"));
        }
    }
    continue_prompt()
}

fn continue_prompt() -> Result<(), String> {
    if let Ok(response) = prompt_password_stdout("\nContinue? (y/n) ") {
        match &response.to_ascii_lowercase()[..1] {
            "y" => Ok(()),
            "n" => Err(HzErr::UserCancel.to_string()),
            _ => Err(HzErr::UserInput.to_string()),
        }
    } else {
        Err(HzErr::UserPrompt.to_string())
    }
}

fn gen_config_text(host_conf: &HostConfig) -> Secret<String> {
    let timestamp = format!("# Configuration generated by Haze. {}", time_now());
    let addr_line = format!("Address = {}", host_conf.priv_addr);
    let key_line = format!("PrivateKey = {}", host_conf.priv_key.expose_secret());
    let port_line = format!("ListenPort = {}", host_conf.endpoint_addr.port());
    let mut text = format!(
        "{}\n[Interface]\n{}\n{}\n{}\n",
        timestamp, addr_line, key_line, port_line
    );

    for peer in &host_conf.peers {
        let key_line = format!("PublicKey = {}", peer.pub_key);
        let psk_line = format!("PreSharedKey = {}", peer.preshared_key.expose_secret());
        let endpnt_line = format!("Endpoint = {}", peer.endpoint_addr);
        let addr_line = format!("AllowedIPs = {}/32", peer.priv_addr);
        let keepalive_line = format!("PersistentKeepAlive = {}", peer.keepalive);
        text = format!(
            "{}\n[Peer]\n{}\n{}\n{}\n{}\n{}\n",
            text, key_line, psk_line, endpnt_line, addr_line, keepalive_line
        );
    }
    Secret::new(text)
}

fn gen_host_configs(
    pub_ips: &[Ipv4Addr],
    priv_subnet: Ipv4Net,
    ports: String,
    rand_ports: bool,
    keepalive: u16,
) -> Vec<HostConfig> {
    let host_count = pub_ips.len();
    let priv_addresses = ranges::enum_subnet(host_count, priv_subnet).unwrap();
    let host_keypairs = gen_x25519_keypairs(host_count).unwrap();

    let host_pair_count = ranges::peer_combos(host_count, 2).unwrap();
    let host_pair_psks = gen_preshared_keys(host_pair_count).unwrap();

    let port_vec = ranges::enum_port_range(ports, rand_ports).unwrap();
    let mut port_iter = port_vec.iter().cycle();

    let mut hosts: Vec<HostConfig> = Vec::with_capacity(host_count);
    for (i, j) in priv_addresses.into_iter().enumerate() {
        let this_port = port_iter.next().unwrap();
        hosts.push(HostConfig {
            endpoint_addr: SocketAddrV4::new(pub_ips[i], *this_port),
            priv_addr: j,
            priv_key: host_keypairs[i].0.clone(),
            pub_key: host_keypairs[i].1.clone(),
            peers: Vec::new(),
        });
    }

    let mut paired_configs: Vec<(HostPeer, HostPeer)> = Vec::new();

    for (i, j) in hosts.iter().combinations(2).enumerate() {
        let peer_0 = HostPeer {
            endpoint_addr: j[0].endpoint_addr,
            priv_addr: j[0].priv_addr,
            pub_key: j[0].pub_key.clone(),
            preshared_key: host_pair_psks[i].clone(),
            keepalive,
        };
        let peer_1 = HostPeer {
            endpoint_addr: j[1].endpoint_addr,
            priv_addr: j[1].priv_addr,
            pub_key: j[1].pub_key.clone(),
            preshared_key: host_pair_psks[i].clone(),
            keepalive,
        };
        paired_configs.push((peer_0, peer_1));
    }

    for pair in &paired_configs {
        let (peer_0, peer_1) = pair;
        for host in &mut hosts {
            if host.endpoint_addr == peer_1.endpoint_addr {
                host.push_peer(peer_0.clone());
            }
            if host.endpoint_addr == peer_0.endpoint_addr {
                host.push_peer(peer_1.clone());
            }
        }
    }
    hosts
}

fn gen_preshared_keys(host_pair_count: usize) -> Result<Vec<Secret<String>>, String> {
    let mut keys = Vec::with_capacity(host_pair_count);
    for _ in 0..host_pair_count {
        let mut key: [u8; 32] = [0_u8; 32];
        OsRng.fill_bytes(&mut key);
        keys.push(Secret::new(base64::encode(&key)));
        key.zeroize();
    }

    if keys.is_empty() {
        return Err(HzErr::GenPSK.to_string());
    }
    Ok(keys)
}

fn gen_x25519_keypairs(host_count: usize) -> Result<Vec<(Secret<String>, String)>, String> {
    let mut keypairs: Vec<(Secret<String>, String)> = Vec::with_capacity(host_count);
    for _ in 0..host_count {
        let mut secret_key = StaticSecret::new(&mut OsRng);
        let pub_key = PublicKey::from(&secret_key);
        let keypair = (
            Secret::new(base64::encode(&secret_key.to_bytes())),
            base64::encode(&pub_key.as_bytes()),
        );
        keypairs.push(keypair);
        secret_key.zeroize();
    }

    if keypairs.is_empty() {
        return Err(HzErr::GenKeyPair.to_string());
    }
    Ok(keypairs)
}

// Highlight color to help visually parse output
fn hl_one<T: ToString>(item: &T) -> String {
    format!("{}", item.to_string().green())
}

// Another highlight color to help visually parse output
fn hl_two<T: ToString>(item: &T) -> String {
    format!("{}", item.to_string().cyan())
}

fn time_now() -> String {
    Local::now().format("%a-%v-%H%M").to_string()
}
fn main() {
    let matches = App::new("Haze")
        .version("0.1")
        .author("Shane s. <elliptic@tachyon.cx>")
        .about("Generates configuration files for arbitrarily-sized WireGuard mesh networks.")
        .after_help("EXAMPLES:\
        \n\t./haze --endpoints=45.45.45.2,45.45.45.3 --port=51820 --subnet=10.0.0.0/24\
        \n\t./haze --endpoints=45.45.45.2,45.45.45.3,45.45.45.4 --random-port-range=50000-50100 --subnet=192.168.50.128/25")
        .arg(
            Arg::with_name("ip_addr")
                .help("Specify external addresses of WireGuard hosts")
                .display_order(500)
                .short("e")
                .long("endpoints")
                .value_name("IP")
                .multiple(true)
                .required(true)
                .require_equals(true)
                .value_delimiter(",")
                .validator(validate::is_ip),
        )
        .arg(
            Arg::with_name("wg_port")
                .help("Specify external port of WireGuard hosts [default: 51820]")
                .display_order(505)
                .short("p")
                .long("port")
                .value_name("PORT")
                .multiple(false)
                .require_equals(true)
                .validator(validate::is_port),
        )
        .arg(
            Arg::with_name("seq_port_range")
                .help("Specify external port range for WireGuard hosts. Wraps if range is less than available hosts.")
                .display_order(510)
                .short("r")
                .long("port-range")
                .value_name("LPORT-HPORT")
                .multiple(false)
                .require_equals(true)
                .validator(validate::is_port_range),
        )
        .arg(
            Arg::with_name("rand_port_range")
                .help("Specify random external port range for WireGuard hosts.")
                .display_order(515)
                .short("R")
                .long("random-port-range")
                .value_name("LPORT-HPORT")
                .multiple(false)
                .require_equals(true)
                .validator(validate::is_port_range),
        )
        .group(ArgGroup::with_name("ports_group")
            .args(&["wg_port", "seq_port_range", "rand_port_range"])
            .required(false))
        .arg(
            Arg::with_name("private_subnet")
                .help("Internal subnet of WireGuard hosts")
                .display_order(600)
                .short("s")
                .long("subnet")
                .value_name("ADDRESS/CIDR")
                .multiple(false)
                .required(false)
                .require_equals(true)
                .default_value("172.16.128.0/24")
                .validator(validate::is_subnet),
        )
        .arg(
            Arg::with_name("no_confirm")
                .help("Skip confirmation screen")
                .short("q")
                .long("quiet")
                .multiple(false)
                .required(false),
        )
        .arg(
            Arg::with_name("keepalive")
                .help("Set a keepalive time (useful if behind NAT)")
                .display_order(605)
                .short("k")
                .long("keepalive")
                .require_equals(true)
                .default_value("0")
                .multiple(false)
                .required(false)
                .validator(validate::is_keepalive),
        )
        .get_matches();

    let mut pub_ips: Vec<Ipv4Addr> = Vec::new();
    if let Some(pub_addrs) = matches.values_of("ip_addr") {
        for raw_addr in pub_addrs {
            if let Ok(clean_addr) = raw_addr.parse() {
                pub_ips.push(clean_addr);
            } else {
                println!("Error parsing address: {}", raw_addr);
                process::exit(1);
            }
        }
    } else {
        println!("Error encountered reading public IPs.");
        process::exit(1);
    }

    let (pub_port, rand_port): (String, bool) = {
        if let Some(raw_port) = matches.value_of("wg_port") {
            if raw_port.parse::<u16>().is_ok() {
                (raw_port.to_string(), false)
            } else {
                println!("Error parsing port: {}", raw_port);
                process::exit(1);
            }
        } else if let Some(raw_port_range) = matches.value_of("seq_port_range") {
            if validate::is_port_range(raw_port_range.to_string()).is_ok() {
                (raw_port_range.to_string(), false)
            } else {
                println!("Error parsing port range: {}", raw_port_range);
                process::exit(1);
            }
        } else if let Some(raw_port_range) = matches.value_of("rand_port_range") {
            if validate::is_port_range(raw_port_range.to_string()).is_ok() {
                (raw_port_range.to_string(), true)
            } else {
                println!("Error parsing port range: {}", raw_port_range);
                process::exit(1);
            }
        } else {
            ("51820".to_string(), false)
        }
    };

    let priv_subnet: Ipv4Net = {
        if let Some(raw_subnet) = matches.value_of("private_subnet") {
            if let Ok(subnet) = raw_subnet.parse() {
                subnet
            } else {
                println!("Error parsing private subnet: {}", raw_subnet);
                process::exit(1);
            }
        } else {
            println!("Error encountered reading subnet.");
            process::exit(1);
        }
    };

    let keepalive: u16 = {
        if let Some(raw_keepalive) = matches.value_of("keepalive") {
            if let Ok(keepalive) = raw_keepalive.parse() {
                keepalive
            } else {
                println!("Error parsing private keepalive: {}", raw_keepalive);
                process::exit(1);
            }
        } else {
            println!("Error encountered reading keepalive.");
            process::exit(1);
        }
    };

    if matches.occurrences_of("private_subnet") == 0 {
        println!(
            "No private subnet specified. Using default: {}",
            "172.16.128.0/24".green()
        );
    }

    if matches.occurrences_of("keepalive") == 0 {
        println!("No keepalive specified. Using default: {}", "0".green());
    }

    if !(matches.is_present("wg_port")
        | matches.is_present("seq_port_range")
        | matches.is_present("rand_port_range"))
    {
        println!(
            "No port or port range specified. Using default: {}",
            "51820".green()
        );
    }

    if let Err(e) = continue_prompt() {
        println!("{}", e);
        process::exit(1);
    }

    let configs = gen_host_configs(&pub_ips, priv_subnet, pub_port, rand_port, keepalive);

    if !matches.is_present("no_confirm") {
        if let Err(e) = confirmation_display(&configs) {
            println!("{}", e);
            process::exit(1);
        }
    }

    for config in &configs {
        match create_config_files(&gen_config_text(config), config.endpoint_addr) {
            Ok((dir, file)) => println!("Created {} in {}", file, dir.display()),
            Err(e) => {
                println!("{}", e);
                process::exit(1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! expected_return_amounts_psk {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let q = $value;
                assert_eq!(q, gen_preshared_keys(q).unwrap().len());
            }
        )*
        }
    }

    macro_rules! expected_return_amounts_x25519 {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let q = $value;
                assert_eq!(q, gen_x25519_keypairs(q).unwrap().len());
            }
        )*
        }
    }

    macro_rules! psk_does_not_repeat {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let q = $value;

                let preshared_keys: Vec<Secret<String>> = gen_preshared_keys(q).unwrap();
                let mut unmasked_keys: Vec<String> = Vec::new();
                for i in 0..preshared_keys.len() {
                    unmasked_keys.push(preshared_keys[i].expose_secret().clone());
                }

                unmasked_keys.sort();
                unmasked_keys.dedup();

                assert_eq!(unmasked_keys.len(), preshared_keys.len());
            }
        )*
        }
    }

    // Make sure that given x, gen_preshared_keys()
    // returns x keys
    expected_return_amounts_psk! {
        fn_gen_psk_1_returns_1: 1,
        fn_gen_psk_3_returns_3: 3,
        fn_gen_psk_5_returns_5: 5,
        fn_gen_psk_8_returns_8: 8,
        fn_gen_psk_16_returns_16: 16,
    }

    // Make sure that given x, gen_x25519_keypairs()
    // returns x keys
    expected_return_amounts_x25519! {
        fn_gen_x25519_1_returns_1: 1,
        fn_gen_x25519_3_returns_3: 3,
        fn_gen_x25519_5_returns_5: 5,
        fn_gen_x25519_8_returns_8: 8,
        fn_gen_x25519_16_returns_16: 16,
    }

    // Make sure gen_preshared_keys() generates
    // unique output (no dupliate keys)
    psk_does_not_repeat! {
        fn_gen_psk_chk_2_no_repeats: 2,
        fn_gen_psk_chk_4_no_repeats: 4,
        fn_gen_psk_chk_6_no_repeats: 6,
        fn_gen_psk_chk_8_no_repeats: 8,
        fn_gen_psk_chk_16_no_repeats: 16,
    }
}
