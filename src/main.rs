use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::{Path, PathBuf};
use std::{fmt, fs, path, process};

use base64;
use chrono::Local;
use clap::{App, Arg};
use colored::*;
use ipnet::Ipv4Net;
use itertools::Itertools;
use rand_core::{OsRng, RngCore};
use rpassword::prompt_password_stdout;
use secrecy::{ExposeSecret, Secret};
use x25519_dalek::{PublicKey, StaticSecret};

enum HzErr {
    CalcComb,
    DirErr,
    FileErr,
    FileExists,
    GenKeyPair,
    GenPSK,
    ParseIP,
    ParsePort,
    ParseSubnet,
    PortRange,
    TooFewIPs,
    UserCancel,
    UserInput,
    UserPrompt,
}

impl fmt::Display for HzErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HzErr::CalcComb => write!(f, "Error host calculating pair combinations."),
            HzErr::DirErr => write!(f, "Error creating directory for configuration files."),
            HzErr::FileErr => write!(f, "Error creating file."),
            HzErr::FileExists => write!(f, "Error: file already exists."),
            HzErr::GenKeyPair => write!(f, "Error generating keypair."),
            HzErr::GenPSK => write!(f, "Error generating preshared key."),
            HzErr::ParseIP => write!(f, "Error parsing IP address."),
            HzErr::ParsePort => write!(f, "Error parsing port."),
            HzErr::ParseSubnet => write!(f, "Error parsing subnet."),
            HzErr::PortRange => write!(f, "Valid port range: 1 - 65535."),
            HzErr::TooFewIPs => write!(f, "Too few IPs in specified subnet."),
            HzErr::UserCancel => write!(f, "User cancelled."),
            HzErr::UserInput => write!(f, "Unable to interpret input."),
            HzErr::UserPrompt => write!(f, "Encountered error at user prompt."),
        }
    }
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone)]
struct HostPeer {
    endpoint_addr: SocketAddrV4,
    priv_addr: Ipv4Addr,
    pub_key: String,
    preshared_key: Secret<String>,
}

impl PartialEq for HostPeer {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint_addr == other.endpoint_addr
    }
}

// Today I learned that factorials overflow quickly.
// Here's another way to calculate the number of combinations
// without using factorials.
// https://stackoverflow.com/a/12130280
fn calc_combinations(mut n: usize, r: usize) -> Result<usize, String> {
    if r > n {
        return Err(HzErr::CalcComb.to_string());
    }

    let mut combos = 1;
    for i in 1..=r {
        combos *= n;
        n -= 1;
        combos /= i;
    }
    Ok(combos)
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

fn check_and_create_conf_file(dir: &PathBuf, file: &str, text: &str) -> Result<String, String> {
    let path = Path::new(dir).join(file);

    if path.exists() {
        return Err(HzErr::FileExists.to_string());
    } else if fs::write(path, text).is_err() {
        return Err(HzErr::FileErr.to_string());
    }

    Ok(file.to_string())
}

fn create_config_files(
    config_text: &str,
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
    if let Ok(response) = prompt_password_stdout("\nDoes everything look OK? (y/n) ") {
        match &response.to_ascii_lowercase()[..1] {
            "y" => Ok(()),
            "n" => Err(HzErr::UserCancel.to_string()),
            _ => Err(HzErr::UserInput.to_string()),
        }
    } else {
        Err(HzErr::UserPrompt.to_string())
    }
}

fn enum_subnet(host_count: usize, subnet: Ipv4Net) -> Result<Vec<Ipv4Addr>, String> {
    let mut ip_addresses: Vec<Ipv4Addr> = Vec::new();
    for ip_address in subnet.hosts() {
        ip_addresses.push(ip_address);
    }

    if ip_addresses.len() < host_count {
        return Err(HzErr::TooFewIPs.to_string());
    }

    Ok(ip_addresses)
}

fn gen_config_text(host_conf: &HostConfig) -> String {
    let addr_line = format!("Address = {}", host_conf.priv_addr);
    let key_line = format!("PrivateKey = {}", host_conf.priv_key.expose_secret());
    let port_line = format!("ListenPort = {}", host_conf.endpoint_addr.port());
    let mut text = format!("[Interface]\n{}\n{}\n{}\n", addr_line, key_line, port_line);

    for peer in &host_conf.peers {
        let key_line = format!("PublicKey = {}", peer.pub_key);
        let psk_line = format!("PreSharedKey = {}", peer.preshared_key.expose_secret());
        let endpnt_line = format!("Endpoint = {}", peer.endpoint_addr);
        let addr_line = format!("AllowedIPs = {}/32", peer.priv_addr);
        text = format!(
            "{}\n[Peer]\n{}\n{}\n{}\n{}\n",
            text, key_line, psk_line, endpnt_line, addr_line
        );
    }
    text
}

fn gen_host_configs(pub_ips: &[Ipv4Addr], priv_subnet: Ipv4Net, port: u16) -> Vec<HostConfig> {
    let host_count = pub_ips.len();
    let mut priv_addresses = enum_subnet(host_count, priv_subnet).unwrap();
    priv_addresses.truncate(host_count);
    let host_keypairs = gen_x25519_keypairs(host_count).unwrap();

    let host_pair_count = calc_combinations(host_count, 2).unwrap();
    let host_pair_psks = gen_preshared_keys(host_pair_count).unwrap();

    let mut hosts: Vec<HostConfig> = Vec::with_capacity(host_count);
    for (i, j) in priv_addresses.iter().enumerate() {
        hosts.push(HostConfig {
            endpoint_addr: SocketAddrV4::new(pub_ips[i], port),
            priv_addr: *j,
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
        };
        let peer_1 = HostPeer {
            endpoint_addr: j[1].endpoint_addr,
            priv_addr: j[1].priv_addr,
            pub_key: j[1].pub_key.clone(),
            preshared_key: host_pair_psks[i].clone(),
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
    }

    if keys.is_empty() {
        return Err(HzErr::GenPSK.to_string());
    }
    Ok(keys)
}

fn gen_x25519_keypairs(host_count: usize) -> Result<Vec<(Secret<String>, String)>, String> {
    let mut keypairs: Vec<(Secret<String>, String)> = Vec::with_capacity(host_count);
    for _ in 0..host_count {
        let secret_key = StaticSecret::new(&mut OsRng);
        let pub_key = PublicKey::from(&secret_key);
        let keypair = (
            Secret::new(base64::encode(&secret_key.to_bytes())),
            base64::encode(&pub_key.as_bytes()),
        );
        keypairs.push(keypair);
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

// Is this input string an IP?
fn is_ip(val: String) -> Result<(), String> {
    if val.parse::<Ipv4Addr>().is_ok() {
        Ok(())
    } else {
        Err(HzErr::ParseIP.to_string())
    }
}

// Is this input string a port?
fn is_port(val: String) -> Result<(), String> {
    if let Ok(integer) = val.parse::<u32>() {
        if (integer > 0) && (integer < 65536) {
            Ok(())
        } else {
            Err(HzErr::PortRange.to_string())
        }
    } else {
        Err(HzErr::ParsePort.to_string())
    }
}

// Is this input string a subnet?
fn is_subnet(val: String) -> Result<(), String> {
    if val.parse::<Ipv4Net>().is_ok() {
        Ok(())
    } else {
        Err(HzErr::ParseSubnet.to_string())
    }
}
fn time_now() -> String {
    Local::now().format("%a-%H-%M").to_string()
}
fn main() {
    let matches = App::new("Haze")
        .version("0.1")
        .author("Shane s. <elliptic@tachyon.cx>")
        .about("Generates configuration files for arbitrarily-sized WireGuard mesh networks.")
        .arg(
            Arg::with_name("public_addresses")
                .help("Specify external addresses of WireGuard hosts")
                .short("e")
                .long("external-ips")
                .takes_value(true)
                .multiple(true)
                .required(true)
                .require_equals(true)
                .value_delimiter(",")
                .validator(is_ip),
        )
        .arg(
            Arg::with_name("public_port")
                .help("Specify external port of WireGuard hosts")
                .short("p")
                .long("port")
                .takes_value(true)
                .multiple(false)
                .required(false)
                .default_value("51820")
                .validator(is_port),
        )
        .arg(
            Arg::with_name("private_subnet")
                .help("Internal subnet of WireGuard hosts")
                .short("s")
                .long("subnet")
                .takes_value(true)
                .multiple(false)
                .required(false)
                .default_value("172.16.128.0/24")
                .validator(is_subnet),
        )
        .arg(
            Arg::with_name("no_confirm")
                .help("Skip confirmation screen")
                .short("q")
                .long("quiet")
                .multiple(false)
                .required(false),
        )
        .get_matches();

    let mut pub_ips: Vec<Ipv4Addr> = Vec::new();
    if let Some(pub_addrs) = matches.values_of("public_addresses") {
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

    let pub_port: u16 = {
        if let Some(raw_port) = matches.value_of("public_port") {
            if let Ok(port) = raw_port.parse() {
                port
            } else {
                println!("Error parsing port: {}", raw_port);
                process::exit(1);
            }
        } else {
            println!("Error encountered reading port.");
            process::exit(1);
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

    if !matches.is_present("public_ports") {
        println!(
            "No public port specified. Using default: {}",
            "51820".green()
        );
    }

    if !matches.is_present("private_addresses") {
        println!(
            "No private subnet specified. Using default: {}",
            "172.16.128.0/24".green()
        );
    }

    let configs = gen_host_configs(&pub_ips, priv_subnet, pub_port);

    if !matches.is_present("no_confirm") {
        if let Err(e) = confirmation_display(&configs) {
            println!("{}", e);
            process::exit(1);
        }
    }

    for config in &configs {
        match create_config_files(&gen_config_text(&config), config.endpoint_addr) {
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

    macro_rules! comb_tests {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (n, r, q) = $value;
                assert_eq!(q, calc_combinations(n, r).unwrap());
            }
        )*
        }
    }

    macro_rules! expected_return_amounts_enum_subnet {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (q, r) = $value;
                assert_eq!(q, enum_subnet(0, r.parse::<Ipv4Net>().unwrap()).unwrap().len());
            }
        )*
        }
    }

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

    macro_rules! is_ip_works_correctly {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let (q, r) = $value;
                    assert_eq!(r, is_ip(String::from(q)));
                }
            )*
            }
    }

    macro_rules! is_port_works_correctly {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let (q, r) = $value;
                    assert_eq!(r, is_port(String::from(q)));
                }
            )*
            }
    }

    macro_rules! is_subnet_works_correctly {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let (q, r) = $value;
                    assert_eq!(r, is_subnet(String::from(q)));
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

    // Ensure calc_combinations() is correct.
    // Tuple: (population, sample, expected combinations)
    comb_tests! {
        fn_calc_combos_0_and_0: (0, 0, 1),
        fn_calc_combos_3_and_2: (3, 2, 3),
        fn_calc_combos_7_and_2: (7, 2, 21),
        fn_calc_combos_12_and_2: (12, 2, 66),
        fn_calc_combos_20_and_2: (20, 2, 190),
    }

    // Ensure that enumerating a subnet returns the expected
    // number of hosts
    expected_return_amounts_enum_subnet! {
        fn_enum_subnet_slash24_is_254: (254, "10.0.0.0/24"),
        fn_enum_subnet_slash25_is_126: (126, "10.0.0.0/25"),
        fn_enum_subnet_slash27_is_30: (30, "10.0.0.0/27"),
        fn_enum_subnet_slash28_is_14: (14, "10.0.0.0/28"),
        fn_enum_subnet_slash29_is_6: (6, "10.0.0.0/29"),
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

    // Verifies is_ip() properly identifies input as correct
    // or incorrect
    is_ip_works_correctly! {
        fn_is_ip_rfc_1918a: ("10.0.0.0", Ok(()) ),
        fn_is_ip_rfc_1918b: ("172.16.0.0", Ok(()) ),
        fn_is_ip_rfc_1918c: ("192.168.0.0", Ok(()) ),
        fn_is_ip_invalid_octet: ("192.168.256.0", Err(String::from("Error parsing IP address."))),
        fn_is_ip_extra_octet: ("192.168.256.0.0", Err(String::from("Error parsing IP address."))),
    }

    // Verifies is_port() properly identifies input as correct
    // or incorrect
    is_port_works_correctly! {
        fn_is_port_256: ("256", Ok(()) ),
        fn_is_port_2048: ("2048", Ok(()) ),
        fn_is_port_65535: ("65535", Ok(()) ),
        fn_is_port_65536: ("65536", Err(String::from("Valid port range: 1 - 65535."))),
        fn_is_port_0: ("0", Err(String::from("Valid port range: 1 - 65535."))),
    }

    // Verifies is_subnet() properly identifies input as correct
    // or incorrect
    is_subnet_works_correctly! {
        fn_is_subnet_rfc1918a: ("10.0.0.0/8", Ok(()) ),
        fn_is_subnet_rfc1918b: ("172.16.0.0/12", Ok(()) ),
        fn_is_subnet_rfc1918c: ("192.168.0.0/16", Ok(()) ),
        fn_is_subnet_invalid_octet: ("11.11.256.0/8", Err(String::from("Error parsing subnet."))),
        fn_is_subnet_invalid_prefix: ("11.11.11.0/33", Err(String::from("Error parsing subnet."))),
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
