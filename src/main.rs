use std::net::{Ipv4Addr, SocketAddrV4};
use std::process;

use base64;
use clap::{App, Arg};
use colored::*;
use ipnet::Ipv4Net;
use itertools::Itertools;
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

// Today I learned that factorials overflow quickly.
// Here's another way to calculate the number of combinations
// without using factorials.
// https://stackoverflow.com/a/12130280

#[derive(Debug, Clone)]
struct HostConfig {
    endpoint_addr: SocketAddrV4,
    priv_addr: Ipv4Addr,
    priv_key: String,
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
    preshared_key: String,
}

impl PartialEq for HostPeer {
    fn eq(&self, other: &Self) -> bool {
        self.endpoint_addr == other.endpoint_addr
    }
}

fn hl_host<T: ToString>(item: T) -> String {
    format!("{}", item.to_string().green())
}

fn hl_peer<T: ToString>(item: T) -> String {
    format!("{}", item.to_string().cyan())
}

fn gen_configs(pub_ips: Vec<Ipv4Addr>, priv_subnet: Ipv4Net, port: u16) -> Vec<HostConfig> {
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

    for pair in paired_configs.iter() {
        let (peer_0, peer_1) = pair;
        for i in 0..hosts.len() {
            if hosts[i].endpoint_addr == peer_1.endpoint_addr {
                hosts[i].push_peer(peer_0.clone());
            }
            if hosts[i].endpoint_addr == peer_0.endpoint_addr {
                hosts[i].push_peer(peer_1.clone());
            }
        }
    }

    hosts
}

fn calc_combinations(mut n: usize, r: usize) -> Result<usize, String> {
    if r > n {
        return Err(String::from("Error calculating host combinations."));
    }

    let mut combos = 1;
    for i in 1..=r {
        combos *= n;
        n = n - 1;
        combos /= i;
    }
    Ok(combos)
}

fn confirmation_display(host_configs: &Vec<HostConfig>) {
    for (i, host) in host_configs.iter().enumerate() {
        println!("\n\n{:^80}", format!("[ Host {} ]", i + 1).bold());
        println!(
            "Public address: {:<40}Private address: {:<40}",
            hl_host(host.endpoint_addr),
            hl_host(host.priv_addr)
        );
        println!("Public key: {}", hl_host(&host.pub_key));
        println!("Private key: {}", hl_host(format!("{:*<42}", "")));

        for (i, peer) in host.peers.iter().enumerate() {
            println!("\n\t{}", format!("[ Peer {} ]", i + 1).bold());
            println!(
                "\tPublic address: {:<32}Private address: {:<40}",
                hl_peer(peer.endpoint_addr),
                hl_peer(peer.priv_addr)
            );
            println!("\tPublic key: {}", hl_peer(&peer.pub_key));
            println!("\tPreshared key: {}", hl_peer(format!("{:*<42}", "")));
        }
    }
}

fn gen_preshared_keys(host_pair_count: usize) -> Result<Vec<String>, String> {
    let mut keys: Vec<String> = Vec::with_capacity(host_pair_count);
    for _ in 0..host_pair_count {
        let mut key: [u8; 32] = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        keys.push(base64::encode(&key));
    }

    if keys.len() < 1 {
        return Err(String::from("Error generating preshared keys."));
    }
    Ok(keys)
}

fn gen_x25519_keypairs(host_count: usize) -> Result<Vec<(String, String)>, String> {
    let mut keypairs: Vec<(String, String)> = Vec::with_capacity(host_count);
    for _ in 0..host_count {
        let secret_key = StaticSecret::new(&mut OsRng);
        let pub_key = PublicKey::from(&secret_key);
        let keypair = (
            base64::encode(&secret_key.to_bytes()),
            base64::encode(&pub_key.as_bytes()),
        );
        keypairs.push(keypair);
    }

    if keypairs.len() < 1 {
        return Err(String::from("Error generating keypairs."));
    }
    Ok(keypairs)
}

fn enum_subnet(host_count: usize, subnet: Ipv4Net) -> Result<Vec<Ipv4Addr>, String> {
    let mut ip_addresses: Vec<Ipv4Addr> = Vec::new();
    for ip_address in subnet.hosts() {
        ip_addresses.push(ip_address);
    }

    if ip_addresses.len() < host_count {
        return Err(String::from("Subnet too small for hosts specified."));
    }

    Ok(ip_addresses)
}

fn is_ip(val: String) -> Result<(), String> {
    if let Ok(_) = val.parse::<Ipv4Addr>() {
        Ok(())
    } else {
        Err(String::from("Error parsing IP address"))
    }
}

fn is_port(val: String) -> Result<(), String> {
    if let Ok(integer) = val.parse::<u32>() {
        if (integer > 0) && (integer < 65536) {
            Ok(())
        } else {
            Err(String::from("The value must be between 0 and 65535"))
        }
    } else {
        Err(String::from("Unable to parse port"))
    }
}

fn is_subnet(val: String) -> Result<(), String> {
    if let Ok(_) = val.parse::<Ipv4Net>() {
        Ok(())
    } else {
        Err(String::from("Error parsing subnet"))
    }
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
                .require_delimiter(true)
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

    let configs = gen_configs(pub_ips, priv_subnet, pub_port);

    if !matches.is_present("no_confirm") {
        confirmation_display(&configs);
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

    macro_rules! psk_does_not_repeat {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let q = $value;

                let mut preshared_keys: Vec<String> = gen_preshared_keys(q).unwrap();
                preshared_keys.sort();

                let mut preshared_keys_ded = preshared_keys.clone();
                preshared_keys_ded.dedup();

                assert_eq!(preshared_keys_ded.len(), preshared_keys.len());
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

    // Ensure calc_combinations() is correct.
    // Tuple: (population, sample, expected combinations)
    comb_tests! {
    combinatations_zero_and_zero: (0, 0, 1),
    combinatations_three_and_two: (3, 2, 3),
    combinatations_seven_and_two: (7, 2, 21),
    combinatations_twelve_and_two: (12, 2, 66),
    combinatations_twenty_and_two: (20, 2, 190),
    }

    // Make sure gen_preshared_keys() generates
    // unique output (no duplicate keys)
    psk_does_not_repeat! {
        gen_two_psk_no_repeats: 2,
        gen_four_psk_no_repeats: 4,
        gen_six_psk_no_repeats: 6,
        gen_eight_psk_no_repeats: 8,
        gen_sixteen_psk_no_repeats: 16,
    }

    // Make sure that given x, gen_preshared_keys()
    // returns x keys
    expected_return_amounts_psk! {
        gen_psk_one_returns_one: 1,
        gen_psk_three_returns_three: 3,
        gen_psk_five_returns_five: 5,
        gen_psk_eight_returns_eight: 8,
        gen_psk_sixteen_returns_sixteen: 16,
    }

    // Make sure that given x, gen_x25519_keypairs()
    // returns x keys
    expected_return_amounts_x25519! {
        gen_x25519_one_returns_one: 1,
        gen_x25519_three_returns_three: 3,
        gen_x25519_five_returns_five: 5,
        gen_x25519_eight_returns_eight: 8,
        gen_x25519_sixteen_returns_sixteen: 16,
    }
}
