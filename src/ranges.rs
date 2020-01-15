use super::{Ipv4Addr, Ipv4Net, OsRng};
use rand::seq::SliceRandom;

pub fn enum_port_range(val: &str, randomize: bool) -> Result<Vec<u16>, String> {
    let ports: Vec<&str> = val.split('-').collect();

    if ports.len() == 2 {
        let low_port: u16 = match ports[0].parse() {
            Ok(p) => p,
            Err(_) => return Err("Error parsing first port in the range.".to_string()),
        };
        let high_port: u16 = match ports[1].parse() {
            Ok(p) => p,
            Err(_) => return Err("Error parsing second port in the range.".to_string()),
        };

        if low_port > high_port {
            return Err("Error: low port is higher than upper port.".to_string());
        }

        let mut port_vec: Vec<u16> = (low_port..=high_port).collect();
        if randomize {
            port_vec.shuffle(&mut OsRng);
        }
        Ok(port_vec)
    } else if ports.len() == 1 {
        if let Ok(port) = ports[0].parse() {
            Ok(vec![port])
        } else {
            Err("Error parsing port.".to_string())
        }
    } else {
        Err("Error parsing range (verify format matches 'LPORT-HPORT'".to_string())
    }
}

pub fn enum_subnet(host_count: usize, subnet: Ipv4Net) -> Result<Vec<Ipv4Addr>, String> {
    let mut ip_addresses: Vec<Ipv4Addr> = Vec::new();
    for ip_address in subnet.hosts() {
        ip_addresses.push(ip_address);
    }
    ip_addresses.truncate(host_count);

    if ip_addresses.len() < host_count {
        return Err("Error: too few IPs for hosts.".to_string());
    }

    Ok(ip_addresses)
}

pub fn exclude_addresses(exclude: Vec<Ipv4Addr>, subnet: &mut Vec<Ipv4Addr>) {
    for address in exclude {
        match subnet.binary_search(&address) {
            Ok(index) => {
                subnet.remove(index);
            }
            Err(_) => continue,
        }
    }
}

// Today I learned that factorials overflow quickly.
// Here's another way to calculate the number of combinations
// without using factorials.
// https://stackoverflow.com/a/12130280
pub fn peer_combos(mut n: usize, r: usize) -> Result<usize, String> {
    if r > n {
        return Err(String::from("Error calculating peer combinations."));
    }

    let mut combos = 1;
    for i in 1..=r {
        combos *= n;
        n -= 1;
        combos /= i;
    }
    Ok(combos)
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
                assert_eq!(q, peer_combos(n, r).unwrap());
            }
        )*
        }
    }

    macro_rules! enum_port_range_correctly {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let (q, r) = $value;
                    assert_eq!(r, enum_port_range(&String::from(q), false));
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
                assert_eq!(q, enum_subnet(q, r.parse::<Ipv4Net>().unwrap()).unwrap().len());
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

    enum_port_range_correctly! {
        fn_enum_port_range_5_to_10: (("5-7"), Ok(vec![5,6,7]) ),
        fn_enum_port_range_500_to_600: (("500-502"), Ok(vec![500,501,502]) ),
        fn_enum_port_range_50k_to_51k: (("50000-50002"), Ok(vec![50000,50001,50002]) ),
        fn_enum_port_range_backwards: (("51002-50000"), Err(String::from("Error: low port is higher than upper port.")) ),
        fn_enum_port_range_first_invalid: (("80a-800"), Err(String::from("Error parsing first port in the range.")) ),
        fn_enum_port_range_second_invalid: (("800-80b"), Err(String::from("Error parsing second port in the range.")) ),
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
}
