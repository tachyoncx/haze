use super::{Ipv4Addr, Ipv4Net};

// Is this input string an IP?
pub fn is_ip(ip: String) -> Result<(), String> {
    if ip.parse::<Ipv4Addr>().is_ok() {
        Ok(())
    } else {
        Err("Error parsing IP address.".to_string())
    }
}

// Is this input string a valid port or keepalive?
pub fn is_keepalive(keepalive: String) -> Result<(), String> {
    if let Ok(integer) = keepalive.parse::<u32>() {
        if integer < 65536 {
            Ok(())
        } else {
            Err("Error: valid keepalive range is 0-65535.".to_string())
        }
    } else {
        Err("Error parsing keepalive.".to_string())
    }
}

// Is this input string a valid port or keepalive?
pub fn is_port(val: String) -> Result<(), String> {
    if let Ok(integer) = val.parse::<u32>() {
        if (integer > 0) && (integer < 65536) {
            Ok(())
        } else {
            Err("Error: valid port range is 1-65535.".to_string())
        }
    } else {
        Err("Error parsing port number.".to_string())
    }
}

// Wrapper function for parse_port_range that only returns Ok()/Err()
pub fn is_port_range(val: String) -> Result<(), String> {
    let ports: Vec<&str> = val.split('-').collect();

    if ports.len() == 2 {
        let low_port: u16 = match ports[0].parse() {
            Ok(p) => p,
            Err(_) => return Err("Error parsing first port in range.".to_string()),
        };
        let high_port: u16 = match ports[1].parse() {
            Ok(p) => p,
            Err(_) => return Err("Error parsing second port in range.".to_string()),
        };

        if low_port > high_port {
            return Err("Error: first port in range is higher than second.".to_string());
        }

        return Ok(());
    }
    Err("Error parsing range (verify format matches 'LPORT-HPORT'".to_string())
}

// Is this input string a subnet?
pub fn is_subnet(val: String) -> Result<(), String> {
    if val.parse::<Ipv4Net>().is_ok() {
        Ok(())
    } else {
        Err("Error parsing subnet.".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    macro_rules! is_keepalive_works_correctly {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let (q, r) = $value;
                    assert_eq!(r, is_keepalive(String::from(q)));
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

    macro_rules! is_port_range_works_correctly {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let (q, r) = $value;
                    assert_eq!(r, is_port_range(String::from(q)));
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

    is_ip_works_correctly! {
        fn_is_ip_rfc_1918a: ("10.0.0.0", Ok(()) ),
        fn_is_ip_rfc_1918b: ("172.16.0.0", Ok(()) ),
        fn_is_ip_rfc_1918c: ("192.168.0.0", Ok(()) ),
        fn_is_ip_invalid_octet: ("192.168.256.0", Err(String::from("Error parsing IP address."))),
        fn_is_ip_extra_octet: ("192.168.256.0.0", Err(String::from("Error parsing IP address."))),
    }

    is_keepalive_works_correctly! {
        fn_is_keepalive_0: ("0", Ok(()) ),
        fn_is_keepalive_25: ("25", Ok(()) ),
        fn_is_keepalive_65535: ("65535", Ok(()) ),
        fn_is_keepalive_65536: ("65536", Err(String::from("Error: valid keepalive range is 0-65535."))),
        fn_is_keepalive_chars: ("abcd", Err(String::from("Error parsing keepalive."))),
    }

    is_port_works_correctly! {
        fn_is_port_256: ("256", Ok(()) ),
        fn_is_port_2048: ("2048", Ok(()) ),
        fn_is_port_65535: ("65535", Ok(()) ),
        fn_is_port_65536: ("65536", Err(String::from("Error: valid port range is 1-65535."))),
        fn_is_port_neg_1: ("-1", Err(String::from("Error parsing port number."))),
    }

    is_port_range_works_correctly! {
        fn_is_port_range_50_to_75: ("50-75", Ok(())),
        fn_is_port_range_50k_plus_25: ("50000-50025", Ok(())),
        fn_is_port_range_reversed_range: ("50025-50000", Err(String::from("Error: first port in range is higher than second."))),
        fn_is_port_range_invalid_first_port: ("655bb-65538", Err(String::from("Error parsing first port in range."))),
        fn_is_port_range_invalid_second_port: ("6665-7abc", Err(String::from("Error parsing second port in range."))),
        fn_is_port_range_bad_syntax: ("700-800-900", Err(String::from("Error parsing range (verify format matches 'LPORT-HPORT'"))),
    }

    is_subnet_works_correctly! {
        fn_is_subnet_rfc1918a: ("10.0.0.0/8", Ok(()) ),
        fn_is_subnet_rfc1918b: ("172.16.0.0/12", Ok(()) ),
        fn_is_subnet_rfc1918c: ("192.168.0.0/16", Ok(()) ),
        fn_is_subnet_invalid_octet: ("11.11.256.0/8", Err(String::from("Error parsing subnet."))),
        fn_is_subnet_invalid_prefix: ("11.11.11.0/33", Err(String::from("Error parsing subnet."))),
    }
}
