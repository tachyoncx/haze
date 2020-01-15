# Haze (Work in Progress)
## About
Given an arbitrary number of WireGuard hosts, Haze generates (rather, *will* generate) the wg0.conf files needed for a full mesh topology. Each host is assigned a private address from the desired subnet, a keypair, and is made aware of peers' addresses and public keys. Additionally, for each pair of peers, Haze generates and assigns a unique preshared key.

## Uses:
- [x25519_dalek](https://docs.rs/x25519-dalek/0.6.0/x25519_dalek/) to generate keypairs
- [OsRng](https://docs.rs/rand/0.7.3/rand/rngs/struct.OsRng.html) to generate preshared keys
- The [secrecy](https://docs.rs/secrecy/0.6.0/secrecy/index.html) crate to handle secrets
- [Clap](https://docs.rs/clap/2.33.0/clap/) to parse command line arguments

## Example Four-Node Topology
![Four-node topology](/resources/haze_1.png)

## To-do
- Tidy up and pay off debt accrued while battling the borrow checker
- Expand on the tests for existing functions 
- ~~Add option to randomize ports for hosts~~
- ~~Add option to exclude specific private IPs within the private subnet~~
- ~~Finish generating the fully-formed wg0.confs (currently prints the information to stdout)~~
- Add option to encrypt the config files with a password
    - I'm thinking AES-256/PBKDF2-SHA3-512 (500K iterations)
    - Instead of encrypted_blob.txt, output a Python script with the ciphertext inline as a variable. Use python/cryptography to read in the ciphertext, salt, and encryption parameters. Then request a user password, derive the key, and decrypt directly to /etc/wg0.conf.
- Add option to generate all the scp commands needed to transport configs to each server

## --help
```
user@workstation % ./haze --help

Haze 0.1
Shane S. <elliptic@tachyon.cx>
Generates configuration files for arbitrarily-sized WireGuard mesh networks.

USAGE:
    haze [FLAGS] [OPTIONS] --endpoints=<IP>...

FLAGS:
    -h, --help       Prints help information
    -q, --quiet      Skip confirmation screen
    -V, --version    Prints version information

OPTIONS:
    -e, --endpoints=<IP>...                  Specify external addresses of WireGuard hosts
    -p, --port=<PORT>                        Specify external port of WireGuard hosts [default: 51820]
    -r, --port-range=<LPORT-HPORT>           Specify external port range for WireGuard hosts. Wraps if range is less
                                             than available hosts.
    -R, --random-port-range=<LPORT-HPORT>    Specify random external port range for WireGuard hosts.
    -s, --subnet=<ADDRESS/CIDR>              Internal subnet of WireGuard hosts [default: 172.16.128.0/24]
    -k, --keepalive=<keepalive>              Set a keepalive time (useful if behind NAT) [default: 0]
    -x, --exclude=<IP>...                    Specify excluded internal IP addresses

EXAMPLES:
	./haze --endpoints=45.45.45.2,45.45.45.3 --port=51820 --subnet=10.0.0.0/24
	./haze --endpoints=45.45.45.2,45.45.45.3,45.45.45.4 --random-port-range=50000-50100 --subnet=192.168.50.128/25
```

## Expected functionality
```
user@workstation:~$ haze --endpoints=20.20.20.20,21.21.21.21,22.22.22.22 --port=51000 --subnet=10.0.0.0/24 --encrypt
Please enter password: ************************
Configurations generated: wg2020202020.py, wg21212121.1.py, wg2222222222.py

user@workstation:~$ scp wg2020202020.py remote_user@20.20.20.20:/home/remote_user/configs/
user@workstation:~$ ssh remote_user@20.20.20.20

remote_user@20.20.20.20:~$ sudo ./configs/wg20202020.py
Please enter password: ************************
Configuration extracted to /etc/wireguard/wg0.conf
```
## A Note on Security
I'm not a professional. Can't make any guarantees.