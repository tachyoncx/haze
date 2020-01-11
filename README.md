## Haze
### About
Given an arbitrary number of hosts, Haze generates (rather, *will* generate) the wg0.conf files needed for a full mesh topology. Each host is assigned a private address from the desired subnet, a keypair, and is made aware of peers' addresses and public keys. Additionally, for each pair of peers, it generates and assigns a unique preshared key.

### To-do
- Expand on the tests for existing functions 
- Finish generating the fully-formed wg0.confs (currently prints the information to stdout)
- Add option to encrypt the config outputs with a password
    - AES-256/PBKDF2-SHA3-512 500k
    - Instead of encrypted_blob.txt, output a Python script with the ciphertext inline as a variable. Use python/cryptography to read in the blobvar, request a user password, derive the key, and decrypt directly to /etc/wg0.conf.
- Add option to generate all the scp commands needed to transport configs to each server

### Expected functionality
```
user@workstation:~$ haze --external-ips=20.20.20.20,21.21.21.21,22.22.22.22 --port 51000 --subnet 10.0.0.0/24 --encrypt
Please enter password: ************************
Configurations generated: wg2020202020.py, wg21212121.1.py, wg2222222222.py

user@workstation:~$ scp wg2020202020.py remote_user@20.20.20.20:/home/remote_user/configs/
user@workstation:~$ ssh remote_user@20.20.20.20

remote_user@20.20.20.20:~$ sudo ./configs/wg20202020.py
Please enter password: ************************
Configuration extracted to /etc/wireguard/wg0.conf