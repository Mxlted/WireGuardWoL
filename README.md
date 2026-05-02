# WireGuard Wake-on-LAN Forwarder (Python)

## Overview

This project provides a simple and reliable Wake-on-LAN (WoL) forwarding
service for networks connected through WireGuard.

It listens for WoL magic packets on a WireGuard interface and
rebroadcasts them to the local network. This enables remote wake
functionality for devices on a private LAN without exposing broadcast
traffic directly over the VPN.

## Features

-   Listens for WoL packets on a WireGuard interface
-   Forwards packets to LAN broadcast address
-   Zero-dependency Python implementation (stdlib only)
-   Runs as a persistent systemd service

## Requirements

-   Raspberry Pi or Linux host running Debian or Raspberry Pi OS
-   WireGuard configured and active
-   Python 3 (no pip packages needed)
-   Root privileges

## Network Assumptions

-   WireGuard interface: `wg0`
-   LAN interface: `eth0`
-   LAN broadcast address: `192.168.1.255`

Adjust these values in the script if your environment differs.

## Installation

### 1. Enable IP Forwarding

Edit sysctl configuration:

``` bash
sudo nano /etc/sysctl.conf
```

Ensure the following line is present:

``` bash
net.ipv4.ip_forward=1
```

Apply changes:

``` bash
sudo sysctl -p
```

### 2. Configure Firewall (iptables only)

If using iptables:

``` bash
sudo iptables -A INPUT -p udp --dport <YOUR_PORT> -j ACCEPT
sudo iptables -A INPUT -i wg0 -p udp --dport 9 -j ACCEPT
```

Skip this step if using ufw.

### 3. Install Python 3

``` bash
sudo apt update
sudo apt install python3 -y
```

### 4. Create Forwarder Script

``` bash
sudo nano /usr/local/bin/wol_forwarder.py
```

Paste the following:

``` python
#!/usr/bin/env python3
import socket

VPN_IFACE = "wg0"
LAN_IFACE = "eth0"
LAN_BROADCAST_IP = "192.168.1.255"
WOL_PORT = 9
SO_BINDTODEVICE = 25


def is_wol_magic_packet(payload):
    return payload.startswith(b'\xff' * 6)


def main():
    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    recv_sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, VPN_IFACE.encode())
    recv_sock.bind(('', WOL_PORT))

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    send_sock.setsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, LAN_IFACE.encode())

    print("🔎 Listening for WoL packets on wg0...")

    while True:
        payload, addr = recv_sock.recvfrom(1024)
        if is_wol_magic_packet(payload):
            mac_addr = ':'.join(f'{b:02x}' for b in payload[6:12])
            print(f"✅ Detected WoL magic packet for MAC: {mac_addr}. Forwarding...")
            send_sock.sendto(payload, (LAN_BROADCAST_IP, WOL_PORT))
            print(f"📤 Forwarded magic packet to LAN (eth0).")


if __name__ == "__main__":
    main()
```

Make executable:

``` bash
sudo chmod +x /usr/local/bin/wol_forwarder.py
```

### 5. Create systemd Service

``` bash
sudo nano /etc/systemd/system/wol-forwarder.service
```

``` ini
[Unit]
Description=WireGuard Wake-on-LAN Forwarder
After=network.target

[Service]
ExecStart=/usr/local/bin/wol_forwarder.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Enable and start:

``` bash
sudo systemctl daemon-reload
sudo systemctl enable wol-forwarder
sudo systemctl start wol-forwarder
```

## Verification

Check service status:

``` bash
sudo systemctl status wol-forwarder
```

View logs:

``` bash
sudo journalctl -u wol-forwarder -f
```

## Uninstall

``` bash
sudo systemctl stop wol-forwarder
sudo systemctl disable wol-forwarder
sudo rm /etc/systemd/system/wol-forwarder.service
sudo rm /usr/local/bin/wol_forwarder.py
sudo systemctl daemon-reload
```

## Notes

-   Ensure target devices support Wake-on-LAN and have it enabled in
    BIOS and OS settings.
-   Confirm MAC address and subnet broadcast are correct.
-   Packet forwarding depends on correct interface configuration.
