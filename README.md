# WireGuard Wake-on-LAN Forwarder (Python)

This guide explains how to set up a robust and efficient Wake-on-LAN (WoL) forwarding solution using a Raspberry Pi running Debian (or Raspberry Pi OS) with WireGuard.

This forwarder listens for WoL packets coming through the WireGuard VPN (`wg0`) interface and rebroadcasts them onto your local LAN network (`eth0`).

## 🚀 Prerequisites

- Raspberry Pi running Debian or Raspberry Pi OS
- WireGuard server installed and working (`wg0` interface active)
- Python3 installed

## 📦 Installation

### Step 1: Install Dependencies

```bash
sudo apt update
sudo apt install python3-pip python3-scapy -y
```

### Step 2: Create Forwarder Script

Save this script to `/usr/local/bin/wol_forwarder.py`:

```python
#!/usr/bin/env python3
from scapy.all import sniff, Ether, IP, UDP, Raw, sendp

VPN_IFACE = "wg0"
LAN_IFACE = "eth0"
LAN_BROADCAST_IP = "192.168.1.255"


def forward_wol_packet(packet):
    payload = bytes(packet[Raw])
    mac_addr = ':'.join(f'{b:02x}' for b in payload[6:12])

    print(f"✅ Detected WoL magic packet for MAC: {mac_addr}. Forwarding...")

    wol_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=LAN_BROADCAST_IP) / UDP(sport=9, dport=9) / Raw(load=payload)
    sendp(wol_packet, iface=LAN_IFACE, verbose=False)
    print(f"📤 Forwarded magic packet to LAN ({LAN_IFACE}).")


if __name__ == "__main__":
    print(f"🔎 Listening for WoL packets on {VPN_IFACE}...")
    sniff(
        iface=VPN_IFACE,
        filter="udp and udp dst port 9",
        prn=lambda pkt: forward_wol_packet(pkt)
        if Raw in pkt and bytes(pkt[Raw]).startswith(b'\xff' * 6)
        else None,
    )
```

Make the script executable:

```bash
sudo chmod +x /usr/local/bin/wol_forwarder.py
```

### Step 2: Setup systemd Service

Create a systemd service at `/etc/systemd/system/wol-forwarder.service`:

```ini
[Unit]
Description=WireGuard WoL Forwarder
After=network.target

[Service]
ExecStart=/usr/local/bin/wol_forwarder.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

Reload and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wol-forwarder
sudo systemctl start wol-forwarder
```

## ✅ Checking Status

To confirm the service is running:

```bash
sudo systemctl status wol-forwarder
```

### Check Logs

```bash
sudo journalctl -u wol-forwarder -f
```

## 🧹 Clean-Up

If you previously had redundant scripts/services:

```bash

```

---

✅ **Your WireGuard Wake-on-LAN forwarder is now configured and running reliably!**
