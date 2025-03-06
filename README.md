# Raspberry Pi WireGuard WoL Forwarding & Relay

This guide shows how to set up a reliable Wake-on-LAN (WoL) relay and forwarder using a Raspberry Pi running Debian and WireGuard.

## ✅ Prerequisites

- Raspberry Pi running Debian (or Raspberry Pi OS)
- WireGuard server installed and functional (`wg0` interface active)

## 🛠 Installation

### Step 1: Install Dependencies

```bash
sudo apt update
sudo apt install python3-pip python3-scapy -y
```

### Step 2: Python Scripts

#### `/usr/local/bin/wol_forwarder.py`

```python
#!/usr/bin/env python3
from scapy.all import sniff, sendp, Ether, IP, UDP, Raw

VPN_IFACE = "wg0"
LAN_IFACE = "eth0"
LAN_BROADCAST_IP = "192.168.1.255"

def forward_wol_packet(packet):
    payload = bytes(packet[Raw])
    mac = ':'.join(f'{b:02x}' for b in payload[6:12])
    print(f"Forwarding WoL packet for MAC: {mac_addr}")

    wol_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=LAN_BROADCAST_IP) / UDP(sport=9, dport=9) / Raw(load=payload)
    sendp(wol_packet, iface=LAN_IFACE, verbose=False)

if __name__ == "__main__":
    sniff(iface=VPN_IFACE, filter="udp and dst port 9", prn=lambda pkt: forward_wol_packet(pkt) if Raw in pkt and pkt[Raw].load.startswith(b'\xff'*6) else None)
```

### Step 2: Setup Systemd Services

Create two services:

**`wol-forwarder.service`** (`/etc/systemd/system/wol-forwarder.service`)
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

**`wol-relay.service`** (`/etc/systemd/system/wol-relay.service`)
```ini
[Unit]
Description=WireGuard WoL Relay
After=network.target

[Service]
ExecStart=/usr/local/bin/wol_relay.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

### Step 2: Enable and Run

Make scripts executable:

```bash
sudo chmod +x /usr/local/bin/wol_forwarder.py
sudo chmod +x /usr/local/bin/wol_relay.py
```

Reload systemd and enable services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable wol-forwarder.service
sudo systemctl enable wol-relay.service
sudo systemctl start wol-forwarder.service
sudo systemctl start wol-relay.service
```

## 🔍 Check Status

```bash
sudo systemctl status wol-forwarder.service
sudo systemctl status wol-relay.service
```

### View Logs

```bash
sudo journalctl -u wol-forwarder.service -f
sudo journalctl -u wol-relay.service -f
```

## 🧹 Remove Old Bash Scripts (optional)

Clean up old Bash scripts and services:

```bash
sudo systemctl stop wol-forwarder wol-relay
sudo systemctl disable wol-forwarder wol-relay
sudo rm /etc/systemd/system/wol-forwarder.service /etc/systemd/system/wol-relay.service
sudo rm /usr/local/bin/wol_forwarder.sh /usr/local/bin/wolrelay.sh
sudo systemctl daemon-reload
```

Your Raspberry Pi now forwards WoL packets reliably from WireGuard clients to your LAN! 🎉
