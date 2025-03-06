#!/usr/bin/env python3
from scapy.all import sniff, Ether, IP, UDP, Raw, sendp

VPN_IFACE = "wg0"
LAN_IFACE = "eth0"
LAN_BROADCAST_IP = "192.168.1.255"

def is_wol_magic_packet(packet):
    payload = bytes(packet[Raw])
    return payload.startswith(b'\xff'*6)

def forward_wol_packet(packet):
    payload = bytes(packet[Raw])
    mac_addr = ':'.join(f'{b:02x}' for b in payload[6:12])

    print(f"✅ Detected WoL magic packet for MAC: {mac_addr}. Forwarding...")

    wol_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=LAN_BROADCAST_IP) / UDP(sport=9, dport=9) / Raw(load=payload)
    sendp(wol_packet, iface="eth0", verbose=False)
    print(f"📤 Forwarded magic packet to LAN (eth0).")

if __name__ == "__main__":
    print("🔎 Listening for WoL packets on wg0...")
    sniff(iface="wg0", filter="udp and udp dst port 9",
          prn=lambda pkt: forward_wol_packet(pkt) if Raw in pkt and is_wol_magic_packet(pkt) else None)
