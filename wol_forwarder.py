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
