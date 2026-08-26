"""
Network Packet Analyzer
------------------------
CodSoft Cyber Security Internship - Task 1

Captures live packets off the network, pulls out the useful fields
(source/dest IP, protocol, ports, size), prints them in a readable
live table, and logs everything to a CSV file for later review.

"""

import argparse
import csv
import os
import sys
import time
from collections import Counter
from datetime import datetime

from colorama import Fore, Style, init as colorama_init
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list

colorama_init(autoreset=True)

# Colors per protocol so the live output is easy to scan at a glance
PROTOCOL_COLORS = {
    "TCP": Fore.CYAN,
    "UDP": Fore.YELLOW,
    "ICMP": Fore.MAGENTA,
    "OTHER": Fore.WHITE,
}

# Running stats, updated as packets come in
stats = {
    "total": 0,
    "protocol_counts": Counter(),
    "top_talkers": Counter(),   # source IPs seen
    "start_time": None,
}

captured_rows = []  # buffered rows, written to CSV at the end


def get_protocol_name(pkt):
    if pkt.haslayer(TCP):
        return "TCP"
    elif pkt.haslayer(UDP):
        return "UDP"
    elif pkt.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def get_payload_preview(pkt, max_len=30):
    """Grab a short, safe preview of the raw payload bytes, if any."""
    if pkt.haslayer(Raw):
        try:
            raw_bytes = bytes(pkt[Raw].load)
            preview = raw_bytes[:max_len]
            # replace anything non-printable so it doesn't wreck the terminal
            text = "".join(chr(b) if 32 <= b <= 126 else "." for b in preview)
            return text
        except Exception:
            return ""
    return ""


def process_packet(pkt):
    if not pkt.haslayer(IP):
        return  # skip non-IP traffic (ARP etc.) for this task

    ip_layer = pkt[IP]
    proto = get_protocol_name(pkt)

    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    length = len(pkt)

    src_port = dst_port = "-"
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    payload_preview = get_payload_preview(pkt)
    timestamp = datetime.now().strftime("%H:%M:%S")

    # update stats
    stats["total"] += 1
    stats["protocol_counts"][proto] += 1
    stats["top_talkers"][src_ip] += 1

    # store for CSV export
    captured_rows.append({
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": proto,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": length,
        "payload_preview": payload_preview,
    })

    # live console output
    color = PROTOCOL_COLORS.get(proto, Fore.WHITE)
    line = (
        f"{Fore.LIGHTBLACK_EX}{timestamp}{Style.RESET_ALL} | "
        f"{color}{proto:<6}{Style.RESET_ALL} | "
        f"{src_ip:>15}:{str(src_port):<6} -> {dst_ip:<15}:{str(dst_port):<6} | "
        f"{length:>5} bytes"
    )
    if payload_preview:
        line += f" | {Fore.GREEN}{payload_preview}{Style.RESET_ALL}"

    print(line)


def save_to_csv(filename):
    if not captured_rows:
        print(f"{Fore.YELLOW}No packets captured, nothing to save.{Style.RESET_ALL}")
        return

    fieldnames = ["timestamp", "src_ip", "dst_ip", "protocol",
                  "src_port", "dst_port", "length", "payload_preview"]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(captured_rows)

    print(f"\n{Fore.GREEN}Saved {len(captured_rows)} packets to {filename}{Style.RESET_ALL}")


def print_summary():
    duration = time.time() - stats["start_time"]
    print("\n" + "=" * 60)
    print(f"{Fore.CYAN}CAPTURE SUMMARY{Style.RESET_ALL}")
    print("=" * 60)
    print(f"Duration        : {duration:.1f} seconds")
    print(f"Total packets   : {stats['total']}")

    print("\nProtocol breakdown:")
    for proto, count in stats["protocol_counts"].most_common():
        color = PROTOCOL_COLORS.get(proto, Fore.WHITE)
        pct = (count / stats["total"] * 100) if stats["total"] else 0
        print(f"  {color}{proto:<6}{Style.RESET_ALL} : {count:>5}  ({pct:.1f}%)")

    print("\nTop 5 source IPs (busiest devices):")
    for ip, count in stats["top_talkers"].most_common(5):
        print(f"  {ip:<20} {count} packets")
    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(description="Simple network packet analyzer")
    parser.add_argument("-i", "--interface", default=None,
                         help="Network interface to sniff on (default: scapy picks one)")
    parser.add_argument("-p", "--protocol", default=None, choices=["tcp", "udp", "icmp"],
                         help="Only capture this protocol")
    parser.add_argument("-c", "--count", type=int, default=0,
                         help="Stop after N packets (default: run until Ctrl+C)")
    parser.add_argument("-o", "--output", default=None,
                         help="CSV output filename (default: auto-generated with timestamp)")
    parser.add_argument("--list-interfaces", action="store_true",
                         help="List available network interfaces and exit")
    args = parser.parse_args()

    if args.list_interfaces:
        print("Available interfaces:")
        for iface in get_if_list():
            print(f"  - {iface}")
        sys.exit(0)

    bpf_filter = args.protocol if args.protocol else None

    output_file = args.output or f"packet_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

    print(f"{Fore.CYAN}Network Packet Analyzer{Style.RESET_ALL}")
    print(f"Interface : {args.interface or 'auto'}")
    print(f"Filter    : {bpf_filter or 'all traffic'}")
    print(f"Saving to : {output_file}")
    print(f"{Fore.LIGHTBLACK_EX}Press Ctrl+C to stop capturing{Style.RESET_ALL}\n")

    stats["start_time"] = time.time()

    try:
        sniff(
            iface=args.interface,
            filter=bpf_filter,
            prn=process_packet,
            count=args.count,
            store=False,
        )
    except PermissionError:
        print(f"{Fore.RED}Permission denied. Run this script as Administrator/root.{Style.RESET_ALL}")
        sys.exit(1)
    except KeyboardInterrupt:
        pass
    finally:
        print_summary()
        save_to_csv(output_file)


if __name__ == "__main__":
    main()
