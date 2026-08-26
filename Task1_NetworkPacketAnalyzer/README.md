# Network Packet Analyzer

A small Python tool that captures live network traffic, extracts key
details from each packet (source/destination IP, protocol, ports, size),
prints them in a color-coded live view, and saves everything to a CSV
file for review.

Built for the CodSoft Cyber Security Internship — Task 1.

## What it does

- Captures packets in real time using Scapy
- Identifies protocol (TCP / UDP / ICMP)
- Extracts source IP, destination IP, ports, packet length, and a short
  payload preview
- Prints a clean, color-coded live table in the terminal
- Logs every packet to a timestamped CSV file
- Prints a summary at the end: total packets, protocol breakdown, and
  the busiest (top-talker) source IPs

## Setup

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Install a packet capture driver

Scapy needs a lower-level driver to actually read raw packets off the
network card.

- **Windows:** install [Npcap](https://npcap.com/#download) (check
  "Install Npcap in WinPcap API-compatible Mode" during setup).
- **Linux:** you likely already have `libpcap` — if not:
  `sudo apt install libpcap-dev`
- **Mac:** `brew install libpcap`

### 3. Run as Administrator / root

Packet sniffing needs elevated privileges.

- **Windows:** open Command Prompt or PowerShell "as Administrator",
  then run the script.
- **Linux/Mac:** run with `sudo`.

## Usage

List available network interfaces:

```bash
python packet_analyzer.py --list-interfaces
```

Start capturing (all traffic, until you hit Ctrl+C):

```bash
python packet_analyzer.py
```

Capture only TCP traffic on a specific interface:

```bash
python packet_analyzer.py -i "Wi-Fi" -p tcp
```

Capture exactly 50 packets and save to a specific file:

```bash
python packet_analyzer.py -c 50 -o my_capture.csv
```

## Sample output

```
14:32:10 | TCP    |    192.168.1.5:51322 -> 142.250.183.14:443    |   517 bytes
14:32:10 | UDP    |    192.168.1.5:60112 -> 8.8.8.8    :53        |    72 bytes | ..google.com...
...
============================================================
CAPTURE SUMMARY
============================================================
Duration        : 42.3 seconds
Total packets   : 318

Protocol breakdown:
  TCP    :   241  (75.8%)
  UDP    :    68  (21.4%)
  ICMP   :     9  (2.8%)

Top 5 source IPs (busiest devices):
  192.168.1.5          182 packets
  192.168.1.1          54 packets
  ...
============================================================
```

## How this maps to the task requirements

| Requirement | Where it's handled |
|---|---|
| Capture packets transmitted over a network | `sniff()` in `main()` |
| Inspect packets to understand protocol behavior | `process_packet()` / `get_protocol_name()` |
| Extract source IP, dest IP, protocol, packet data | `process_packet()` |
| Use Scapy/Socket for capturing | Built entirely on Scapy |
| Present captured info clearly | Live color-coded table + CSV export + end summary |

## Notes / things I'd improve with more time

- Add a `--live-chart` mode showing protocol % updating in real time
- Resolve IPs to hostnames (reverse DNS) as an optional flag
- Flag unusually large numbers of SYN packets as a possible port-scan
  indicator
