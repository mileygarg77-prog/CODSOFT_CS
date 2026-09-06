# Task 2 - Network Intrusion Detection System

A lightweight IDS built using Suricata, with custom detection rules and a Python-based alert response script.

## Features

- Live network traffic monitoring via Suricata
- Custom rules detecting ICMP pings, SSH brute-force attempts, and suspicious HTTP User-Agents
- Python script (`alert_watcher.py`) that tails Suricata's JSON log and logs/responds to alerts in real time

## Tools Used

- Suricata (IDS engine)
- Python 3
- Windows (Npcap for packet capture)

## How to Run

1. Install Suricata and configure `HOME_NET` in `suricata.yaml`
2. Copy `suricata_rules/local.rules` into Suricata's rules directory and reference it in `suricata.yaml`
3. Start Suricata: `suricata -c suricata.yaml -i <interface> -vvvv`
4. In a separate terminal, run: `python scripts/alert_watcher.py`
5. Generate test traffic (e.g. `ping 8.8.8.8`) and watch alerts appear live

## Screenshots

See the `screenshots/` folder for Suricata running, live alerts, and logs.
