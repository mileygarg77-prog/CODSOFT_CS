# CodSoft Cyber Security Internship

This repository contains the projects and tasks completed as part of my **Cyber Security Internship at CodSoft**.

The projects in this repository focus on practical cybersecurity concepts, networking, Python programming, and security-related problem solving.

## Internship Tasks

| Task | Project | Status |
|------|---------|--------|
| Task 1 | Network Packet Analyzer | Completed |
| Task 2 | Network Intrusion Detection System | Completed |
| Task 3 | Secure File Sharing System | Completed |
---

## Task 1 – Network Packet Analyzer

A Python-based network packet analyzer developed to capture and inspect network packets.

### Features

- Capture network packets using Python
- Display source and destination IP addresses
- Identify common network protocols
- Extract basic packet information
- Display packet details in a readable format
- Save captured packet information for later analysis

### Technologies Used

- Python
- Scapy
- Networking concepts
- Packet analysis

### Project Structure

```text
Task1_NetworkPacketAnalyzer/
│
├── packet_analyzer.py
├── requirements.txt
├── README.md
└── .gitignore
```

## Task 2 – Network Intrusion Detection System

A lightweight IDS built using Suricata, with custom detection rules and a Python-based alert response script that monitors live network traffic and reacts to threats in real time.

### Features

- Live network traffic monitoring via Suricata
- Custom rules detecting ICMP pings, SSH brute-force attempts, and suspicious HTTP User-Agents
- Python script (`alert_watcher.py`) that tails Suricata's JSON log and logs/responds to alerts in real time
- Structured alert logging for review and analysis

### Technologies Used

- Suricata (IDS engine)
- Python
- Npcap (packet capture)
- Windows

### Project Structure

```text
Task2_NIDS/
├── scripts/
│   └── alert_watcher.py
├── suricata_rules/
│   └── local.rules
├── screenshots/
├── README.md
└── .gitignore
```
## Task 3 – Secure File Sharing System

A backend file-sharing system built with Node.js and Express, focused on secure storage and controlled access rather than just basic upload/download.

### Features
- User authentication with JWT (JSON Web Tokens)
- Passwords hashed with bcrypt before storage
- Files encrypted with AES-256-GCM before being saved to disk
- Role-based access control — users can only access their own files, admins can view all
- SQLite database for users and file metadata

### Technologies Used
- Node.js / Express
- SQLite3
- jsonwebtoken, bcrypt
- Node's built-in crypto module for encryption
- multer for file uploads

### Project Structure
- `routes/auth.js` – signup/login
- `routes/files.js` – upload, download, admin file listing
- `middleware/auth.js` – JWT verification
- `db.js` – database schema and connection
