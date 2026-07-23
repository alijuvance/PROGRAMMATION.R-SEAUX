# Lightweight Network Intrusion Detection System (NIDS)

A Python-based real-time Network Intrusion Detection System (NIDS) engine designed to detect TCP port scanning attempts using packet inspection and stateful sliding window metrics.

---

## Overview

This project provides a lightweight network monitoring tool built on top of [Scapy](https://scapy.net/). It captures raw Ethernet frames, isolates TCP connection initiation attempts (SYN flags), and evaluates traffic density per source IP address across a sliding time window to identify reconnaissance and scanning activities in real time.

---

## Detection Mechanism

The detection pipeline operates in three distinct phases :

1. **Packet Capture & Filtering:**  
   Sniffs live network traffic on the specified interface and filters for TCP packets containing strictly the `SYN` flag (`flags == "S"`).

2. **Stateful Windowing (Sliding Window):**  
   Maintains an in-memory historical record of targeted destination ports per source IP address (`historique`). Records older than the configured time window (`FENETRE_SECONDES`) are dynamically purged.

3. **Threshold Evaluation & Alerting:**  
   Computes the cardinality of unique destination ports targeted by a source IP within the active window. An alert is raised when the count exceeds the predefined threshold (`SEUIL_PORTS`).

---

## Technical Specifications

| Parameter | Default Value | Description |
| :--- | :--- | :--- |
| `INTERFACE` | `"Ethernet"` | Network interface card (NIC) bound for packet capture. |
| `FENETRE_SECONDES` | `10` | Time window duration (in seconds) for history retention. |
| `SEUIL_PORTS` | `15` | Minimum number of unique destination ports to trigger an alert. |

---

## Prerequisites & Installation

### 1. System Requirements
- **OS:** Windows 10/11 or Linux
- **Python:** 3.8 or higher
- **Driver (Windows only):** [Npcap Driver](https://npcap.com/) (required for Scapy raw packet sniffing)

### 2. Dependency Installation
Install Scapy via `pip`:

```bash
pip install scapy
```

---

## Usage

> **Note:** Raw socket sniffing requires administrator privileges on Windows (Run PowerShell/CMD as Administrator) or `sudo` on Linux.

Execute the main detection script:

```bash
python test_capture.py
```

### Simulating a Port Scan (Validation)
You can validate detection using [Nmap](https://nmap.org/) from another host or locally:

```bash
nmap -sS -p 1-100 <TARGET_IP>
```

---

## Repository Structure

```text
.
├── test_capture.py    # Main NIDS engine script (capture, filtering, detection)
├── Note.txt           # Setup and dependency notes
└── README.md          # Project documentation
```

---

## Roadmap & Future Enhancements

- [ ] Add CLI argument parsing (`argparse`) for runtime parameter tuning.
- [ ] Implement structured file logging (`logging` module / JSON formatted logs).
- [ ] Extend protocol coverage to UDP sweeps and stealth TCP scans (FIN, NULL, XMAS).
- [ ] Refactor codebase into modular packages (`sniffer`, `analyzer`, `notifier`).
