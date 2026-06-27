# Cowrie SSH/Telnet Honeypot — Threat Intelligence Project

A medium-interaction SSH/Telnet honeypot deployed on an internet-facing Debian VPS to capture, analyse and document real-world attack traffic. Over a 15-day collection window the sensor recorded **335,553 events** from **879 unique source IPs** and captured **21 distinct malware samples** across three threat families.

---

## Overview

This project deploys [Cowrie](https://github.com/cowrie/cowrie) to emulate a vulnerable Linux host, attracting opportunistic internet-wide scanning and brute-force attacks. Every credential, command and downloaded payload is logged for analysis. No service was advertised — all traffic arrived through automated scanning.

## Architecture
Internet (attackers)

│

▼

Port 22 / 23  ──redirect──►  Cowrie listener (2223)

│

▼

JSON event logs

│

▼

Python analysis pipeline

| Port | Role |
|------|------|
| 22 / 23 | Exposed to the internet; redirected to Cowrie |
| 2223 | Cowrie listener (emulated shell) |
| 2222 | Real admin SSH, key-based authentication only |

## Key Findings

| Metric | Value |
|--------|-------|
| Total events | 335,553 |
| Unique source IPs | 879 |
| Authentication attempts | 39,998 |
| Unique sessions | 42,033 |
| Malware samples captured | 21 |
| Distinct malware families | 3+ |
| Most-used credential | `0` / `0` |

### Malware families identified

- **IRC botnet worm** — backdoor + IRC C2 (Undernet, channel `#biret`) with RSA-signed commands; self-propagates by scanning for Raspberry Pis with default credentials.
- **Redtail cryptominer** — architecture-aware loader that deploys a CPU miner.
- **Competitor "cleaner" scripts** — malware that removes rival miners/bots to monopolise the host.

Full analysis: [`docs/SSH-Honeypot-Threat-Intelligence-Report.docx`](docs/SSH-Honeypot-Threat-Intelligence-Report.docx)

## Repository Structure
.

├── config/      # Cowrie configuration

├── docs/        # Threat intelligence report

├── samples/     # Anonymised sample logs

├── scripts/     # Log analysis pipeline

└── README.md

## Usage

Run the analysis pipeline against Cowrie's JSON logs:

```bash
python3 scripts/analyze_logs_v2.py
```

The analyser aggregates source IPs, credential pairs, executed commands, client (HASSH) fingerprints and downloaded payloads.

## Tools & Technologies

- **Cowrie** — medium-interaction SSH/Telnet honeypot
- **Debian VPS** — sensor platform
- **iptables** — port redirection
- **Python 3** — log analysis
- **VirusTotal** — malware triage

## Defensive Takeaways

Every attack observed was a commodity campaign exploiting weak or default credentials. All are defeated by:

- Disabling password authentication (key-based only)
- Forbidding direct root login
- Removing default accounts and passwords
- Restricting SSH exposure via firewall or VPN

## Disclaimer

This project was conducted for educational and research purposes in a controlled, isolated environment. All captured data is anonymised. Malware samples are referenced by hash only and are not distributed.
