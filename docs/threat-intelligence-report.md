# Threat Intelligence Report
## SSH/Telnet Honeypot — 15-Day Deployment Analysis

**Sensor:** Cowrie medium-interaction honeypot (Debian VPS)
**Collection window:** 10–24 June 2026 (≈15 days)
**Classification:** TLP:CLEAR

---

## 1. Executive Summary

A medium-interaction SSH and Telnet honeypot was deployed on an internet-facing Debian VPS and left in monitored operation for roughly fifteen days. The objective was to observe live, unsolicited attack traffic against a freshly exposed host, characterise the adversaries, and triage any malware delivered to the sensor. No service was advertised; all traffic arrived through opportunistic internet-wide scanning.

Within minutes of exposure the sensor began receiving automated login attempts. Over the full window it recorded **335,553 events** from **879 unique source IPs**, **39,998 authentication attempts**, and **21 distinct malware samples**. The captured payloads map to three threat classes: a self-propagating IRC-controlled botnet worm, the Redtail cryptomining loader, and defensive "cleaner" scripts that evict competing malware.

| Metric | Value |
|---|---|
| Total events | 335,553 |
| Unique source IPs | 879 |
| Authentication attempts | 39,998 |
| Unique sessions | 42,033 |
| Malware samples | 21 |
| Distinct families | 3+ |
| Most-used credential | `0` / `0` |

---

## 2. Sensor Architecture & Methodology

Cowrie emulates a full Linux shell. Attackers can "log in", run commands and attempt downloads inside a sandbox that never executes their code, while every keystroke, credential and file is logged.

| Port | Role |
|---|---|
| 22 / 23 | Exposed; redirected to Cowrie |
| 2223 | Cowrie listener |
| 2222 | Real admin SSH, key-based only |

Traffic redirected with NAT prerouting; real SSH moved off port 22 to prevent operator lockout; Cowrie ran as an unprivileged systemd service with log rotation.

---

## 3. Volumetric & Source Analysis

Traffic was highly concentrated — a few IPs produced most of it, signalling dedicated brute-force infrastructure.

| Source IP | Events | Observation |
|---|---|---|
| 176.65.132.24 | 24,946 | Highest-volume |
| 176.65.132.129 | 18,258 | Same /24 — coordinated |
| 179.43.133.154 | 16,137 | Sustained attack |
| 176.65.132.22 | 12,473 | Same /24 |
| 45.153.34.112 | 12,473 | Identical volume — shared tooling |

**Analyst note:** repeated /24 ranges (176.65.132.0/24, 45.156.87.0/24, 45.153.34.0/24) with near-identical event counts indicate rented host blocks running one toolkit, with an attack list distributed evenly across a fleet.

---

## 4. Credential Intelligence

| Username / Password | Attempts | Category |
|---|---|---|
| `0` / `0` | 1,791 | Default / IoT |
| `1234` / `1234` | 338 | Trivial numeric |
| `admin` / `admin` | 212 | Default appliance |
| `root` / *(blank)* | 128 | Privileged, no password |
| `root` / `root` | 103 | Privileged default |
| `ubuntu` / `ubuntu` | 102 | Cloud-image default |

The list is IoT- and privilege-focused. **Every credential here is defeated by disabling password authentication and forbidding root login** — the exact config used on the sensor's admin port.

---

## 5. Post-Compromise Behaviour

Behaviour was uniform — fully automated tooling. Dominant first action: host reconnaissance.

| Command | Count | Purpose |
|---|---|---|
| `uname -s -v -n -r -m` | 33,971 | OS/kernel fingerprint |
| `export PATH=...` | 736 | Normalise environment |
| `cat /proc/uptime` | 736 | Uptime / sandbox check |
| `uname -a` | 87 | Full system string |

**Reconstructed attacker playbook:**

1. Brute-force SSH with a weak-credential dictionary
2. Fingerprint host via `uname` (OS + CPU architecture)
3. Normalise environment, perform sandbox checks
4. Download an architecture-matched payload
5. Establish persistence and propagate (SSH keys, self-replication)

A single HASSH client fingerprint drove **34,524 sessions** — one tool behind the bulk of the campaign.

---

## 6. Malware Triage

21 samples: 10 ELF binaries plus shell loaders. Three distinct behaviours emerged.

### 6.1 Family A — IRC Botnet Worm
*Detection 39/75 · `36.sh`*

The most complete payload captured — simultaneously a backdoor installer, an IRC bot, and an internet worm:

- **Persistence:** copies itself to `/opt`, writes an `/etc/rc.local` entry, installs an attacker-controlled SSH key in `/root/.ssh/authorized_keys`
- **Rival eviction:** kills competing miners (`minerd`, `kaiten`, `ktx-*`) and blackholes a rival domain via `/etc/hosts`
- **C2:** connects to Undernet IRC on port 6667, joins channel `#biret`; commands arrive base64-encoded and **RSA-signed**, verified against a bundled public key before execution
- **Worm:** installs `zmap` + `sshpass`, scans the internet for port 22 in 100,000-host batches, logs into Raspberry Pis with default `raspberry` credentials, and copies itself via SCP

### 6.2 Family B — Redtail Cryptominer
*Detection 27/74 · `setup.sh`*

A modern, stealth-conscious loader. It detects CPU architecture, locates a writable non-`noexec` directory with ≥2 MB free, deploys the matching `redtail.<arch>` binary, and removes staging files. Resource-theft malware targeting cloud CPUs.

### 6.3 Family C — Competitor "Cleaner" Scripts
*Detection 21/73 · `clean_sh`*

These scripts attack **other malware**, not the host. They disable the `c3pool_miner` service, strip rival crontab entries, wipe `/tmp`, `/var/tmp` and `/dev/shm`, and kill masquerading processes (`systemtd`, fake `-bash`). Their presence proves multiple actors were fighting over the same machine.

### 6.4 ELF Binaries
The standout `discord-exploit` (45/74 — highest in the set) is a likely RAT / token stealer. The remaining unnamed binaries are most consistent with DDoS bots and additional miners. Full reverse-engineering is recommended as follow-on work.

---

## 7. Indicators of Compromise (IOCs)

**Network:**
- `176.65.132.0/24`, `45.156.87.0/24`, `45.153.34.0/24` — brute-force clusters
- `179.43.133.154`, `91.92.40.10`
- IRC `:6667` channel `#biret` (Undernet) — botnet C2
- `bins.deutschland-zahlung.eu` — rival domain blackholed by the worm

**Host:**
- Unexpected key in `/root/.ssh/authorized_keys`
- `/etc/rc.local` entry pointing to a random `/opt` binary
- Hidden executables in `/tmp`, `/var/tmp`, `/dev/shm`
- Presence of `zmap` / `sshpass`
- Outbound connections to TCP 6667

**File hashes (SHA-256):**

| Hash | Family |
|---|---|
| `6d1fe6ab…267c9b` | IRC worm |
| `783adb7a…7e0d59` | Redtail |
| `197c7440…78daf8` | Cleaner |
| `94f2e4d8…5da4c00` | discord-exploit |

---

## 8. Defensive Recommendations

1. Disable password authentication; permit key-based login only
2. Forbid direct root login (`PermitRootLogin no`)
3. Eliminate default accounts and passwords (especially on IoT)
4. Restrict SSH exposure via firewall allow-list or VPN
5. Alert on outbound IRC (TCP 6667) and the appearance of `zmap` / `sshpass`
6. Monitor `authorized_keys`, `rc.local` and crontabs for unauthorised changes

---

## 9. Conclusion

In fifteen days an unadvertised Debian host attracted over a third of a million malicious events from nearly 900 sources and was served 21 malware samples across three behavioural classes. Three takeaways:

- **Exposure equals compromise** — attackers find and brute-force new SSH services within minutes, unprovoked
- **The threat is automated and industrialised** — uniform tooling, distributed rented infrastructure, architecture-aware payloads
- **The attack surface is contested territory** — malware families actively evict one another to monopolise a single low-value VPS

None of the observed attacks were sophisticated zero-days. They were commodity campaigns exploiting weak and default credentials — and every one is stopped by key-based authentication. **Disciplined fundamentals neutralise the overwhelming majority of real-world intrusion attempts.**

---

*A Word version of this report is available at [`SSH-Honeypot-Threat-Intelligence-Report.docx`](SSH-Honeypot-Threat-Intelligence-Report.docx).*
