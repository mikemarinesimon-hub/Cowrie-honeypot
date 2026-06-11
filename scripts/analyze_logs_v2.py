#!/usr/bin/env python3
"""
Cowrie honeypot log analyzer (v2).

Improvements over v1:
  - Reads credentials and login counts from the REAL events
    'cowrie.login.success' and 'cowrie.login.failed'.
    (v1 read 'cowrie.login.attempt', which Cowrie never emits, so the
     credential list was always empty.)
  - Reads every rotated log file automatically (cowrie.json, cowrie.json.YYYY-MM-DD).
  - Adds HASSH client fingerprints and a downloaded-payload list.
  - Reconstructs the attack playbook (ordered command sequence) for the
    most active attackers.

Usage:
    python3 analyze_logs_v2.py                     # auto: all cowrie.json* in LOG_DIR
    python3 analyze_logs_v2.py file1 file2 ...      # explicit files
"""

import sys
import json
import glob
import os
from collections import Counter, defaultdict

LOG_DIR = "/home/cowrie/cowrie/var/log/cowrie"

# How many "most insistent" attackers to show a command playbook for
TOP_ATTACKERS_PLAYBOOK = 5
# Max sessions to print per attacker (avoid flooding the terminal)
MAX_SESSIONS_PER_IP = 3


def get_log_files():
    """Return explicit args, or every rotated cowrie.json* in LOG_DIR."""
    if len(sys.argv) > 1:
        files = []
        for a in sys.argv[1:]:
            expanded = glob.glob(a)
            files.extend(expanded if expanded else [a])
        return files
    return sorted(glob.glob(os.path.join(LOG_DIR, "cowrie.json*")))


def load_logs(files):
    logs = []
    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            print(f"[!] Not found, skipped: {path}", file=sys.stderr)
    return logs


def describe_event(ev):
    """One-line human description of a session event, for the playbook."""
    eid = ev.get("eventid", "")
    if eid == "cowrie.login.success":
        return f"LOGIN OK    {ev.get('username')!r}/{ev.get('password')!r}"
    if eid == "cowrie.login.failed":
        return f"LOGIN FAIL  {ev.get('username')!r}/{ev.get('password')!r}"
    if eid == "cowrie.command.input":
        return f"CMD         {ev.get('input', '')}"
    if eid == "cowrie.session.file_download":
        return f"DOWNLOAD    sha256={ev.get('shasum', '?')}"
    if eid == "cowrie.session.file_upload":
        return f"UPLOAD      sha256={ev.get('shasum', '?')}"
    return None


def analyze(logs):
    print("=" * 60)
    print("🍯 HONEYPOT ANALYSIS REPORT")
    from datetime import datetime, timezone
    print(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')} UTC")
    print("=" * 60)

    print(f"\n📊 Total events captured: {len(logs)}")

    ips = [l["src_ip"] for l in logs if "src_ip" in l]
    print(f"🌍 Unique attacking IPs: {len(set(ips))}")

    print("\n🔥 Top 10 attacking IPs:")
    ip_counter = Counter(ips)
    for ip, count in ip_counter.most_common(10):
        print(f"   {ip:20s} → {count} events")

    # --- Logins: read BOTH real events --------------------------------------
    failed  = [l for l in logs if l.get("eventid") == "cowrie.login.failed"]
    success = [l for l in logs if l.get("eventid") == "cowrie.login.success"]
    attempts = len(failed) + len(success)

    print(f"\n🔑 Login attempts (failed + success): {attempts}")
    print(f"   ├─ failed:  {len(failed)}")
    print(f"   └─ success: {len(success)}")

    # Credentials from BOTH events (this is the v1 bug fix)
    creds = [(l.get("username", "?"), l.get("password", "?")) for l in failed + success]
    print("\n🔓 Top 10 credentials tried:")
    for (user, pwd), count in Counter(creds).most_common(10):
        print(f"   {user!r}/{pwd!r} → {count}x")

    # --- Commands -----------------------------------------------------------
    commands = [l["input"] for l in logs
                if l.get("eventid") == "cowrie.command.input" and l.get("input")]
    if commands:
        print("\n💻 Top 10 commands executed:")
        for cmd, count in Counter(commands).most_common(10):
            shown = cmd if len(cmd) <= 60 else cmd[:57] + "..."
            print(f"   {shown:60s} → {count}x")

    # --- Client fingerprints (group attackers by tool) ----------------------
    hassh = [l["hassh"] for l in logs
             if l.get("eventid") == "cowrie.client.kex" and l.get("hassh")]
    if hassh:
        print("\n🧬 Top 5 client fingerprints (HASSH):")
        for h, count in Counter(hassh).most_common(5):
            print(f"   {h} → {count} sessions")

    # --- Downloaded payloads ------------------------------------------------
    downloads = [l.get("shasum", "?") for l in logs
                 if l.get("eventid") == "cowrie.session.file_download"]
    if downloads:
        print(f"\n📥 Payloads downloaded: {len(downloads)}")
        for sha, count in Counter(downloads).most_common(10):
            print(f"   {sha} → {count}x")

    sessions = set(l.get("session") for l in logs if l.get("session"))
    print(f"\n🔗 Unique sessions: {len(sessions)}")

    # --- ATTACK PLAYBOOKS: command sequence per top attacker ----------------
    attack_playbooks(logs, ip_counter)


def attack_playbooks(logs, ip_counter):
    """Reconstruct the ordered command sequence for the most active attackers."""
    # Build per-session timelines (timestamp-ordered)
    sessions = defaultdict(list)   # session_id -> list of events
    session_ip = {}                # session_id -> src_ip
    for l in logs:
        sid = l.get("session")
        if not sid:
            continue
        sessions[sid].append(l)
        if l.get("src_ip"):
            session_ip[sid] = l["src_ip"]

    # Which IPs actually ran commands? Those are the interesting ones.
    ips_with_cmds = Counter()
    for l in logs:
        if l.get("eventid") == "cowrie.command.input" and l.get("src_ip"):
            ips_with_cmds[l["src_ip"]] += 1

    if not ips_with_cmds:
        print("\n⚔️  No interactive commands were executed (brute-force only).")
        return

    print("\n" + "=" * 60)
    print("⚔️  ATTACK PLAYBOOKS — command sequence of top attackers")
    print("=" * 60)

    for ip, cmd_count in ips_with_cmds.most_common(TOP_ATTACKERS_PLAYBOOK):
        print(f"\n▶ {ip}  ({ip_counter[ip]} events, {cmd_count} commands)")

        # This attacker's sessions, ordered by their first timestamp
        ip_sessions = [sid for sid, ip2 in session_ip.items() if ip2 == ip]
        ip_sessions.sort(key=lambda s: min(e.get("timestamp", "") for e in sessions[s]))

        shown = 0
        for sid in ip_sessions:
            evs = sorted(sessions[sid], key=lambda e: e.get("timestamp", ""))
            timeline = [(e.get("timestamp", "")[11:19], describe_event(e))
                        for e in evs if describe_event(e)]
            if not timeline:
                continue   # session with no login/command/download (just noise)
            if shown >= MAX_SESSIONS_PER_IP:
                remaining = len(ip_sessions) - shown
                print(f"     … and more sessions from this IP")
                break
            print(f"   session {sid}:")
            for ts, desc in timeline:
                print(f"     {ts}  {desc}")
            shown += 1


if __name__ == "__main__":
    files = get_log_files()
    if not files:
        print(f"No log files found in {LOG_DIR}")
        sys.exit(1)
    analyze(load_logs(files))
