#!/usr/bin/env python3
"""
CodeAlpha_NetworkIntrusionDetectionSystem
alert_monitor.py

Monitors Suricata's eve.json log in (near) real time, prints a live
alert feed, summarizes alerts by signature/severity, generates a
bar-chart visualization, and demonstrates a basic automated response
mechanism (adding offending source IPs to a local blocklist file that
can be fed into iptables/ufw).

Usage:
    python3 alert_monitor.py --logfile /var/log/suricata/eve.json --follow
    python3 alert_monitor.py --logfile /var/log/suricata/eve.json --report

Requires:
    pip install matplotlib
"""

import argparse
import json
import time
import os
from collections import Counter
from datetime import datetime

BLOCKLIST_FILE = "blocklist.txt"
HIGH_SEVERITY_THRESHOLD = 2  # Suricata severity: 1=high, 2=medium, 3=low


def parse_alert(line: str):
    """Parse a single eve.json line; return the event dict if it's an alert."""
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None
    if event.get("event_type") != "alert":
        return None
    return event


def format_alert(event: dict) -> str:
    ts = event.get("timestamp", "unknown-time")
    src = event.get("src_ip", "?")
    dst = event.get("dest_ip", "?")
    sig = event.get("alert", {}).get("signature", "unknown signature")
    sev = event.get("alert", {}).get("severity", "?")
    proto = event.get("proto", "?")
    return f"[{ts}] SEV{sev} {sig} | {src} -> {dst} ({proto})"


def respond_to_alert(event: dict):
    """Basic automated response: log high-severity source IPs to a blocklist."""
    sev = event.get("alert", {}).get("severity", 3)
    src = event.get("src_ip")
    if sev is not None and int(sev) <= HIGH_SEVERITY_THRESHOLD and src:
        with open(BLOCKLIST_FILE, "a") as f:
            existing = set()
            if os.path.exists(BLOCKLIST_FILE):
                with open(BLOCKLIST_FILE) as rf:
                    existing = set(l.strip() for l in rf)
            if src not in existing:
                f.write(f"{src}\n")
                print(f"  -> [RESPONSE] {src} added to {BLOCKLIST_FILE} "
                      f"(apply with: iptables -A INPUT -s {src} -j DROP)")


def follow(logfile: str):
    """Tail the eve.json file and print/respond to alerts as they arrive."""
    print(f"Monitoring {logfile} for alerts... (Ctrl+C to stop)\n")
    with open(logfile, "r") as f:
        f.seek(0, os.SEEK_END)  # start at end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            event = parse_alert(line)
            if event:
                print(format_alert(event))
                respond_to_alert(event)


def report(logfile: str):
    """Read the whole log, summarize alerts by signature, and chart them."""
    counts = Counter()
    severities = Counter()
    total = 0

    with open(logfile, "r") as f:
        for line in f:
            event = parse_alert(line)
            if not event:
                continue
            total += 1
            sig = event.get("alert", {}).get("signature", "unknown")
            sev = event.get("alert", {}).get("severity", "?")
            counts[sig] += 1
            severities[f"Severity {sev}"] += 1

    print(f"\nTotal alerts: {total}")
    print("\nTop signatures:")
    for sig, count in counts.most_common(10):
        print(f"  {count:>4}  {sig}")

    print("\nBy severity:")
    for sev, count in severities.most_common():
        print(f"  {count:>4}  {sev}")

    if total == 0:
        print("\nNo alerts found — nothing to chart.")
        return

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        top = counts.most_common(10)
        labels = [s[:40] for s, _ in top]
        values = [c for _, c in top]

        plt.figure(figsize=(10, 6))
        plt.barh(labels[::-1], values[::-1], color="#c0392b")
        plt.xlabel("Alert count")
        plt.title(f"Suricata Alerts by Signature — {datetime.now():%Y-%m-%d %H:%M}")
        plt.tight_layout()
        plt.savefig("alert_summary.png", dpi=150)
        print("\nChart saved to alert_summary.png")
    except ImportError:
        print("\n(matplotlib not installed — skipping chart. "
              "Install with: pip install matplotlib)")


def main():
    parser = argparse.ArgumentParser(description="Suricata eve.json alert monitor")
    parser.add_argument("--logfile", default="/var/log/suricata/eve.json",
                         help="Path to Suricata eve.json")
    parser.add_argument("--follow", action="store_true",
                         help="Live-tail the log and respond to new alerts")
    parser.add_argument("--report", action="store_true",
                         help="Summarize and chart existing alerts in the log")
    args = parser.parse_args()

    if args.follow:
        follow(args.logfile)
    elif args.report:
        report(args.logfile)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
