#!/usr/bin/env python3
"""
CodeAlpha_NetworkIntrusionDetectionSystem
alert_monitor.py  (Python 3.5+ compatible)
"""

import argparse
import json
import time
import os
from collections import Counter
from datetime import datetime

BLOCKLIST_FILE = "blocklist.txt"
HIGH_SEVERITY_THRESHOLD = 2


def parse_alert(line):
    try:
        event = json.loads(line)
    except ValueError:
        return None
    if event.get("event_type") != "alert":
        return None
    return event


def format_alert(event):
    ts = event.get("timestamp", "unknown-time")
    src = event.get("src_ip", "?")
    dst = event.get("dest_ip", "?")
    sig = event.get("alert", {}).get("signature", "unknown signature")
    sev = event.get("alert", {}).get("severity", "?")
    proto = event.get("proto", "?")
    return "[{}] SEV{} {} | {} -> {} ({})".format(ts, sev, sig, src, dst, proto)


def respond_to_alert(event):
    sev = event.get("alert", {}).get("severity", 3)
    src = event.get("src_ip")
    if sev is not None and int(sev) <= HIGH_SEVERITY_THRESHOLD and src:
        existing = set()
        if os.path.exists(BLOCKLIST_FILE):
            with open(BLOCKLIST_FILE) as rf:
                existing = set(l.strip() for l in rf)
        if src not in existing:
            with open(BLOCKLIST_FILE, "a") as f:
                f.write(src + "\n")
            print("  -> [RESPONSE] {} added to {} (apply with: iptables -A INPUT -s {} -j DROP)".format(
                src, BLOCKLIST_FILE, src))


def follow(logfile):
    print("Monitoring {} for alerts... (Ctrl+C to stop)\n".format(logfile))
    with open(logfile, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            event = parse_alert(line)
            if event:
                print(format_alert(event))
                respond_to_alert(event)


def report(logfile):
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
            severities["Severity {}".format(sev)] += 1

    print("\nTotal alerts: {}".format(total))
    print("\nTop signatures:")
    for sig, count in counts.most_common(10):
        print("  {:>4}  {}".format(count, sig))

    print("\nBy severity:")
    for sev, count in severities.most_common():
        print("  {:>4}  {}".format(count, sev))

    if total == 0:
        print("\nNo alerts found - nothing to chart.")
        return

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        top = counts.most_common(10)
        labels = [s[:40] for s, _ in top]
        values = [c for _, c in top]

        y_pos = list(range(len(labels)))
        plt.figure(figsize=(10, 6))
        plt.barh(y_pos, values[::-1], color="#c0392b")
        plt.yticks(y_pos, labels[::-1])
        plt.xlabel("Alert count")       
        plt.title("Suricata Alerts by Signature - {}".format(
            datetime.now().strftime("%Y-%m-%d %H:%M")))
        plt.tight_layout()
        plt.savefig("alert_summary.png", dpi=150)
        print("\nChart saved to alert_summary.png")
    except ImportError:
        print("\n(matplotlib not installed - skipping chart. "
              "Install with: pip3 install matplotlib)")


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
