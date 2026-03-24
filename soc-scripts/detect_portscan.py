#!/usr/bin/env python3
"""
Port Scan Detector
Uses iptables logging to detect port scans from Kali IP.
Sends an alert to TheHive when threshold is exceeded.

PREREQUISITE - Run these iptables rules first (the setup.sh script does this):
  sudo iptables -N PORTSCAN_LOG 2>/dev/null
  sudo iptables -A PORTSCAN_LOG -j LOG --log-prefix "PORTSCAN: " --log-level 4
  sudo iptables -A INPUT -s KALI_IP -p tcp --syn -j PORTSCAN_LOG
"""

import re
import uuid
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from thehive4py import TheHiveApi
from config import (
    THEHIVE_URL, THEHIVE_API_KEY, KALI_IP,
    SCAN_LOG_FILE, SCAN_THRESHOLD, SCAN_TIME_WINDOW
)


def create_thehive_client():
    return TheHiveApi(url=THEHIVE_URL, apikey=THEHIVE_API_KEY)


def send_alert(hive, source_ip, port_count, ports_hit):
    """Send port scan alert to TheHive."""
    source_ref = f"portscan-{source_ip}-{uuid.uuid4().hex[:8]}"
    port_list = ", ".join(str(p) for p in sorted(ports_hit)[:30])

    alert = {
        "type": "port-scan",
        "source": "scan-detector",
        "sourceRef": source_ref,
        "title": f"[Port Scan] {port_count} ports scanned from {source_ip}",
        "description": (
            f"## Port Scan Detected\n\n"
            f"- **Source IP:** `{source_ip}`\n"
            f"- **Ports scanned:** {port_count} in {SCAN_TIME_WINDOW} seconds\n"
            f"- **Ports hit:** {port_list}\n"
            f"- **Threshold:** {SCAN_THRESHOLD} ports / {SCAN_TIME_WINDOW}s\n"
            f"- **Detection time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"**Recommendation:** This is likely reconnaissance. "
            f"Monitor for follow-up exploitation attempts."
        ),
        "severity": 2,  # Medium
        "tlp": 2,
        "pap": 2,
        "tags": ["scan", "nmap", "reconnaissance", source_ip],
        "observables": [
            {
                "dataType": "ip",
                "data": source_ip,
                "message": f"Scanner IP - {port_count} ports scanned",
                "tags": ["attacker", "scanner"],
                "ioc": True
            }
        ]
    }

    try:
        result = hive.alert.create(alert=alert)
        print(f"[!] ALERT SENT -> {alert['title']} (ID: {result['_id']})")
    except Exception as e:
        print(f"[ERROR] Failed to send alert: {e}")


def follow_log(filepath):
    """Tail a log file, yielding new lines as they appear."""
    proc = subprocess.Popen(
        ["tail", "-F", filepath],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    for line in iter(proc.stdout.readline, ''):
        yield line.strip()


def main():
    print("=" * 60)
    print("  Port Scan Detector")
    print(f"  Monitoring: /var/log/kern.log (iptables PORTSCAN logs)")
    print(f"  Watching for: {KALI_IP}")
    print(f"  Threshold: {SCAN_THRESHOLD} ports in {SCAN_TIME_WINDOW}s")
    print("=" * 60)

    hive = create_thehive_client()

    # Track scanned ports: ip -> list of (timestamp, port)
    scan_events = defaultdict(list)
    last_alert_time = {}

    # Pattern to match iptables PORTSCAN log entries
    pattern = re.compile(
        r"PORTSCAN: .*SRC=(\S+).*DPT=(\d+)"
    )

    # Monitor kernel log where iptables writes
    for line in follow_log("/var/log/kern.log"):
        if "PORTSCAN:" not in line:
            continue

        match = pattern.search(line)
        if not match:
            continue

        source_ip = match.group(1)
        dest_port = int(match.group(2))

        # Filter for Kali IP only (remove to watch all IPs)
        if source_ip != KALI_IP:
            continue

        now = datetime.now()
        scan_events[source_ip].append((now, dest_port))

        # Clean old entries
        cutoff = now - timedelta(seconds=SCAN_TIME_WINDOW)
        scan_events[source_ip] = [
            (t, p) for t, p in scan_events[source_ip] if t > cutoff
        ]

        # Count unique ports
        unique_ports = set(p for _, p in scan_events[source_ip])
        count = len(unique_ports)

        print(f"  [{now.strftime('%H:%M:%S')}] SYN -> port {dest_port} from {source_ip} ({count}/{SCAN_THRESHOLD})")

        # Check threshold
        if count >= SCAN_THRESHOLD:
            if source_ip in last_alert_time:
                if (now - last_alert_time[source_ip]).seconds < 300:
                    continue

            send_alert(hive, source_ip, count, unique_ports)
            last_alert_time[source_ip] = now
            scan_events[source_ip] = []


if __name__ == "__main__":
    main()
