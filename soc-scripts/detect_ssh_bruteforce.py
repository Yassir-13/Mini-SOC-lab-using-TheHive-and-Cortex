#!/usr/bin/env python3
"""
SSH Brute Force Detector
Watches /var/log/auth.log for failed SSH attempts from Kali IP.
Sends an alert to TheHive when threshold is exceeded.
"""

import re
import time
import uuid
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict
from thehive4py import TheHiveApi
from config import (
    THEHIVE_URL, THEHIVE_API_KEY, KALI_IP,
    SSH_LOG_FILE, SSH_MAX_FAILURES, SSH_TIME_WINDOW
)


def create_thehive_client():
    return TheHiveApi(url=THEHIVE_URL, apikey=THEHIVE_API_KEY)


def send_alert(hive, source_ip, attempt_count, failed_users):
    """Send SSH brute force alert to TheHive."""
    source_ref = f"ssh-bf-{source_ip}-{uuid.uuid4().hex[:8]}"
    user_list = ", ".join(set(failed_users))

    alert = {
        "type": "ssh-bruteforce",
        "source": "ssh-detector",
        "sourceRef": source_ref,
        "title": f"[SSH Brute Force] {attempt_count} failed attempts from {source_ip}",
        "description": (
            f"## SSH Brute Force Attack Detected\n\n"
            f"- **Source IP:** `{source_ip}`\n"
            f"- **Failed attempts:** {attempt_count} in {SSH_TIME_WINDOW} seconds\n"
            f"- **Targeted users:** {user_list}\n"
            f"- **Threshold:** {SSH_MAX_FAILURES} attempts / {SSH_TIME_WINDOW}s\n"
            f"- **Detection time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"**Recommendation:** Block the source IP and investigate."
        ),
        "severity": 2,  # Medium
        "tlp": 2,       # TLP:AMBER
        "pap": 2,       # PAP:AMBER
        "tags": ["ssh", "brute-force", "kali", source_ip],
        "observables": [
            {
                "dataType": "ip",
                "data": source_ip,
                "message": f"Attacker IP - {attempt_count} failed SSH attempts",
                "tags": ["attacker", "ssh"],
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
    # Start from end of file
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
    print("  SSH Brute Force Detector")
    print(f"  Monitoring: {SSH_LOG_FILE}")
    print(f"  Watching for: {KALI_IP}")
    print(f"  Threshold: {SSH_MAX_FAILURES} failures in {SSH_TIME_WINDOW}s")
    print("=" * 60)

    hive = create_thehive_client()

    # Track failed attempts: ip -> list of timestamps
    failed_attempts = defaultdict(list)
    # Track usernames targeted
    failed_users = defaultdict(list)
    # Cooldown: don't spam alerts for same IP
    last_alert_time = {}

    # Patterns for failed SSH auth
    patterns = [
        re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
        re.compile(r"authentication failure.*rhost=(\S+).*user=(\S+)"),
        re.compile(r"Invalid user (\S+) from (\S+)"),
    ]

    for line in follow_log(SSH_LOG_FILE):
        source_ip = None
        username = None

        for pattern in patterns:
            match = pattern.search(line)
            if match:
                groups = match.groups()
                if "rhost=" in line:
                    source_ip, username = groups[0], groups[1]
                else:
                    username, source_ip = groups[0], groups[1]
                break

        if not source_ip:
            continue

        # Filter: only watch for our Kali IP (remove this line to watch all IPs)
        if source_ip != KALI_IP:
            continue

        now = datetime.now()
        failed_attempts[source_ip].append(now)
        failed_users[source_ip].append(username)

        # Clean old entries outside the time window
        cutoff = now - timedelta(seconds=SSH_TIME_WINDOW)
        failed_attempts[source_ip] = [
            t for t in failed_attempts[source_ip] if t > cutoff
        ]

        count = len(failed_attempts[source_ip])
        print(f"  [{now.strftime('%H:%M:%S')}] Failed SSH: {username}@{source_ip} ({count}/{SSH_MAX_FAILURES})")

        # Check threshold
        if count >= SSH_MAX_FAILURES:
            # Cooldown: don't alert more than once per 5 minutes for same IP
            if source_ip in last_alert_time:
                if (now - last_alert_time[source_ip]).seconds < 300:
                    continue

            send_alert(hive, source_ip, count, failed_users[source_ip])
            last_alert_time[source_ip] = now
            failed_attempts[source_ip] = []
            failed_users[source_ip] = []


if __name__ == "__main__":
    main()
