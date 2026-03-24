#!/bin/bash
# =============================================================
# SOC Detection Scripts - Setup
# Run this ONCE on your Ubuntu VM before starting the detectors
# =============================================================
set -e

KALI_IP="192.168.37.129"

echo "=============================================="
echo " SOC Detection Scripts - Setup"
echo "=============================================="

# 1. Install Python dependencies
echo ""
echo "[1/4] Installing Python dependencies..."
pip3 install thehive4py --break-system-packages 2>/dev/null || pip3 install thehive4py
echo "  -> thehive4py installed"

# 2. Install inotify-tools (for malware drop detector)
echo ""
echo "[2/4] Installing inotify-tools..."
sudo apt-get update -qq && sudo apt-get install -y -qq inotify-tools
echo "  -> inotify-tools installed"

# 3. Set up iptables rules for port scan detection
echo ""
echo "[3/4] Setting up iptables rules for port scan detection..."
# Create chain if it doesn't exist
sudo iptables -N PORTSCAN_LOG 2>/dev/null || true
# Flush existing rules in the chain
sudo iptables -F PORTSCAN_LOG 2>/dev/null || true
# Add LOG rule
sudo iptables -A PORTSCAN_LOG -j LOG --log-prefix "PORTSCAN: " --log-level 4
# Add rule to INPUT chain (avoid duplicates)
sudo iptables -C INPUT -s $KALI_IP -p tcp --syn -j PORTSCAN_LOG 2>/dev/null || \
    sudo iptables -I INPUT -s $KALI_IP -p tcp --syn -j PORTSCAN_LOG
echo "  -> iptables rules set for $KALI_IP"

# 4. Create watched directory for malware drops
echo ""
echo "[4/4] Creating watched directory..."
mkdir -p /tmp/uploads
chmod 777 /tmp/uploads
echo "  -> /tmp/uploads created"

echo ""
echo "=============================================="
echo " Setup complete!"
echo "=============================================="
echo ""
echo " Start the detectors in 3 separate terminals:"
echo ""
echo "   Terminal 1 (SSH Brute Force):"
echo "     sudo python3 detect_ssh_bruteforce.py"
echo ""
echo "   Terminal 2 (Port Scan):"
echo "     sudo python3 detect_portscan.py"
echo ""
echo "   Terminal 3 (Malware Drop):"
echo "     python3 detect_malware_drop.py"
echo ""
echo " Then attack from Kali:"
echo ""
echo "   1) SSH brute force:"
echo "     hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.19.130"
echo ""
echo "   2) Port scan:"
echo "     nmap -sS 192.168.19.130"
echo ""
echo "   3) Malware transfer:"
echo "     scp malware.exe user@192.168.19.130:/tmp/uploads/"
echo ""
