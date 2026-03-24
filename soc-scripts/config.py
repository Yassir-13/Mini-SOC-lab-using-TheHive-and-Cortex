# =============================================================
# SOC Detection Scripts - Configuration
# =============================================================

# TheHive connection
THEHIVE_URL = "http://localhost:9000"
THEHIVE_API_KEY = "kUrcfC3GBjUzVQm0N1ecnYA3mnMdDwBZ"

# Kali attacker IP
KALI_IP = "192.168.19.129"

# SSH Brute Force detection settings
SSH_LOG_FILE = "/var/log/auth.log"
SSH_MAX_FAILURES = 5          # failures within the time window
SSH_TIME_WINDOW = 60          # seconds

# Port Scan detection settings
SCAN_LOG_FILE = "/var/log/portscan.log"
SCAN_THRESHOLD = 15           # different ports within the time window
SCAN_TIME_WINDOW = 30         # seconds

# Malware drop detection settings
WATCH_DIRECTORY = "/tmp/uploads"   # directory to monitor for new files
