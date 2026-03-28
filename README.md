# SOC Lab — TheHive + Cortex + Custom Detection Scripts

A fully dockerized Security Operations Center (SOC) lab environment featuring **TheHive 5** for incident response, **Cortex** for automated observable analysis, and **custom Python detection scripts** that monitor and alert on attacks in real time.

Built for learning, testing, and demonstrating SOC workflows in a controlled lab environment.

![TheHive](https://img.shields.io/badge/TheHive-5.4-orange)
![Cortex](https://img.shields.io/badge/Cortex-3.1.8-blue)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)

---

## Table of Contents

- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Scripts](#detection-scripts)
- [Attack Simulation](#attack-simulation)
- [Investigation Workflow](#investigation-workflow)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Ubuntu VM                             │
│                                                              │
│  ┌────────────┐  ┌────────────────┐  ┌─────────────────┐    │
│  │ Cassandra  │  │ Elasticsearch  │  │      MinIO       │    │
│  │   (DB)     │  │    (Index)     │  │   (S3 Storage)   │    │
│  │   :9042    │  │    :9200       │  │  :9002 / :9090   │    │
│  └─────┬──────┘  └───────┬───────┘  └────────┬─────────┘    │
│        │          ┌──────┘ └──────┐           │              │
│        ▼          ▼               ▼           ▼              │
│  ┌──────────────────┐     ┌──────────────┐                   │
│  │   TheHive 5      │◄───►│    Cortex     │                  │
│  │     :9000         │     │    :9001      │                  │
│  └────────▲─────────┘     └──────────────┘                   │
│           │                                                  │
│  ┌────────┴──────────────────────────────┐                   │
│  │        Python Detection Scripts       │                   │
│  │  • SSH Brute Force Detector           │                   │
│  │  • Port Scan Detector                 │                   │
│  │  • Malware Drop Detector              │                   │
│  └───────────────────────────────────────┘                   │
│                                                              │
│ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  │
│                    Kali VM (Attacker)                         │
│              SSH brute force / Nmap / SCP                     │
└──────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

| Technology      | Role                                                                 |
|-----------------|----------------------------------------------------------------------|
| **Docker**      | Containerization of all SOC services via Docker Compose              |
| **TheHive 5**   | Incident response platform — alert management, case tracking         |
| **Cortex**      | Automated observable analysis (IPs, hashes, domains) via analyzers   |
| **Cassandra**   | NoSQL database backend for TheHive cases, alerts, and observables    |
| **Elasticsearch** | Search and indexing engine for TheHive and Cortex                  |
| **MinIO**       | S3-compatible object storage for file attachments and evidence       |
| **Python**      | Custom detection scripts using `thehive4py` to send real-time alerts |

---

## Prerequisites

- **Ubuntu VM** — 4+ GB RAM, 20+ GB disk
- **Docker** and **Docker Compose** installed
- **Kali VM** — on the same network as the Ubuntu VM
- **Python 3.9+** on the Ubuntu VM

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/Yassir-13/Mini-SOC-lab-using-TheHive-and-Cortex
cd soc-lab
```

### 2. Prepare the host

```bash
chmod +x setup.sh
./setup.sh
```

This sets `vm.max_map_count` for Elasticsearch, creates required directories, and verifies Docker is ready.

### 3. Configure environment variables

```bash
cp .env.example .env
nano .env
```

Update `THEHIVE_SECRET` with a random string:

```bash
openssl rand -base64 32
```

### 4. Launch the stack

```bash
docker compose up -d
```

Wait 1–2 minutes for all services to initialize, then verify:

```bash
docker compose ps
```

All containers should show `healthy` or `started`.

### 5. Initial setup

**Cortex** (`http://YOUR_IP:9001`):
1. Click **Update Database**
2. Create an admin account
3. Create an Organization → create a User with `read, analyze, orgadmin` roles
4. Log in as the org user → generate an **API Key**

**TheHive** (`http://YOUR_IP:9000`):
1. Login: `admin@thehive.local` / `secret`
2. Create an Organization and an analyst user
3. Connect Cortex: **Platform Management → Connectors → Cortex** → add URL `http://cortex:9001` + API key

### 6. Install detection dependencies

```bash
cd soc-scripts
chmod +x setup.sh
./setup.sh
```

Update `config.py` with your TheHive API key and Kali IP address.

---

## Detection Scripts

Three Python scripts monitor the Ubuntu host and send alerts to TheHive in real time:

### SSH Brute Force Detector
- **File:** `detect_ssh_bruteforce.py`
- **Monitors:** `/var/log/auth.log`
- **Triggers:** 5+ failed SSH attempts within 60 seconds
- **Alert includes:** attacker IP, targeted usernames, attempt count

### Port Scan Detector
- **File:** `detect_portscan.py`
- **Monitors:** `/var/log/kern.log` (via iptables logging)
- **Triggers:** 15+ unique ports scanned within 30 seconds
- **Alert includes:** attacker IP, list of scanned ports

### Malware Drop Detector
- **File:** `detect_malware_drop.py`
- **Monitors:** `/tmp/uploads` directory
- **Triggers:** any new file appearing in the watched directory
- **Alert includes:** filename, file size, MD5/SHA1/SHA256 hashes

---

## Attack Simulation

Start the three detectors on the Ubuntu VM in separate terminals:

```bash
# Terminal 1
sudo python3 detect_ssh_bruteforce.py

# Terminal 2
sudo python3 detect_portscan.py

# Terminal 3
python3 detect_malware_drop.py
```

Then launch attacks from the **Kali VM**:

```bash
# Attack 1: SSH Brute Force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://UBUNTU_IP -t 4

# Attack 2: Port Scan
sudo nmap -sS UBUNTU_IP

# Attack 3: Malware Transfer (EICAR test file)
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > eicar.com
scp eicar.com user@UBUNTU_IP:/tmp/uploads/
```

---

## Investigation Workflow

```
Kali Attack → Python Detection → TheHive Alert → Case Creation → Cortex Analysis
```

1. **Alerts** appear automatically in TheHive's alert dashboard
2. **Promote** an alert to a case for investigation
3. Click on an observable (IP, hash) → **Analyze** with Cortex
4. Review analyzer results (VirusTotal, Abuse_Finder, FileInfo, etc.)
5. **Close** the case with findings and recommendations


---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Elasticsearch crashes | Run `sudo sysctl -w vm.max_map_count=262144` |
| TheHive won't start | Wait for Cassandra to be healthy, then `docker compose restart thehive` |
| MinIO healthcheck fails | Use `curl -f http://localhost:9002/minio/health/live` as healthcheck |
| Cortex analyzers empty | Log in as org user → Organization → Analyzers → Refresh |
| Alerts not showing in TheHive | Ensure API key belongs to the org user, not the admin account |
| Container name conflict | Run `docker rm -f <container_name>` then `docker compose up -d` |

---

## Service URLs

| Service       | URL                    | Default Credentials            |
|---------------|------------------------|--------------------------------|
| TheHive       | `http://IP:9000`       | `admin@thehive.local` / `secret` |
| Cortex        | `http://IP:9001`       | Created during initial setup   |
| MinIO Console | `http://IP:9090`       | `minioadmin` / `minioadmin`    |
| Elasticsearch | `http://IP:9200`       | No authentication              |

---

## Disclaimer

This project is intended for **lab and educational purposes only**. It uses default credentials and configurations that are **not secure for production environments**. Do not expose these services to the internet.

---

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
