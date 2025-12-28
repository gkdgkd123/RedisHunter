# 🏹 Redis Hunter

> **Advanced Redis Enumeration & Vulnerability Scanner for Red Team Operations.**
>
> Redis 深度枚举与漏洞扫描工具 | 支持单机深度审计与多线程批量扫描

![Python](https://img.shields.io/badge/Python-3.x-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Type](https://img.shields.io/badge/Tool-RedTeam-red.svg)

## 📖 Introduction

**Redis Hunter** is a specialized tool designed to audit Redis servers during penetration testing. Unlike generic scanners, it goes deeper to extract system fingerprints, analyze risky configurations, and check for RCE (Remote Code Execution) conditions.

It supports two modes:
1.  **Single Target Mode (Deep):** Detailed report including OS info, internal clients, key sampling, and config analysis.
2.  **Batch Scan Mode (Fast):** Multi-threaded scanning for large IP lists with summarized one-line output.

## ✨ Features

* **RCE Vulnerability Check**:
    * Detects `4.x/5.x` versions vulnerable to **Rogue Server** attacks.
    * Probes write permissions on `dir` and `dbfilename` (Non-destructive check).
    * Checks for `MODULE` command availability.
* **Deep Enumeration**:
    * **System Fingerprint**: OS, Arch, Uptime, Config File path, Process path.
    * **Network**: Discovers Internal Clients (Side-movement targets).
    * **Data Sampling**: Enumerates DBs and samples keys (to identify sensitive data).
* **Security Audit**:
    * Detects weak configurations (Empty password, Exposed to 0.0.0.0, Plaintext MasterAuth).
    * Detects Renamed/Disabled commands.
* **Batch Scanning**:
    * Multi-threaded engine for scanning thousands of targets.
    * Noise reduction: Clean one-line summary for bulk results.

## 📦 Installation

```bash
git clone [https://github.com/YOUR_USERNAME/RedisHunter.git](https://github.com/YOUR_USERNAME/RedisHunter.git)
cd RedisHunter
pip install -r requirements.txt

```

## 🚀 Usage

### 1. Single Target Audit (Detailed)

Best for analyzing a specific compromised host.

```bash
# Basic scan
python3 redis_hunter.py 192.168.1.10

# With password and custom port
python3 redis_hunter.py 192.168.1.10 -p 6380 -a "password123"

# With username (ACL)
python3 redis_hunter.py 192.168.1.10 -u "admin" -a "password123"

```

**Output Preview:**

```text
--- [ 1. System Fingerprint ] ---
       Redis Version         : 7.4.3
       Operating System      : Linux 6.8.0 (64-bit)
       ...
--- [ 2. RCE Vulnerability Check ] ---
[VULN] High Risk Version: 4.0.9 (RCE possible via Rogue Server)
[RCE!] Config 'dir' is WRITABLE! -> Cron/SSH Attack Possible

```

### 2. Bulk Scanning (Batch)

Best for discovering vulnerable assets in a subnet.

```bash
# Scan a list of targets with 20 threads
python3 redis_hunter.py -f targets.txt -t 20

```

**File Format (`targets.txt`):**

```text
192.168.1.10
10.0.0.5:6380
example.com

```

**Output Preview:**

```text
STATUS    TARGET                | STATE           | DETAILS
----------------------------------------------------------------------
[RCE!]    192.168.1.10:6379     | Connected       | Ver:4.0.9 OS:Linux | WRITABLE_DIR
[SAFE]    10.0.0.5:6380         | Connected       | Ver:7.0.0 OS:Linux
[DEAD]    example.com:6379      | Connection refused

```

## 🛡️ Disclaimer

This tool is for **educational purposes and authorized security testing only**. The author is not responsible for any misuse or damage caused by this tool. Please obtain proper authorization before scanning any target.

## 📜 License

[MIT License](https://www.google.com/search?q=LICENSE)

```

```
