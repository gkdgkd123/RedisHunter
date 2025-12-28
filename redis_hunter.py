#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Redis Hunter - Advanced Redis Enumeration & Vulnerability Scanner
Author: GKDf1sh
License: MIT
Description: A tool designed for Red Team operations to audit Redis servers.
"""

import redis
import argparse
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style

# Initialize Colorama
init(autoreset=True)

# Global lock for thread-safe printing in batch mode
print_lock = threading.Lock()

class Logger:
    """Unified logger class."""
    @staticmethod
    def rce(msg):    print(f"{Style.BRIGHT}{Fore.RED}[RCE!] {Style.RESET_ALL}{msg}")
    @staticmethod
    def vuln(msg):   print(f"{Style.BRIGHT}{Fore.RED}[VULN] {Style.RESET_ALL}{msg}")
    @staticmethod
    def warn(msg):   print(f"{Fore.YELLOW}[WARN] {Style.RESET_ALL}{msg}")
    @staticmethod
    def info(msg):   print(f"{Fore.GREEN}[INFO] {Style.RESET_ALL}{msg}")
    
    @staticmethod
    def kv(key, val, status_color=Fore.WHITE):
        print(f"       {Fore.CYAN}{key.ljust(22)}: {Style.BRIGHT}{status_color}{val}{Style.RESET_ALL}")

    @staticmethod
    def section(title):
        print(f"\n{Fore.WHITE}{Style.DIM}--- [ {title} ] ---{Style.RESET_ALL}")

    @staticmethod
    def hint(cmd, desc):
        print(f"{Fore.MAGENTA}    -> Hint: {desc}")
        print(f"{Fore.LIGHTBLACK_EX}       CMD: {cmd}")

    @staticmethod
    def bulk_log(target, status, risk_level, extra_info=""):
        """One-line logger for bulk scanning."""
        with print_lock:
            if risk_level >= 3:
                color = Fore.RED + Style.BRIGHT
                tag = "[RCE!]"
            elif risk_level == 2:
                color = Fore.RED
                tag = "[VULN]"
            elif risk_level == 1:
                color = Fore.YELLOW
                tag = "[WARN]"
            else:
                color = Fore.GREEN
                tag = "[SAFE]"
            
            print(f"{color}{tag.ljust(7)} {Style.RESET_ALL} {target.ljust(21)} | {status.ljust(15)} | {extra_info}")


def safe_config_set(r, key, value, original):
    """Non-destructive write check."""
    try:
        r.config_set(key, value)
        r.config_set(key, original)
        return True, "Write OK"
    except Exception as e:
        return False, str(e)

def perform_audit(host, port, password, user):
    """
    Core logic: Collects ALL data needed for both Single and Batch modes.
    Restored full data collection from V4.1.
    """
    result = {
        "target": f"{host}:{port}",
        "connected": False,
        "error": None,
        "risk_score": 0,
        # System Info
        "version": "Unknown",
        "os": "Unknown",
        "process_path": "Unknown",
        "config_file": "Unknown",
        "uptime": 0,
        "role": "Unknown",
        "clients_count": 0,
        "memory": "Unknown",
        # Configs
        "current_dir": "N/A",
        "current_dbfile": "dump.rdb",
        "protected_mode": "no",
        # Checks
        "rce_rogue": False,
        "write_dir": False,
        "write_dir_msg": "",
        "write_db": False,
        "write_db_msg": "",
        "module_cmd": False,
        "master_auth": None,
        "internal_ips": [],
        # Data
        "db_data": [] # List of {index, size, sample}
    }

    try:
        r = redis.Redis(host=host, port=port, password=password, username=user, 
                        socket_timeout=5, decode_responses=True)
        r.ping()
        result["connected"] = True
        
        # 1. INFO Collection
        info = r.info()
        result["version"] = info.get('redis_version', 'Unknown')
        result["os"] = info.get('os', 'Unknown')
        result["process_path"] = info.get('executable', 'Unknown')
        result["config_file"] = info.get('config_file', 'Unknown')
        result["uptime"] = info.get('uptime_in_days', 0)
        result["role"] = info.get('role', 'Unknown')
        result["clients_count"] = info.get('connected_clients', 0)
        result["memory"] = info.get('used_memory_human', 'Unknown')

        # 2. CONFIG Collection
        config = {}
        try:
            config = r.config_get('*')
            result["current_dir"] = config.get('dir', 'N/A')
            result["current_dbfile"] = config.get('dbfilename', 'dump.rdb')
            result["protected_mode"] = config.get('enable-protected-configs', 'no')
            result["master_auth"] = config.get('masterauth', None)
        except:
            # Config might be disabled
            pass

        # 3. RCE Analysis
        # Rogue Server Check
        if result["version"].startswith('4.') or result["version"].startswith('5.'):
            result["rce_rogue"] = True
            result["risk_score"] = max(result["risk_score"], 2)

        # Write Permission Check
        if config:
            if result["protected_mode"] == 'no':
                # Test Dir
                test_path = '/tmp' if 'Linux' in result["os"] else 'C:\\Windows\\Temp'
                is_dir, msg = safe_config_set(r, 'dir', test_path, result["current_dir"])
                result["write_dir"] = is_dir
                result["write_dir_msg"] = msg
                if is_dir: result["risk_score"] = 3
                
                # Test Dbfilename
                is_db, msg = safe_config_set(r, 'dbfilename', 'pwn.rdb', result["current_dbfile"])
                result["write_db"] = is_db
                result["write_db_msg"] = msg
                if is_db and result["rce_rogue"]: result["risk_score"] = 3
            else:
                result["write_dir_msg"] = "Protected Configs Enabled"
                result["write_db_msg"] = "Protected Configs Enabled"

        # Module Check
        try:
            r.execute_command("MODULE", "LIST")
            result["module_cmd"] = True
        except: pass

        # 4. Security Audit
        if result["master_auth"]:
            result["risk_score"] = max(result["risk_score"], 1)
        
        try:
            clients = r.client_list()
            ips = set()
            for c in clients:
                addr = c.get('addr', '').split(':')[0]
                if addr and addr not in ['127.0.0.1', '::1', '0.0.0.0', host]:
                    ips.add(addr)
            result["internal_ips"] = list(ips)
            if ips: result["risk_score"] = max(result["risk_score"], 1)
        except: pass

        # 5. Data Sampling (Restored!)
        db_count = int(config.get('databases', 16)) if config else 16
        # Scan first 16 DBs
        for i in range(min(db_count, 16)):
            try:
                r.select(i)
                dbsize = r.dbsize()
                if dbsize > 0:
                    # Get sample
                    sample_keys = r.scan(cursor=0, count=5)[1]
                    result["db_data"].append({
                        "index": i,
                        "size": dbsize,
                        "sample": sample_keys
                    })
            except: pass

    except Exception as e:
        result["error"] = str(e)
    
    return result

def print_single_report(res, password):
    """
    Prints the detailed V4.1-style report using data from perform_audit.
    """
    if not res["connected"]:
        print(f"\n{Fore.RED}[-] Connection Failed: {res['error']}")
        return

    print(f"\n{Fore.GREEN}[+] Connected to Target: {Style.BRIGHT}{res['target']}")
    
    # 1. System Fingerprint
    Logger.section("1. System Fingerprint")
    Logger.kv("Redis Version", res['version'])
    Logger.kv("Operating System", res['os'])
    Logger.kv("Process Path", res['process_path'])
    Logger.kv("Config File", res['config_file'])
    Logger.kv("Uptime", f"{res['uptime']} days")
    Logger.kv("Role", res['role'])
    Logger.kv("Connected Clients", str(res['clients_count']))
    Logger.kv("Memory Used", res['memory'])

    # 2. RCE Check
    Logger.section("2. RCE Vulnerability Check")
    
    # Rogue Server
    if res['rce_rogue']:
        Logger.vuln(f"High Risk Version: {res['version']} (Rogue Server RCE)")
    else:
        Logger.info(f"Version Check: {res['version']} (Not inherently vulnerable)")
    
    # Config Info
    Logger.kv("Current Dir", res['current_dir'])
    Logger.kv("Current DbFilename", res['current_dbfile'])
    Logger.kv("Protected Configs", res['protected_mode'], 
              Fore.GREEN if res['protected_mode'] == 'yes' else Fore.YELLOW)
    
    # Write Perms
    if res['write_dir']:
        Logger.rce(f"Config 'dir' is WRITABLE! -> Cron/SSH Attack Possible")
    else:
        Logger.kv("Dir Write Check", f"FAILED ({res['write_dir_msg']})", Fore.LIGHTBLACK_EX)
        
    if res['write_db']:
        Logger.vuln(f"Config 'dbfilename' is WRITABLE! -> Rogue Server Attack Possible")
    else:
        Logger.kv("DbFile Write Check", f"FAILED ({res['write_db_msg']})", Fore.LIGHTBLACK_EX)
    
    if res['module_cmd']:
        Logger.warn("Command 'MODULE' is available.")

    # 3. Security Audit
    Logger.section("3. Security Audit")
    
    if res['master_auth']:
        Logger.warn(f"Plaintext Master Auth: {res['master_auth']}")
    else:
        Logger.kv("Master Auth", "Not Set (Safe)", Fore.GREEN)
        
    if res['internal_ips']:
        Logger.warn(f"Internal Clients Discovered: {res['internal_ips']}")
    else:
        Logger.kv("Internal Clients", "None detected", Fore.WHITE)

    # 4. Data & Persistence (Restored!)
    Logger.section("4. Data & Persistence")
    Logger.kv("Persistence File", res['current_dbfile'])
    
    if res['db_data']:
        for db in res['db_data']:
            print(f"       {Fore.YELLOW}DB [{db['index']}]{Style.RESET_ALL} Keys: {Style.BRIGHT}{db['size']}{Style.RESET_ALL}")
            if db['sample']:
                print(f"       {Fore.LIGHTBLACK_EX}Sample: {db['sample']}{Style.RESET_ALL}")
    else:
        print("       (No keys found in scanned databases)")

    # 5. Hints
    Logger.section("5. Manual Exploitation Hints")
    base_cmd = f"redis-cli -h {res['target'].split(':')[0]} -p {res['target'].split(':')[1]}"
    if password: base_cmd += f" -a '{password}'"

    if res['write_dir']:
        Logger.hint(f"{base_cmd} CONFIG SET dir /var/spool/cron/crontabs/", "Write Cron Job")
    if res['rce_rogue']:
        Logger.hint("python3 redis-rogue-server.py ...", "Rogue Server Attack")
    Logger.hint(f"{base_cmd} MONITOR", "Sniff Real-time Traffic")
    print("")

def worker(target, password, user):
    """Thread worker for bulk scan - Uses strict summary."""
    if ":" in target:
        host, port = target.split(":")
        port = int(port)
    else:
        host = target
        port = 6379
    
    res = perform_audit(host, port, password, user)
    
    if not res["connected"]:
        with print_lock:
            print(f"{Fore.LIGHTBLACK_EX}[DEAD]    {res['target'].ljust(21)} | {str(res['error'])[:40]}")
        return

    # Bulk Summary Logic
    info_str = f"Ver:{res['version']} OS:{res['os']}"
    if res['write_dir']: info_str += " | WRITABLE_DIR"
    if res['master_auth']: info_str += " | WEAK_AUTH"
    if res['internal_ips']: info_str += f" | {len(res['internal_ips'])} Clients"
    if res['db_data']: 
        total_keys = sum(d['size'] for d in res['db_data'])
        info_str += f" | Keys:{total_keys}"

    Logger.bulk_log(res['target'], "Connected", res['risk_score'], info_str)


def main():
    print(Fore.CYAN + Style.BRIGHT + r"""
    ===============================================================
       REDIS HUNTER V5.1 (Fixed Edition)
       > Single Audit (Deep) & Bulk Scan (Fast)
    ===============================================================
    """)

    parser = argparse.ArgumentParser(description="Redis Hunter - Open Source Audit Tool")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("host", nargs="?", help="Single Target IP")
    group.add_argument("-f", "--file", help="File containing list of IP:PORT")
    
    parser.add_argument("-p", "--port", type=int, default=6379, help="Target Port (Single mode)")
    parser.add_argument("-a", "--password", help="Redis Password")
    parser.add_argument("-u", "--user", help="Redis Username (ACL)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads for bulk scan")

    args = parser.parse_args()

    if args.host:
        res = perform_audit(args.host, args.port, args.password, args.user)
        print_single_report(res, args.password)
    
    elif args.file:
        targets = []
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{Fore.RED}[-] File not found: {args.file}")
            sys.exit(1)

        print(f"{Fore.WHITE}[*] Loaded {len(targets)} targets. Scanning with {args.threads} threads...")
        print(f"{Fore.WHITE}{Style.DIM}{'-'*70}")
        print(f"{Fore.WHITE}{'STATUS'.ljust(9)} {'TARGET'.ljust(21)} | {'STATE'.ljust(15)} | {'DETAILS'}")
        print(f"{Fore.WHITE}{Style.DIM}{'-'*70}")

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            for target in targets:
                executor.submit(worker, target, args.password, args.user)
        
        print(f"\n{Fore.WHITE}[*] Bulk Scan Completed.")

if __name__ == "__main__":
    main()
