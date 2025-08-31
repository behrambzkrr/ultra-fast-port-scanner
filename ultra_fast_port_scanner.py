import socket
import logging
import threading
import argparse
import json
from datetime import datetime
from typing import List, Dict
from queue import Queue, Empty
from colorama import Fore, Style, init
import concurrent.futures
import time

init(autoreset=True)

# Advanced protocol definitions
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 
    445: 'SMB', 993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 
    1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    27017: 'MongoDB', 11211: 'Memcached'
}

# Optimized log settings
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("enhanced_port_scanner.log", mode='w'),
        logging.StreamHandler()
    ]
)

# Thread-safe results collection
scan_results = []
results_lock = threading.Lock()

def validate_ip(ip: str) -> bool:
    """Faster and safer IP address validation"""
    try:
        return bool(socket.inet_pton(socket.AF_INET, ip))
    except socket.error:
        try:
            return bool(socket.inet_pton(socket.AF_INET6, ip))
        except socket.error:
            return False

def scan_port(ip: str, port: int, timeout: float = 0.3) -> Dict:
    """Scan a single port and return the result"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.setblocking(False)
            start = time.time()
            try:
                sock.connect((ip, port))
            except BlockingIOError:
                pass
            ready = False
            while time.time() - start < timeout:
                try:
                    ready = sock.connect_ex((ip, port)) == 0
                    if ready:
                        break
                except:
                    pass
                time.sleep(0.01)
            if ready:
                service = COMMON_PORTS.get(port, 'Unknown')
                banner = get_banner(sock) if service != 'Unknown' else ''
                return {
                    "ip": ip,
                    "port": port,
                    "status": "open",
                    "service": service,
                    "banner": banner,
                    "timestamp": datetime.now().isoformat()
                }
    except Exception as e:
        logging.debug(f"Port {port} scan error: {str(e)}")
    return None

def get_banner(sock: socket.socket) -> str:
    """Get banner from open port"""
    try:
        sock.settimeout(1)
        return sock.recv(1024).decode('utf-8', errors='ignore').strip()
    except:
        return ""

def port_scan_worker(ip: str, ports: List[int], timeout: float, results: List[Dict]):
    """Thread worker function - scans a list of ports"""
    for port in ports:
        result = scan_port(ip, port, timeout)
        if result:
            with results_lock:
                results.append(result)
            logging.info(Fore.GREEN + f"{ip}:{port} open ({result['service']}) {Fore.YELLOW}{result.get('banner', '')}")

def batch_ports(start: int, end: int, batch_size: int = 100) -> List[List[int]]:
    """Batch port ranges"""
    ports = list(range(start, end + 1))
    return [ports[i:i + batch_size] for i in range(0, len(ports), batch_size)]

def fast_scan(ip: str, start_port: int, end_port: int, max_threads: int = 200, timeout: float = 0.3):
    """High performance port scanning"""
    port_batches = batch_ports(start_port, end_port, max_threads // 2)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = []
        for batch in port_batches:
            futures.append(
                executor.submit(port_scan_worker, ip, batch, timeout, scan_results)
            )
        concurrent.futures.wait(futures)

def save_results(filename: str, results: List[Dict]):
    """Save results in JSON format"""
    with open(filename, 'w') as f:
        json.dump(results, f, indent=4, default=str)
    logging.info(Fore.CYAN + f"Results saved to {filename}")

def parse_arguments():
    """Parse arguments"""
    parser = argparse.ArgumentParser(description="Ultra Fast Port Scanner")
    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("-p", "--ports", default="1-65535", help="Port range (e.g. 1-1000)")
    parser.add_argument("-t", "--threads", type=int, default=200, help="Number of threads (max: 500)")
    parser.add_argument("--timeout", type=float, default=0.3, help="Timeout (seconds)")
    parser.add_argument("-o", "--output", default="scan_results.json", help="Output file")
    parser.add_argument("--banner", action="store_true", help="Collect banner information")
    return parser.parse_args()

def main():
    args = parse_arguments()
    if not validate_ip(args.ip):
        logging.error("Invalid IP address")
        return
    try:
        if '-' in args.ports:
            start_port, end_port = map(int, args.ports.split('-'))
        else:
            start_port = end_port = int(args.ports)
    except ValueError:
        logging.error("Invalid port range")
        return
    if start_port < 1 or end_port > 65535 or start_port > end_port:
        logging.error("Invalid port range (1-65535)")
        return
    args.threads = min(max(args.threads, 1), 500)
    args.timeout = max(min(args.timeout, 5.0), 0.1)
    logging.info(f"Scanning ports {start_port}-{end_port} on {args.ip} ...")
    logging.info(f"Threads: {args.threads}, Timeout: {args.timeout}s")
    start_time = datetime.now()
    fast_scan(args.ip, start_port, end_port, args.threads, args.timeout)
    duration = datetime.now() - start_time
    if scan_results:
        save_results(args.output, scan_results)
        open_ports = sorted([r['port'] for r in scan_results])
        logging.info(Fore.GREEN + f"Scan complete! Open ports: {open_ports}")
    else:
        logging.warning(Fore.YELLOW + "No open ports found")
    logging.info(Fore.YELLOW + f"Total time: {duration}")

if __name__ == "__main__":
    main()