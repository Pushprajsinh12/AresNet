import socket
import concurrent.futures
import time
from utils import get_service_name, detect_vulnerabilities

# Nmap-style timing profiles
timing_profiles = {
    "T0": 5.0,   # Paranoid (very slow)
    "T1": 2.0,   # Sneaky
    "T2": 1.0,   # Polite
    "T3": 0.5,   # Normal
    "T4": 0.2,   # Aggressive
    "T5": 0.05   # Insane
}

def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(1)
            s.connect((ip, port))
            return s.recv(1024).decode(errors='ignore').strip()
    except:
        return None

def scan_single_port(ip, port, timeout=1, grab_banner=False):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = get_service_name(port)
                output = f"[open] {ip}:{port}/tcp  --> {service}"

                if grab_banner:
                    banner = grab_banner(ip, port)
                    if banner:
                        output += f"\n   ↳ Banner: {banner}"
                        vuln = detect_vulnerabilities(banner)
                        if vuln:
                            output += f"\n   ⚠️  Vulnerability: {vuln}"
                        else:
                            output += f"\n   ↳ No known vulnerability"
                    else:
                        output += f"\n   ↳ Banner: [Not Received]"

                print(output)

    except Exception as e:
        pass

def scan_ports(ip, port_range, threads, grab_banner=False, timing_profile="T3"):
    start_port, end_port = map(int, port_range.split('-'))
    timeout = timing_profiles.get(timing_profile.upper(), 0.5)  # default to T3

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for port in range(start_port, end_port + 1):
            futures.append(executor.submit(scan_single_port, ip, port, timeout, grab_banner=grab_banner))
            time.sleep(timeout)  # delay between scans based on profile

        for future in concurrent.futures.as_completed(futures):
            pass