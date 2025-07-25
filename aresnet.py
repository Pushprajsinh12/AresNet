import threading
import argparse
import socket
import time
from datetime import datetime
from utils import get_service_name, detect_vulnerabilities, grab_tcp_banner, detect_os_by_ttl
from network import discover_hosts
import json
import csv
import os
import importlib.util
import subprocess
import re
import xml.etree.ElementTree as ET
import urllib.request
import json
import sys
import itertools
import threading
import time
import sys
import queue

def print_progress_bar(iteration, total, prefix='', suffix='', length=50, fill='█'):
    percent = f"{100 * (iteration / float(total)):.1f}"
    filled_length = int(length * iteration // total)
    bar = fill * filled_length + '-' * (length - filled_length)
    sys.stdout.write(f'\r{prefix} |{bar}| {percent}% {suffix}')
    sys.stdout.flush()
    if iteration == total:
        print()

def show_spinner(stop_event, message="Running AresNet advanced scan..."):
    spinner = itertools.cycle(['|', '/', '-', '\\'])
    while not stop_event.is_set():
        sys.stdout.write(f'\r{message} {next(spinner)}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * (len(message) + 5) + '\r')

# === OUTPUT HELPER ===

def print_banner():
    banner = r"""
    
                         _   _      _   
     /\                 | \ | |    | |  
    /  \   _ __ ___  ___|  \| | ___| |_ 
   / /\ \ | '__/ _ \/ __| . ` |/ _ \ __|
  / ____ \| | |  __/\__ \ |\  |  __/ |_ 
 /_/    \_\_|  \___||___/_| \_|\___|\__|
                                         
    >>>  AresNet - Advanced Network & Vulnerability Scanner
    """
    print(banner)

def write_output(line, output_file=None):
    print(line)
    if output_file:
        with open(output_file, 'a') as f:
            f.write(line + '\n')

import urllib.request
import json

def fetch_vuln_data(cve_id):
    try:
        url = f"https://vulners.com/api/v3/search/lucene/?query={cve_id}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read())

        documents = data.get("data", {}).get("documents", [])
        if not documents:
            return {}

        doc = documents[0]  # Take first result
        return {
            "severity": doc.get("cvss", {}).get("score", 0),
            "cvss": doc.get("cvss", {}).get("score", 0),
            "description": doc.get("description", ""),
            "references": doc.get("references", []),
            "cwe": doc.get("cwe", "")
        }

    except Exception as e:
        print(f"[!] Error fetching metadata for {cve_id}: {e}")
        return {}

def export_results_to_json_csv(results, json_enabled=False, csv_enabled=False):
    if not results:
        return

    structured = []
    for entry in results:
        if isinstance(entry, dict):
            structured.append({
                "status": entry.get("status", ""),
                "ip": entry.get("ip", ""),
                "port": entry.get("port", ""),
                "protocol": entry.get("protocol", ""),
                "service": entry.get("service", ""),
                "banner": entry.get("banner", ""),
                "vulnerability": entry.get("vulnerability", ""),
                "cve": entry.get("cve", ""),
                "cwe": entry.get("cwe", ""),
                "severity": entry.get("severity", ""),
                "summary": entry.get("summary", ""),
                "description": entry.get("description", ""),
                "references": ", ".join(entry.get("references", []))
            })

    if not structured:
        return

    if json_enabled:
        with open("scan_results.json", "w") as jf:
            json.dump(structured, jf, indent=4)

    if csv_enabled:
        with open("scan_results.csv", "w", newline='') as cf:
            writer = csv.DictWriter(cf, fieldnames=structured[0].keys())
            writer.writeheader()
            writer.writerows(structured)

def fetch_vuln_data(vuln_id):
    try:
        url = f"https://vulners.com/api/v3/search/lucene/?query={vuln_id}"
        with urllib.request.urlopen(url, timeout=10) as response:
            if response.status == 200:
                data = json.loads(response.read().decode())
                if data.get("data", {}).get("search"):
                    top = data["data"]["search"][0]
                    metadata = {
                        "vuln_id": top.get("id"),
                        "cve": top.get("cvelist", []),
                        "cwe": top.get("cwe", "N/A"),
                        "severity": top.get("cvss", {}).get("score", "N/A"),
                        "summary": top.get("title", ""),
                        "description": top.get("description", ""),
                        "references": top.get("references", [])
                    }
                    return metadata
    except Exception as e:
        print(f"[!] Metadata fetch failed for {vuln_id}: {e}")
    return None

def export_results_to_html(results, filename="scan_results.html"):
    html_content = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Scan Results</title>
    <style>
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 8px 12px; border: 1px solid #ddd; text-align: left; }
        th { background-color: #f2f2f2; }
        .critical { background-color: #ffcccc; }
        .high { background-color: #ffd699; }
        .medium { background-color: #ffffcc; }
        .low { background-color: #ccffcc; }
        .info { background-color: #e0e0e0; }
    </style>
</head>
<body>
    <h2>AresNet Scan Report</h2>
    <table>
        <tr>
            <th>IP</th>
            <th>Port</th>
            <th>Protocol</th>
            <th>Service</th>
            <th>Product</th>
            <th>Vulnerability</th>
            <th>Severity</th>
            <th>CVSS</th>
            <th>Description</th>
            <th>References</th>
        </tr>
"""

    for entry in results:
        if not isinstance(entry, dict):
            continue  # skip non-dict entries

        sev = str(entry.get("severity", "")).lower()
        severity_class = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low"
        }.get(sev, "info")

        html_content += f"""
        <tr class="{severity_class}">
            <td>{entry.get("ip", "")}</td>
            <td>{entry.get("port", "")}</td>
            <td>{entry.get("protocol", "")}</td>
            <td>{entry.get("service", "")}</td>
            <td>{entry.get("product", "")}</td>
            <td>{entry.get("vuln_id", "") or entry.get("cve", "") or "-"}</td>
            <td>{entry.get("severity", "")}</td>
            <td>{entry.get("cvss", "")}</td>
            <td>{entry.get("description", "").replace('<', '&lt;')}</td>
            <td>""" + "<br>".join(
            f'<a href="{ref}" target="_blank">{ref}</a>'
            for ref in entry.get("reference", [])  # Use 'reference' or 'references' based on your data
        ) + """</td>
        </tr>
"""

    html_content += """
    </table>
</body>
</html>
"""

    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[*] HTML report saved to {filename}")

def get_severity_label(score):
    try:
        score = float(score)
        if score >= 9.0:
            return "Critical"
        elif score >= 7.0:
            return "High"
        elif score >= 4.0:
            return "Medium"
        elif score > 0:
            return "Low"
        else:
            return "None"
    except:
        return "Unknown"

# === SCRIPT ENGINE ===
def run_detection_scripts(ip, port, service, banner):
    results = []
    scripts_dir = 'scripts'
    if not os.path.isdir(scripts_dir):
        return results

    for file in os.listdir(scripts_dir):
        if file.endswith(".py"):
            script_path = os.path.join(scripts_dir, file)
            spec = importlib.util.spec_from_file_location("module.name", script_path)
            mod = importlib.util.module_from_spec(spec)
            try:
                spec.loader.exec_module(mod)
                if hasattr(mod, 'run'):
                    result = mod.run(ip, port, service, banner)
                    if result:
                        results.append(f"{file}: {result}")
            except Exception as e:
                results.append(f"{file} error: {e}")
    return results

# === SCANNER ===
def run_nmap_scan(target, ports=None, use_sudo=True, output_file=None, export_json=False, export_csv=False, use_pn=False, script=None):
    cmd = ["nmap", "-sS", "-sV", "-O", "-oX", "-"]

    if script:
        if script is True:
            cmd += ["--script", "default,vuln"]
        elif script.strip().lower() == "all":
            cmd += ["--script", "default,safe,vuln,auth,discovery,exploit"]
        else:   
            cmd += ["--script", script]
    else:
        cmd += ["--script", "default,vuln"]

    cmd += ["--script-timeout", "60s"]
    cmd += ["--host-timeout", "15m"]

    if use_pn:
        cmd.insert(1, "-Pn")
    if use_sudo:
        cmd.insert(0, "sudo")

    cmd.append(target)

    try:
        write_output("[*] Running AresNet advanced scan ...", output_file)
        stop_event = threading.Event()
        spinner_thread = threading.Thread(target=show_spinner, args=(stop_event,))
        spinner_thread.start()
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        except subprocess.TimeoutExpired:
            stop_event.set()
            spinner_thread.join()
            write_output("[ERROR] ❌ scan timed out. Try reducing ports/scripts or increase timeout.\n", output_file)
            return []

        stop_event.set()
        spinner_thread.join()

        nmap_xml = result.stdout

        if not nmap_xml.strip():
            write_output("[!] Scan returned empty result. Check host status or try --no-sudo", output_file)
            return []

        write_output("\n--- AresNet Scan Output ---", output_file)

        results = []

        root = ET.fromstring(nmap_xml)
        for host in root.findall("host"):
            address = host.find("address").attrib.get("addr", "unknown")
            ports = host.find("ports")
            if ports is None:
                continue

            for port in ports.findall("port"):
                protocol = port.attrib["protocol"]
                port_id = port.attrib["portid"]
                state = port.find("state").attrib["state"]

                if state != "open":
                    continue

                service_info = port.find("service")
                service = service_info.attrib.get("name", "unknown") if service_info is not None else "unknown"
                product = service_info.attrib.get("product", "") if service_info is not None else ""
                version = service_info.attrib.get("version", "") if service_info is not None else ""
                banner = f"{product} {version}".strip()

                script_output = []
                cve = []
                references = []
                cwe = ""
                severity = ""
                summary = ""
                description = ""
                cvss = ""

                for script in port.findall("script"):
                    sid = script.attrib.get("id")
                    output = script.attrib.get("output", "")
                    script_output.append(f"{sid}: {output}")
                    script_output_str = " ".join(script_output)

                    cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", script_output_str)
                    cve += cve_matches

                    if "cwe" in output:
                        cwe_match = re.search(r"CWE-\d+", output)
                        if cwe_match:
                            cwe = cwe_match.group(0)
                    if "Severity:" in output:
                        severity_match = re.search(r"Severity:\s+(\w+)", output)
                        if severity_match:
                            severity = severity_match.group(1)
                    links = re.findall(r"https?://\S+", output)
                    references.extend(links)

                if cve:
                    for cve_id in cve:
                        meta = fetch_vuln_data(cve_id)
                        if meta:
                            severity = meta.get("severity", severity)
                            cvss = meta.get("cvss", cvss)
                            summary = meta.get("summary", summary)
                            description = meta.get("description", description)
                            references = meta.get("references", references)
                            break

                entry = {
                    "status": "OPEN",
                    "ip": address,
                    "port": port_id,
                    "protocol": protocol.upper(),
                    "service": service,
                    "product": product,
                    "banner": banner,
                    "vulnerability": " | ".join(script_output) if script_output else "",
                    "cve": ", ".join(cve),
                    "cwe": cwe,
                    "severity": severity,
                    "cvss": cvss,
                    "summary": summary,
                    "description": description,
                    "references": references
                }

                results.append(entry)

                line = f"[OPEN] {address}:{port_id}/{protocol.upper()} → {service}"
                if banner:
                    line += f" | Banner: {banner}"
                if entry["vulnerability"]:
                    line += f" | Vulnerability: {entry['vulnerability']}"
                if entry["cve"]:
                    line += f" | CVE: {entry['cve']}"
                write_output(line, output_file)

        return results

    except Exception as e:
        write_output(f"[ERROR] AresNet scan failed: {e}", output_file)
        return []
    
def enrich_vulnerabilities_with_metadata(results):
    enriched = []
    for entry in results:
        vulns = entry.get("vulnerability", "")
        metadata_list = []
        
        for vuln in vulns.split(" | "):
            vuln_id = vuln.split(":")[0].strip()
            if not vuln_id:
                continue

            try:
                response = metadata = fetch_vuln_data(vuln_id)
                if metadata:
                    metadata_list.append(metadata)
            except Exception as e:
                print(f"[!] Metadata fetch failed for {vuln_id}: {e}")

        entry["metadata"] = metadata_list
        enriched.append(entry)
    return enriched

# === TCP SCANNER ===
def scan_ports(target, port_range, threads=100, grab_banner=False, show_all=False, output_file=None, timing_profile='T3'):
    if '-' in port_range:
        start_port, end_port = map(int, port_range.split('-'))
    else:
        start_port = end_port = int(port_range)
    
    total_ports = end_port - start_port + 1
    progress = [0]  # mutable counter for thread-safe updates
    print_progress_bar(0, total_ports, prefix='TCP Scan Progress', suffix='Starting', length=40)

    open_ports = []
    lock = threading.Lock()

    timing_profiles = {
        "T0": 5.0,
        "T1": 2.0,
        "T2": 1.0,
        "T3": 0.5,
        "T4": 0.2,
        "T5": 0.05
    }
    delay = timing_profiles.get(timing_profile.upper(), 0.5)

    port_queue = queue.Queue()
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    def scan_worker():
        while not port_queue.empty():
            port = port_queue.get()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                result = s.connect_ex((target, port))
                if result == 0:
                    service = get_service_name(port)
                    output = f"[OPEN]  {target}:{port}  →  {service}"
                    banner_info = ""
                    if grab_banner:
                        banner = grab_tcp_banner(target, port)
                        if banner:
                            if len(banner) > 200:
                                banner_info = f"\n        Banner: {banner[:200]}... (truncated)"
                            else:
                                banner_info = f"\n        Banner: {banner}"

                            vuln = detect_vulnerabilities(banner)
                            if vuln:
                                banner_info += f"\n        Vulnerability: {vuln}"

                            script_results = run_detection_scripts(target, port, service, banner)
                            for res in script_results:
                                banner_info += f"\n        Vulnerability: {res}"

                    with lock:
                        full_output = output + banner_info
                        open_ports.append(full_output)
                        # write_output(full_output, output_file)  # Deferred output to end of scan
                elif show_all:
                    with lock:
                        msg = f"[CLOSED] {target}:{port}"
                        open_ports.append(msg)
                        # # write_output(msg, output_file)  # Deferred output to end of scan  # Deferred output to end of scan
                s.close()
            except Exception as e:
                if show_all:
                    with lock:
                        msg = f"[ERROR] {target}:{port} - {e}"
                        open_ports.append(msg)
                        # # write_output(msg, output_file)  # Deferred output to end of scan  # Deferred output to end of scan
            finally:
                with lock:
                    progress[0] += 1
                    print_progress_bar(progress[0], total_ports, prefix='TCP Scan Progress', suffix='Complete', length=40)
                time.sleep(delay)

    num_threads = min(threads, total_ports)
    thread_list = []
    for _ in range(num_threads):
        t = threading.Thread(target=scan_worker)
        thread_list.append(t)
        t.start()

    for t in thread_list:
        t.join()

    return open_ports

# === UDP SCANNER ===
def scan_udp(target, ports, output_file=None):
    results = []
    lock = threading.Lock()
    port_queue = queue.Queue()

    for port in ports:
        port_queue.put(port)

    def udp_worker():
        while not port_queue.empty():
            port = port_queue.get()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(2)
                s.sendto(b'\x00', (target, port))

                data, _ = s.recvfrom(1024)
                banner = data.decode(errors='ignore').strip()

                service = get_service_name(port)
                output = f"[OPEN]  {target}:{port}/UDP  →  {service}"
                vuln_info = ""

                if banner:
                    vuln = detect_vulnerabilities(f"{service.lower()}/udp")
                    if vuln:
                        vuln_info = f"\n        Vulnerability: {vuln}"

                    if len(banner) > 200:
                        output += f"\n        Banner: {banner[:200]}... (truncated)"
                    else:
                        output += f"\n        Banner: {banner}"

                with lock:
                    results.append(output + vuln_info)
                    # write_output(output + vuln_info, output_file)  # Deferred output to end of scan

            except socket.timeout:
                msg = f"[FILTERED] {target}:{port}/UDP"
                with lock:
                    results.append(msg)
                    # # write_output(msg, output_file)  # Deferred output to end of scan  # Deferred output to end of scan
            except Exception as e:
                msg = f"[ERROR] {target}:{port}/UDP - {e}"
                with lock:
                    results.append(msg)
                    # # write_output(msg, output_file)  # Deferred output to end of scan  # Deferred output to end of scan
            finally:
                s.close()

    thread_list = []
    for _ in range(min(100, len(ports))):
        t = threading.Thread(target=udp_worker)
        thread_list.append(t)
        t.start()

    for t in thread_list:
        t.join()

    return results

# ===  ===

def run_post_scan_nmap(args, all_results):
    nmap_results = []

    if args.ad_scan:
        nmap_results = run_nmap_scan(
        target=args.target,
        ports=args.ports,
        use_sudo=not args.no_sudo,
        output_file=args.output,
        export_json=args.json,
        export_csv=args.csv,
        use_pn=args.skip_pn,
        script=args.script
    )
    nmap_results = enrich_vulnerabilities_with_metadata(nmap_results)
    all_results.extend(nmap_results)

    if args.json or args.csv or args.html:
        export_results_to_json_csv(all_results, json_enabled=args.json, csv_enabled=args.csv)
        if args.html:
            export_results_to_html(all_results, filename=args.html_file or "scan_results.html")
            
# === MAIN FUNCTION ===
def main():
    parser = argparse.ArgumentParser(description="AresNet - Advanced Network & Vulnerability Scanner")
    parser.add_argument('-t', '--target')
    parser.add_argument('-p', '--ports', default="0-65535")
    parser.add_argument('-sU', '--udp', action='store_true', default=True)
    parser.add_argument('-sV', '--banner', action='store_true', default=True)
    parser.add_argument('--threads', type=int, default=300)
    parser.add_argument('--discover', action='store_true')
    parser.add_argument('--show-all', action='store_true')
    parser.add_argument('--output')
    parser.add_argument('-O', '--os-detect', action='store_true', default=True)
    parser.add_argument('-T', '--timing', default='T5')
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--csv', action='store_true')
    parser.add_argument('--html', action='store_true', help='Export scan results to HTML')
    parser.add_argument('--html-file', help='Custom HTML report filename (default: scan_results.html)')  
    parser.add_argument('--ad-scan', action='store_true', help='Run advanced scan using integrated Nmap engine')
    parser.add_argument('--no-sudo', action='store_true', help='Run advanced scan without sudo (TCP connect)')
    parser.add_argument('--skip-pn', action='store_true', help='Treat host as online (skip ping)')
    parser.add_argument('--script', nargs='?', const='true', help="Run specific Nmap NSE script(s). Use '--script=all' to run all categories.")

    args = parser.parse_args()
    
    if not args.ports or args.ports.strip() == "":
        args.ports = "0-65535"

    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"NinjaScan v1.0 - Scan Report for {args.target or 'Local Network'}\n")
            f.write(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + '\n\n')

    if args.discover:
        write_output("[*] Discovering network hosts...\n", args.output)
        discover_hosts()
    elif args.target:
        if args.os_detect:
            os_result = detect_os_by_ttl(args.target)
            write_output(f"[*] OS Detection (TTL-based): {os_result}\n", args.output)

        write_output(
            f"[*] Scanning {args.target} on ports {args.ports} (TCP{' & UDP' if args.udp else ''}) with timing {args.timing}...\n",
            args.output
        )

        tcp_results = []
        udp_results = []

        def tcp_task():
            nonlocal tcp_results
            tcp_results = scan_ports(
                args.target, args.ports, args.threads, grab_banner=True,
                show_all=args.show_all, output_file=args.output, timing_profile=args.timing)


        def udp_task():
            nonlocal udp_results
            udp_ports = [53, 67, 123, 161, 500, 1900]
            udp_results = scan_udp(args.target, udp_ports, output_file=args.output)

        threads_list = [threading.Thread(target=tcp_task)]
        threads_list[0].start()

        t2 = threading.Thread(target=udp_task)
        threads_list.append(t2)
        t2.start()

        for t in threads_list:
            t.join()

        # === SHOW TCP RESULTS ===
        write_output("--- TCP Results ---", args.output)
        for line in tcp_results:
            write_output(line, args.output)

        # === SHOW UDP RESULTS ===
        write_output("--- UDP Results ---", args.output)
        for line in udp_results:
            write_output(line, args.output)

        # Final Summary
        write_output(f"[*] TCP scan completed. Found {len(tcp_results)} results.", args.output)
        write_output(f"[*] UDP scan completed. Found {len(udp_results)} results.", args.output)


        
        all_results = tcp_results + udp_results

        run_post_scan_nmap(args, all_results)

        if args.ad_scan:
            nmap_results = run_nmap_scan(
            args.target,
            use_sudo=not args.no_sudo,
            output_file=args.output,
            export_json=False,
            export_csv=False,
            use_pn=args.skip_pn,
            script=args.script
        )
            nmap_results = enrich_vulnerabilities_with_metadata(nmap_results)
            all_results += nmap_results

        if args.json or args.csv or args.html:
            export_results_to_json_csv(all_results, json_enabled=args.json, csv_enabled=args.csv)
            if args.html:
                export_results_to_html(all_results, filename=args.html_file or "scan_results.html")


    else:
        write_output("[-] Error: Provide --target or --discover", args.output)

if __name__ == "__main__":
    print_banner()
    main()
