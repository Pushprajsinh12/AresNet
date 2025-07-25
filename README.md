# AresNet 🔍

**Advanced Network & Vulnerability Scanner for Security Analysts.**

---

## 🚀 About AresNet

AresNet is a powerful Python-based advanced network and vulnerability scanner that combines fast TCP/UDP port scanning with advanced NSE scripting. Designed for live reconnaissance, penetration testing.

---

## 🔧 Features

✅ TCP & UDP port scanning
✅ Banner grabbing
✅ CVE/CWE/Severity metadata enrichment via Vulners API
✅ Nmap integration with NSE script support
✅ OS detection via TTL
✅ Output export to JSON, CSV, and HTML (with severity coloring)

---

## 📸 Demo

<img width="580" height="590" alt="aresnet_helpdesk" src="https://github.com/user-attachments/assets/f3a4e303-e11b-4639-a803-91ff3d11296e" />

<p><em>📌 Help Menu: AresNet's CLI usage and supported flags</em></p>

<img width="643" height="422" alt="ipscan" src="https://github.com/user-attachments/assets/dcc683cd-0c16-4f51-a577-63e76de259b2" />

<p><em>🚀 Scan Progress with Real-time Output Display</em></p>

<img width="1440" height="773" alt="advanced scan" src="https://github.com/user-attachments/assets/2c947e33-2a90-4a54-8119-fb898c511c32" />

<p><em>🔍 Live Scan Output: Scanning IP with detailed vulnerabilities, services, CVSS scores, and references</em></p>

<img width="1440" height="697" alt="result_json" src="https://github.com/user-attachments/assets/ce27a8c9-c54f-4ad6-869c-2014522fe980" />

<p><em>📁 JSON Output: Structured Vulnerability Scan Results</em></p>


```bash
$ python3 aresnet.py -t 103.29.182.94 -p 80 --nmap --json --csv --html
```

---


🛠️ Installation

1. **Clone the repo**:

```bash
git clone https://github.com/Pushprajsinh12/aresnet.git
cd aresnet
```

2. **Create a virtual environment**:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install requirements** 

```bash
pip install tqdm
```

---

💻 Supported Platforms & Requirements AresNet works on:

✅ Kali Linux

✅ macOS

✅ Linux

✅ Windows	

📦 Prerequisites
Requirement Description
Python 3.8+ Required to run the tool
Nmap    Required for Nmap-based scans and NSE scripts
tqdm    For visual progress bar
nmap CLI    Must be installed and accessible in your system

ℹ️ Note: On macOS, use brew install nmap. On Debian-based Linux: sudo apt install nmap.

✅ Add pip requirements file Create a requirements.txt file:

```bash 
pip install -r requirements.txt 
```

✅ Mention VENV for Windows Update the virtual environment part like this:

#Linux/macOS

```bash
python3 -m venv venv source venv/bin/activate
```

#Windows (PowerShell)

```bash
python -m venv venv .\venv\Scripts\activate
```

##⚙️ Usage

###Basic Scan

```bash
python3 aresnet.py -t <target>
```

###Custom Port Range

```bash
python3 aresnet.py -t <target> -p 0-65535
```

###Enable AresNet's Advanced Scan

```bash
python3 aresnet.py -t <target> --ad-scan
```

###Skip Host Discovery (for offline hosts)

```bash
python3 aresnet.py -t <target> --ad-scan --skip-pn
```

###Run All Available Scripts

```bash
python3 aresnet.py -t <target> --script=all
```

###Run Specific Script

```bash
python3 aresnet.py -t <target> --script=ftp-anon
```

###Run Multiple Scripts or Categories

```bash
python3 aresnet.py -t <target> --script=default,vuln,auth
```

###Run Custom NSE Script File

```bash
python3 aresnet.py -t <target> --script=/path/to/custom.nse
```

###Export Report

```bash
python3 aresnet.py -t <target> --output report.json
Supports .json, .csv, .html
```

###📊 Output Sections

TCP Results

UDP Results

TTL-based OS Detection

Vulnerabilities with severity, CVE, CVSS score, and references

###✍️ Flag Reference Table

| Flag                        | Description                                                |
| --------------------------- | ---------------------------------------------------------- |
| `-h, --help`                | Show help message and exit                                 |
| `-t, --target TARGET`       | Target IP address or hostname                              |
| `-p, --ports PORTS`         | Port(s) to scan (e.g. 80, 1-100)                           |
| `-sU, --udp`                | Enable UDP port scanning                                   |
| `-sV, --banner`             | Grab service banners and analyze for vulnerabilities       |
| `--threads THREADS`         | Number of threads (default: 100)                           |
| `--discover`                | Enable host discovery                                      |
| `--show-all`                | Show all ports, including closed ones                      |
| `--output OUTPUT`           | Save output to a file                                      |
| `-O, --os-detect`           | Enable OS detection                                        |
| `-T, --timing TIMING`       | Timing profile (T0-T5, default: T3)                        |
| `--json`                    | Export scan results in JSON format                         |
| `--csv`                     | Export scan results in CSV format                          |
| `--html`                    | Export scan results in HTML format                         |
| `--html-file HTML_FILE`     | Custom HTML report filename (default: `scan_results.html`) |
| `--ad-scan`                 | Use AresNet Advanced Scan (Nmap-based)                     |
| `--no-sudo`                 | Run Nmap without sudo (use `-sT` scan)                     |
| `--skip-pn`                 | Treat host as online (skip ping check)                     |
| `--script` 				  | Run Nmap NSE scripts (single, multiple, or all)            |

---

## 📁 Output Formats

* `scan_results.json` – structured JSON for further automation.
* `scan_results.csv` – tabular data for Excel or CLI tools.
* `scan_results.html` – color-coded report for easy viewing.


📄 Sample Command

```bash
python3 aresnet.py -t <target ip> -p 0-65535 --udp --script=all --ad-scan --output scan_report.html
```

---

##🧠 How It Works

1. TCP/UDP scans detect live services.
2. Banners are grabbed and checked against basic signatures.
3. Nmap runs NSE scripts for deep checks.
4. Vulnerabilities are enriched via Vulners API (CVE, CWE, CVSS, etc.)
5. Results are saved to your selected formats.

---

🤖 Live Bug Bounty Usage
AresNet is designed to scan real IPs for live services and known vulnerabilities using both:

*Nmap scripts like `http-vuln*`, `ftp-anon`, etc.
*CVE-based enrichment from Vulners.

Just pass `--ad-scan` and you’ll get live metadata-enriched vulnerabilities — useful for bounty recon and reporting.

---

##📌 To-Do

*Add support for config files
*Passive scanning mode
*Web dashboard (future)

---

##📄 License

This project is licensed under the MIT License.

---

## ✨ Contributors
Made by Pushprajsinh Parmar
