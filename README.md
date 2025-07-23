# AresNet 🔍

**Advanced Network & Vulnerability Scanner for Bug Bounty Hunters and Security Analysts**

---

## 🚀 About AresNet

AresNet is a fast and extensible CLI-based network and vulnerability scanner inspired by tools like Nmap and Nuclei. It supports live scanning of IP addresses and domains with CVE/CWE metadata enrichment, banner grabbing, and real-time vulnerability detection using Nmap NSE scripts.

> ⚠️ Built for ethical use in **VAPT**, **bug bounty**, and **internal assessments** only.

---

## 🔧 Features

* ✅ TCP & UDP port scanning
* ✅ Banner grabbing
* ✅ CVE/CWE/Severity metadata enrichment via Vulners API
* ✅ Nmap integration with NSE script support
* ✅ OS detection via TTL
* ✅ Output export to JSON, CSV, and HTML (with severity coloring)

---

## 📸 Demo
<img width="602" height="621" alt="Screenshot 2025-07-23 at 1 00 17 PM" src="https://github.com/user-attachments/assets/eb00c764-b2db-4142-9528-44ac5ddae00f" />

<p><em>📌 Help Menu: AresNet's CLI usage and supported flags</em></p>

<img width="588" height="296" alt="Screenshot 2025-07-23 at 12 49 23 PM" src="https://github.com/user-attachments/assets/503fe042-f403-41a7-bac4-7ccf70134f39" />

<p><em>🚀 Scan Progress with Real-time Output Display</em></p>

<img width="1439" height="774" alt="Screenshot 2025-07-23 at 12 59 11 PM" src="https://github.com/user-attachments/assets/446ebce7-5a2c-4226-8728-665137ba74ab" />

<p><em>🔍 Live Scan Output: Scanning IP with detailed vulnerabilities, services, CVSS scores, and references</em></p>

<img width="1440" height="697" alt="result_json" src="https://github.com/user-attachments/assets/ce27a8c9-c54f-4ad6-869c-2014522fe980" />

<p><em>📁 JSON Output: Structured Vulnerability Scan Results</em></p>


```bash
$ python3 aresnet.py -t 103.29.182.94 -p 80 --nmap --json --csv --html
```

---

## 🛠️ Installation

1. **Clone the repo**:

```bash
git clone https://github.com/Pushprajsinh12/aresnet.git
cd aresnet
```

2. **(Optional) Create a virtual environment**:

```bash
python3 -m venv venv
source venv/bin/activate
```

3. **Install requirements** (only if you want progress bar):

```bash
pip install tqdm
```

💻 Supported Platforms & Requirements
AresNet works on:

✅ Kali Linux

✅ macOS 

✅ Linux 

✅ Windows

📦 Prerequisites
Requirement Description
Python 3.8+ Required to run the tool
Nmap    Required for Nmap-based scans and NSE scripts
tqdm    (Optional) For visual progress bar
nmap CLI    Must be installed and accessible in your system

ℹ️ Note: On macOS, use brew install nmap. On Debian-based Linux: sudo apt install nmap.

✅ 2. Add pip requirements file (Optional)
Create a requirements.txt file:

text
Copy
Edit
tqdm
Then in README:

bash
Copy
Edit
pip install -r requirements.txt
✅ 3. Mention VENV for Windows
Update the virtual environment part like this:

bash
Copy
Edit
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\activate

---

## ⚙️ Usage

```bash
python3 aresnet.py -t <target> -p <port-range> [options]
```

### 🔍 Basic Examples

```bash
# TCP scan with Nmap and all exports
python3 aresnet.py -t 192.168.1.1 -p 1-1000 --nmap --json --csv --html

# UDP + OS detection + banner grabbing
python3 aresnet.py -t 192.168.1.1 -p 1-100 --sU -sV -O
```

### 📂 Options

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
| `--nmap`                    | Use Nmap scan (requires sudo for full scan)                |
| `--nmap-noroot`             | Run Nmap without sudo (use `-sT` scan)                     |
| `--nmap-pn`                 | Treat host as online (skip ping check)                     |
| `--nmap-script NMAP_SCRIPT` | Run specific NSE script(s), e.g., `vuln`, `http-enum`      |

---

## 📁 Output Formats

* `scan_results.json` – structured JSON for further automation.
* `scan_results.csv` – tabular data for Excel or CLI tools.
* `scan_results.html` – color-coded report for easy viewing.

---

## 🧠 How It Works

1. TCP/UDP scans detect live services.
2. Banners are grabbed and checked against basic signatures.
3. Nmap runs NSE scripts for deep checks.
4. Vulnerabilities are enriched via Vulners API (CVE, CWE, CVSS, etc.)
5. Results are saved to your selected formats.

---

## 🤖 Live Bug Bounty Usage

AresNet is designed to scan real IPs for live services and known vulnerabilities using both:

* Nmap scripts like `http-vuln*`, `ftp-anon`, etc.
* CVE-based enrichment from Vulners.

Just pass `--nmap` and you’ll get live metadata-enriched vulnerabilities — useful for bounty recon and reporting.

---

## 📌 To-Do

* Add support for config files
* Passive scanning mode
* Web dashboard (future)

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

## ✨ Contributors

Made by Pushprajsinh Parmar
