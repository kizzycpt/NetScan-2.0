SKO Net Scan 2.0 🔍 

Created by Samuel Quarm
⚡ A fast, multi-threaded Network Scanner & Intrusion Detection System (IDS) written in Python.

It identifies devices on your local network, scans for open ports, detects operating systems, and maintains a historical inventory of changes. The tool also features alerts, live Rich tables, reports, and baselines for continuous monitoring.

✨ Features

✅ Two Modes

Scan Mode → one-time ARP + TCP + OS fingerprinting with live console output

IDS Mode → continuous monitoring with baseline tracking, alerting, and reporting

✅ ARP scanning for active hosts

✅ TCP port scanning with protocol mapping (HTTP, SSH, RDP, SMB, etc.)

✅ Optional OS fingerprinting using Nmap

✅ Rich-powered live tables for clean and real-time terminal output

✅ Device inventory tracking with first/last seen timestamps

✅ Alerts for changes:

New devices discovered

Devices going offline

Open/closed ports

OS changes

Gateway MAC changes

IP/MAC mismatches

✅ Reports & Logs automatically generated:

scan_log.txt → detailed logs

console_tables.txt → full terminal tables

devices.csv → inventory of devices

report.md → human-readable IDS summary

alerts.log → cumulative alerts across runs

🛠 Requirements

Install dependencies with:

pip install -r requirements.txt

🚀 Usage

Run directly:

python skonetscan.py


You’ll see a menu with options:

1. IDS Mode (baseline + alerts, scheduled loop)  
2. Scan Mode (one-time snapshot)  
3. Exit  

Command-line flags

Run IDS once:

python skonetscan.py --ids-once


Run IDS every N hours:

python skonetscan.py --ids-every 6

📂 Output

Logs → logs/scan_log.txt

Reports → logs/reports/

Alerts → logs/alerts.log

State baseline → state.json

🖥 Example Output (Scan Mode)
Host Name   IP Address      MAC Address        OS Guess        Open Ports        Closed Ports
---------   ----------      -----------        --------        ----------        -------------
PC-1        192.168.1.15    48:e7:da:92:e8:d7  Windows 10      (22, 80, 443)     (21, 23, 25, 135, 139, 445, 3389)
NAS         192.168.1.50    2c:4d:54:ea:25:ad  Linux           (445)             (22, 80, 443, 3389)

========= SCAN SUMMARY =========
Total Hosts Found: 4
Subnet Scanned: 192.168.1.0/24
Local IP: 192.168.1.15
Public IP: 8.23.5.88
================================

📊 Example IDS Alerts
2025-08-20T00:50:42 HIGH NEW_DEVICE mac=48:e7:da:92:e8:d7 ips=['192.168.1.164'] ports=[]
2025-08-20T00:50:42 MEDIUM OFFLINE mac=aa:8d:b3:54:f2:25 last_seen=2025-08-19T00:46:06 missed_runs=6
2025-08-20T00:50:42 HIGH PORT_OPENED mac=2c:4d:54:ea:25:ad ips=['192.168.1.31'] opened=[445]

⚠️ Disclaimer

This tool is for educational and authorized use only.
Do NOT scan or monitor networks you do not own or lack permission to analyze.
Use responsibly.

📄 License

MIT License
