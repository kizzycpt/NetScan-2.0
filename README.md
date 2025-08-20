Sko_NetScan 2.0 🔍

Created By Samuel Quarm
A fast, multi-threaded network scanner & IDS (Intrusion Detection System) built in Python. It discovers devices on your local network, scans for open ports, performs OS fingerprinting via Nmap, and maintains an inventory with change detection. Results are saved into organized logs and reports.

📌 Features

✅ Interactive menu with two modes:

Scan Mode → One-time ARP/TCP/OS scan with live results

IDS Mode → Continuous monitoring with baselines, alerts, and reports

✅ ARP scan to detect active devices on a subnet

✅ TCP port scanning with protocol labels (HTTPS, FTP, SMB, etc.)

✅ Optional OS detection using Nmap

✅ Inventory tracking of devices across runs

✅ Alerts system for:

New devices

Port changes (opened/closed)

OS changes

Gateway MAC changes

Offline devices

IP/MAC mismatches

✅ Formatted Rich tables for clean console output

✅ Reports generated automatically:

devices.csv → Device inventory

report.md → Human-readable summary

alerts.log → Alerts across runs

scan_log.txt → Console logs

🛠️ Requirements

Install dependencies with:

pip install -r requirements.txt

🚀 Usage

Run the script directly:

python skonetscan.py


You will be prompted with options:

IDS Mode (baseline + alerts, scheduled loop)

Scan Mode (one-time snapshot)

Exit

Command-Line Options

Run IDS once:

python skonetscan.py --ids-once


Run IDS every N hours:

python skonetscan.py --ids-every 6

📁 Output Locations

Logs → logs/scan_log.txt

Reports → logs/reports/

devices.csv

report.md

Alerts → logs/alerts.log

Baseline state → state.json

🧪 Example Alerts
2025-08-20T00:50:42 HIGH NEW_DEVICE mac=48:e7:da:92:e8:d7 ips=['192.168.1.164'] ports=[]
2025-08-20T00:50:42 MEDIUM OFFLINE mac=aa:8d:b3:54:f2:25 last_seen=2025-08-19T00:46:06 missed_runs=6
2025-08-20T00:50:42 HIGH PORT_OPENED mac=2c:4d:54:ea:25:ad ips=['192.168.1.31'] opened=[445]

⚠️ Disclaimer

This tool is for educational and authorized use only.
Do NOT scan networks that you do not own or lack permission to analyze.
Use responsibly.

📄 License

MIT License
