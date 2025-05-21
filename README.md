# 🛡️ SOC Analyst Toolkit

A command-line cybersecurity tool written in Python to assist SOC analysts with common investigation tasks.  
This toolkit automates threat intelligence lookups and email header parsing — all in one script.

---

## 🎯 Features

| Function                | Description                                                      |
|-------------------------|------------------------------------------------------------------|
| `--ip`                  | Checks IP reputation using AbuseIPDB                            |
| `--whois`               | Performs WHOIS lookup on a domain or IP                         |
| `--hash`                | Queries VirusTotal to check if a file hash is malicious         |
| `--email`               | Parses raw email headers and extracts useful investigation info |

---

## 🚀 Usage Examples

```bash
# IP reputation check
python soctoolkit.py --ip 8.8.8.8

# WHOIS lookup
python soctoolkit.py --whois google.com

# Hash check
python soctoolkit.py --hash 44d88612fea8a8f36de82e1278abb02f

# Email header parser
python soctoolkit.py --email "C:\Users\You\Documents\sample-header.txt"
