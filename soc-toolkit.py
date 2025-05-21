import requests
import argparse
import whois

# Replace this with your actual API key

ABUSEIPDB_API_KEY = 'b0761e38cc50c8c36cb29240c634da175b38fe5dea226654d94bbfaba3ce274eeb66835e1ac77c4c'

VIRUSTOTAL_API_KEY = '7069a072223c6a7093f075e0484f207897c8ad1ad97c3bc11758947174d6f057'

# Set up command-line argument parser
parser = argparse.ArgumentParser(description="SOC Analyst Toolkit")
parser.add_argument('--ip', help="Check IP address using AbuseIPDB")
parser.add_argument('--whois', help="Perform WHOIS lookup on domain or IP")
parser.add_argument('--hash', help="Check file hash against VirusTotal")
parser.add_argument('--email', help="Parse and extract fields from raw email headers")

args = parser.parse_args()

# -----------------------------
# IP Reputation Check (AbuseIPDB)
# -----------------------------
if args.ip:
    ip_address = args.ip
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {
        "ipAddress": ip_address,
        "maxAgeInDays": "90"
    }
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }

    response = requests.get(url, headers=headers, params=querystring)
    if response.status_code == 200:
        data = response.json()["data"]
        print(f"\n📌 IP Address: {data['ipAddress']}")
        print(f"🔺 Abuse Confidence Score: {data['abuseConfidenceScore']}%")
        print(f"📝 Total Reports: {data['totalReports']}")
        print(f"📅 Last Reported: {data['lastReportedAt']}")
    else:
        print("❌ Error:", response.status_code, response.text)

# -----------------------------
# WHOIS Lookup
# -----------------------------
if args.whois:
    print(f"\n🌐 Performing WHOIS lookup for: {args.whois}")
    try:
        result = whois.whois(args.whois)
        print("🔎 Domain:", result.domain_name)
        print("📅 Created:", result.creation_date)
        print("📅 Expires:", result.expiration_date)
        print("👤 Registrar:", result.registrar)
        print("📧 Email:", result.emails)
    except Exception as e:
        print("❌ WHOIS lookup failed:", str(e))

# -----------------------------
# VirusTotal Hash Lookup
# -----------------------------
if args.hash:
    print(f"\n🧬 Querying VirusTotal for hash: {args.hash}")
    url = f"https://www.virustotal.com/api/v3/files/{args.hash}"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }

    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()["data"]["attributes"]
        malicious = data["last_analysis_stats"]["malicious"]
        total = sum(data["last_analysis_stats"].values())
        print(f"🦠 Detections: {malicious} out of {total} scanners")
        print("🔍 File type:", data.get("type_description", "N/A"))
        print("📅 Last Analysis:", data.get("last_analysis_date", "N/A"))
    elif response.status_code == 404:
        print("❗ Hash not found in VirusTotal.")
    else:
        print("❌ Error:", response.status_code, response.text)

# -----------------------------
# Email Header Parser
# -----------------------------
if args.email:
    print(f"\n📬 Parsing email header file: {args.email}")
    try:
        with open(args.email, 'r', encoding='utf-8', errors='ignore') as file:
            header = file.read()

        def extract_field(header, field_name):
            for line in header.splitlines():
                if line.lower().startswith(field_name.lower() + ":"):
                    return line.split(":", 1)[1].strip()
            return "Not found"

        print("📤 From:", extract_field(header, "From"))
        print("📥 To:", extract_field(header, "To"))
        print("🧾 Subject:", extract_field(header, "Subject"))
        print("📨 Return-Path:", extract_field(header, "Return-Path"))

        print("\n🔗 Received Hops (Mail Routing):")
        for line in header.splitlines():
            if line.lower().startswith("received:"):
                print("  -", line)

        print("\n✅ Authentication Results:")
        for line in header.splitlines():
            if "dkim=" in line.lower() or "spf=" in line.lower() or "dmarc=" in line.lower():
                print("  ", line)

    except FileNotFoundError:
        print("❌ File not found.")
    except Exception as e:
        print("❌ Failed to parse header:", str(e))
