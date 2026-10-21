import time
import random
import json
import requests
import os
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ES_URL = os.getenv("ES_URL", "http://192.168.56.249:9200/enterprise-security-logs/_doc/")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://192.168.56.249:8088/services/collector")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "63acf0fb-92ed-49d7-a92f-7797dd12c439")

# Live MISP Configuration
MISP_URL = os.getenv("MISP_URL", "http://192.168.56.249:8080")
MISP_AUTH_KEY = os.getenv("MISP_AUTH_KEY", "YbVNuUv6ruFYoYGNNMt7FgxtLW77FtfFE2paU0xg")

ATTACK_PAYLOADS = [
    {"source": "WORKSTATION-01", "ip": "192.168.1.100", "log": "Failed SSH login for root from external suspicious IP", "type": "Brute Force"},
    {"source": "WORKSTATION-05", "ip": "10.0.0.45", "log": "PowerShell execution downloading payload from malicious domain bad-evil-domain.com", "type": "APT / Malicious URL"},
    {"source": "SERVER-DB-02", "ip": "172.16.0.12", "log": "Mass file rename to .locked extension with ransom note drop", "type": "Ransomware"},
    {"source": "WORKSTATION-09", "ip": "192.168.1.50", "log": "Standard HTTP GET request /index.html 200 OK", "type": "Normal Traffic"}
]

def fetch_live_misp_threat_intel():
    """Fetches live IOC threat feeds directly from the MISP API"""
    headers = {
        "Authorization": MISP_AUTH_KEY,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    # Fallback default IOCs just in case MISP is unreachable
    default_iocs = {
        "bad_domains": ["bad-evil-domain.com", "malware-drop-zone.net", "command-control-c2.org"],
        "hacker_tools": ["mimikatz.exe", "powershell -enc", "psexec", "procdump"],
        "malicious_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    }

    try:
        response = requests.get(f"{MISP_URL}/api/iocs", headers=headers, verify=False, timeout=3)
        if response.status_code == 200:
            data = response.json()
            if "indicators" in data:
                return data["indicators"]
    except Exception as e:
        pass
        
    return default_iocs

def run_background_collection():
    print("[*] Unified Log & Threat Intel Collector Initialized (ES + Splunk HEC + Live MISP)...", flush=True)
    counter = 1
    while True:
        event = random.choice(ATTACK_PAYLOADS)
        threat_intel = fetch_live_misp_threat_intel()

        threat_matched = False
        matched_note = "Clean"

        for domain in threat_intel.get("bad_domains", []):
            if domain in event["log"]:
                threat_matched = True
                matched_note = f"MISP IOC Match: Malicious Web Address ({domain})"

        for tool in threat_intel.get("hacker_tools", []):
            if tool in event["log"]:
                threat_matched = True
                matched_note = f"MISP IOC Match: Known Hacker Tool ({tool})"

        log_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": event["source"],
            "source_ip": event["ip"],
            "event_type": event["type"],
            "message": event["log"],
            "misp_threat_intel_matched": threat_matched,
            "intelligence_note": matched_note
        }

        # 1. Elasticsearch
        try:
            res_es = requests.post(f"{ES_URL}{counter}", json=log_entry, headers={"Content-Type": "application/json"}, timeout=3)
            if res_es.status_code in [200, 201]:
                print(f" -> [Elastic Security] Log {counter} indexed | MISP Match: {threat_matched}", flush=True)
        except Exception as e:
            print(f" -> [Elastic Error] {e}", flush=True)

        # 2. Splunk HEC
        try:
            splunk_payload = {
                "time": time.time(),
                "host": event["source"],
                "source": "misp-threat-intel-pipeline",
                "sourcetype": "_json",
                "event": log_entry
            }
            splunk_headers = {
                "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
                "Content-Type": "application/json"
            }
            res_splunk = requests.post(SPLUNK_HEC_URL, json=splunk_payload, headers=splunk_headers, verify=False, timeout=3)
            if res_splunk.status_code == 200:
                print(f" -> [Splunk HEC] Log {counter} forwarded successfully!", flush=True)
            else:
                print(f" -> [Splunk Error] Status Code: {res_splunk.status_code} | Output: {res_splunk.text}", flush=True)
        except Exception as e:
            print(f" -> [Splunk Connection Error] {e}", flush=True)

        counter += 1
        time.sleep(6)

if __name__ == "__main__":
    run_background_collection()
