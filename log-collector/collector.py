import time
import random
import json
import requests
import os
import urllib3

from ai_engine.behavioral_ml import BehavioralAnomalyDetector
from ai_engine.risk_scorer import RiskScorer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200/enterprise-security-logs/_doc/")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "http://splunk:8088/services/collector")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "a1362da2-4df3-4099-93ad-03dd5b3d6071")

MISP_URL = os.getenv("MISP_URL", "http://misp")
MISP_AUTH_KEY = os.getenv("MISP_AUTH_KEY", "eKLRPS854kCk0XEGQO98rHVx0kQy4nNH4abqYry0")

ATTACK_PAYLOADS = [
    {"source": "WORKSTATION-01", "ip": "192.168.1.100", "log": "Failed SSH login for root from external suspicious IP", "type": "Brute Force", "volume": 15},
    {"source": "WORKSTATION-05", "ip": "10.0.0.45", "log": "PowerShell execution downloading payload from malicious domain bad-evil-domain.com", "type": "APT / Malicious URL", "volume": 2},
    {"source": "SERVER-DB-02", "ip": "172.16.0.12", "log": "Mass file rename to .locked extension with ransom note drop", "type": "Ransomware", "volume": 50},
    {"source": "WORKSTATION-09", "ip": "192.168.1.50", "log": "Unusual off-hours database query and mass export by internal employee", "type": "Insider Threat", "volume": 90},
    {"source": "WORKSTATION-09", "ip": "192.168.1.50", "log": "Standard HTTP GET request /index.html 200 OK", "type": "Normal Traffic", "volume": 1}
]

def fetch_live_misp_threat_intel():
    threat_feeds = {
        "bad_domains": ["bad-evil-domain.com", "malware-drop-zone.net", "command-control-c2.org"],
        "hacker_tools": ["mimikatz.exe", "powershell -enc", "psexec", "procdump"],
        "malicious_hashes": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    }
    return threat_feeds

def run_background_collection():
    print("[*] Initializing Enterprise IR Engine with scikit-learn ML & Dual-SIEM...", flush=True)

    behavior_detector = BehavioralAnomalyDetector()
    risk_scorer = RiskScorer()

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

        z_score, is_anomaly, detection_label = behavior_detector.analyze_behavior(
            event["source"], event.get("volume", 1)
        )
        risk_score, severity_grade = risk_scorer.calculate_risk(
            event["type"], threat_matched, is_anomaly, event.get("volume", 1)
        )

        log_entry = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "host": event["source"],
            "source_ip": event["ip"],
            "event_type": event["type"],
            "message": event["log"],
            "misp_threat_intel_matched": threat_matched,
            "intelligence_note": matched_note,
            "scikit_learn_ml_analysis": {
                "isolation_forest_score": z_score,
                "is_behavioral_anomaly": is_anomaly,
                "model_detection_label": detection_label
            },
            "ai_risk_score": risk_score,
            "ai_severity_grade": severity_grade
        }

        # 1. Elasticsearch Ingestion
        try:
            res_es = requests.post(f"{ES_URL}{counter}", json=log_entry, headers={"Content-Type": "application/json"}, timeout=3)
            if res_es.status_code in [200, 201]:
                print(f" -> [Elastic Security] Log {counter} | Grade: {severity_grade} | MISP: {threat_matched}", flush=True)
        except Exception as e:
            print(f" -> [Elastic Error] {e}", flush=True)

        # 2. Splunk HEC Ingestion (Printing Exact Error)
        try:
            splunk_payload = {
                "time": time.time(),
                "host": event["source"],
                "source": "scikit-learn-ml-pipeline",
                "sourcetype": "_json",
                "event": log_entry
            }
            splunk_headers = {
                "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
                "Content-Type": "application/json"
            }
            res_splunk = requests.post(SPLUNK_HEC_URL, json=splunk_payload, headers=splunk_headers, verify=False, timeout=2)
            if res_splunk.status_code == 200:
                print(f" -> [Splunk HEC] Log {counter} Forwarded Successfully!", flush=True)
            else:
                print(f" -> [Splunk Status] Code: {res_splunk.status_code} | Msg: {res_splunk.text.strip()}", flush=True)
        except Exception as e:
            print(f" -> [Splunk Error Details] {type(e).__name__}: {e}", flush=True)

        counter += 1
        time.sleep(6)

if __name__ == "__main__":
    run_background_collection()
