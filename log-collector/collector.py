import time
import random
import json
import requests
import os
import urllib3
from datetime import datetime, timezone, timedelta

from ai_engine.behavioral_ml import BehavioralAnomalyDetector
from ai_engine.risk_scorer import RiskScorer
from ai_engine.deep_threat_net import EnterpriseDeepThreatEngine
from ai_engine.spark_processor import EnterpriseSparkLogProcessor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200/enterprise-security-logs/_doc/")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "http://splunk:8088/services/collector")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "cc758cae-10ed-4283-943e-114f025e192e")

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
    print("[*] Initializing Enterprise IR Engine with scikit-learn, TensorFlow & Apache Spark...", flush=True)

    behavior_detector = BehavioralAnomalyDetector()
    risk_scorer = RiskScorer()

    # Initialize TensorFlow & Spark engines for 30GB RAM server
    deep_threat_engine = EnterpriseDeepThreatEngine()
    spark_processor = EnterpriseSparkLogProcessor()

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

        # 1. Apache Spark Batch Processing Simulation on Raw Event (PKT Timezone)
        pkt_time = datetime.now(timezone(timedelta(hours=5)))
        raw_event_dict = {
            "timestamp": pkt_time.strftime("%Y-%m-%dT%H:%M:%S+05:00"),
            "host": event["source"],
            "source_ip": event["ip"],
            "event_type": event["type"],
            "message": event["log"],
            "volume": event.get("volume", 1)
        }
        batched_logs = spark_processor.process_log_stream_batch([raw_event_dict])

        print(f"-> [Apache Spark Engine] Batch Processed Log | Host: {raw_event_dict['host']} | Event: {raw_event_dict['event_type']}")

        processed_event = batched_logs[0] if batched_logs else raw_event_dict

        # 2. scikit-learn Behavioral Analysis & Risk Scoring
        z_score, is_anomaly, detection_label = behavior_detector.analyze_behavior(
            processed_event["host"], processed_event["volume"]
        )
        risk_score, severity_grade = risk_scorer.calculate_risk(
            processed_event["event_type"], threat_matched, is_anomaly, processed_event["volume"]
        )

        # 3. TensorFlow Deep Learning Neural Network Prediction
        deep_res = deep_threat_engine.predict_deep_threat(
            risk_score=risk_score,
            anomaly_score=z_score,
            misp_match=threat_matched,
            time_dev=0.5,
            payload_size=processed_event["volume"] * 10
        )

        log_entry = {
            "timestamp": processed_event["timestamp"],
            "host": processed_event["host"],
            "source_ip": processed_event["source_ip"],
            "event_type": processed_event["event_type"],
            "message": processed_event["message"],
            "misp_threat_intel_matched": threat_matched,
            "intelligence_note": matched_note,
            "scikit_learn_ml_analysis": {
                "isolation_forest_score": z_score,
                "is_behavioral_anomaly": is_anomaly,
                "model_detection_label": detection_label
            },
            "tensorflow_deep_analysis": deep_res,
            "ai_risk_score": risk_score,
            "ai_severity_grade": severity_grade
        }

        # 4. Elasticsearch Ingestion
        try:
            res_es = requests.post(f"{ES_URL}{counter}", json=log_entry, headers={"Content-Type": "application/json"}, timeout=3)
            if res_es.status_code in [200, 201]:
                print(f" -> [Elastic Security] Log {counter} | Grade: {severity_grade} | TF Score: {deep_res['tensorflow_deep_score']}% | MISP: {threat_matched}", flush=True)
        except Exception as e:
            print(f" -> [Elastic Error] {e}", flush=True)

        # 5. Splunk HEC Ingestion
        try:
            splunk_payload = {
                "time": time.time(),
                "host": event["source"],
                "source": "enterprise-ai-pipeline",
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
    try:
        run_background_collection()
    except KeyboardInterrupt:
        print("\n[*] Shutting down pipeline gracefully...")
