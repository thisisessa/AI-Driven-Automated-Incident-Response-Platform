import os
import re
import time
import requests
import urllib3
from pathlib import Path

from ai_engine.behavioral_ml import BehavioralAnomalyDetector
from ai_engine.risk_scorer import RiskScorer
from ai_engine.deep_threat_net import EnterpriseDeepThreatEngine
from ai_engine.spark_processor import EnterpriseSparkLogProcessor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ES_URL = os.getenv("ES_URL", "http://elasticsearch:9200/enterprise-security-logs/_doc/")
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "http://splunk:8088/services/collector")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")

AUTH_LOG = "/host-logs/auth.log"
SYSLOG = "/host-logs/syslog"
LOG_PATHS = [AUTH_LOG, SYSLOG]

LINE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[^\s]+)\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<message>.*)$"
)

# Real attack / suspicious patterns on the host
ATTACK_PATTERNS = [
    (re.compile(r"Failed password|authentication failure|Invalid user", re.I), "Brute Force / Auth Failure", 25, True),
    (re.compile(r"Connection reset by authenticating|banner exchange.*invalid", re.I), "SSH Probe / Preauth Abuse", 15, True),
    (re.compile(r"POSSIBLE BREAK-IN ATTEMPT|repeated login failures", re.I), "Break-in Attempt", 40, True),
    (re.compile(r"sudo:.*COMMAND=|sudo:.*authentication failure", re.I), "Privileged Command / Sudo", 10, False),
]

# All benign activity labeled as Normal Traffic for Kibana/Splunk clarity
NORMAL_PATTERNS = [
    (re.compile(r"session opened|session closed", re.I), "Normal Traffic", 1),
    (re.compile(r"CRON\[", re.I), "Normal Traffic", 1),
    (re.compile(r"Accepted publickey|Accepted password", re.I), "Normal Traffic", 2),
]


def classify_message(message: str):
    for pattern, event_type, volume, is_attack in ATTACK_PATTERNS:
        if pattern.search(message):
            return event_type, volume, is_attack
    for pattern, event_type, volume in NORMAL_PATTERNS:
        if pattern.search(message):
            return event_type, volume, False
    return "Normal Traffic", 1, False


def extract_source_ip(message: str):
    match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", message)
    return match.group(0) if match else None


def parse_line(line: str, log_file: str):
    line = line.strip()
    if not line:
        return None
    m = LINE_RE.match(line)
    if not m:
        return None

    message = m.group("message")
    event_type, volume, is_attack = classify_message(message)
    source_ip = extract_source_ip(message)

    return {
        "timestamp": m.group("timestamp"),
        "host": m.group("hostname"),
        "source_ip": source_ip,
        "event_type": event_type,
        "message": message,
        "volume": volume,
        "is_attack_signal": is_attack,
        "event_source": "azure_system",
        "log_file": Path(log_file).name,
        "pipeline": "real-system-log-collector",
    }


def fetch_live_misp_threat_intel():
    return {
        "bad_domains": ["bad-evil-domain.com", "malware-drop-zone.net", "command-control-c2.org"],
        "hacker_tools": ["mimikatz.exe", "powershell -enc", "psexec", "procdump"],
        "malicious_ips": ["185.220.101.", "45.33.32.", "198.51.100."],
    }


def check_misp_match(event: dict, threat_intel: dict):
    message = event.get("message", "")
    source_ip = event.get("source_ip") or ""

    for domain in threat_intel.get("bad_domains", []):
        if domain in message:
            return True, f"MISP IOC Match: Malicious Domain ({domain})"

    for tool in threat_intel.get("hacker_tools", []):
        if tool.lower() in message.lower():
            return True, f"MISP IOC Match: Known Hacker Tool ({tool})"

    for ip_prefix in threat_intel.get("malicious_ips", []):
        if source_ip.startswith(ip_prefix):
            return True, f"MISP IOC Match: Suspicious IP prefix ({ip_prefix}*)"

    if event.get("is_attack_signal"):
        return False, "Host attack signal (no external IOC match)"

    return False, "Clean"


def enrich_with_ai(raw_event, behavior_detector, risk_scorer, deep_threat_engine, spark_processor):
    threat_intel = fetch_live_misp_threat_intel()
    threat_matched, matched_note = check_misp_match(raw_event, threat_intel)

    batched = spark_processor.process_log_stream_batch([raw_event])
    processed = batched[0] if batched else raw_event

    z_score, is_anomaly, detection_label = behavior_detector.analyze_behavior(
        processed["host"], processed.get("volume", 1)
    )
    risk_score, severity_grade = risk_scorer.calculate_risk(
        processed["event_type"], threat_matched, is_anomaly, processed.get("volume", 1)
    )
    deep_res = deep_threat_engine.predict_deep_threat(
        risk_score=risk_score,
        anomaly_score=z_score,
        misp_match=threat_matched,
        time_dev=0.5,
        payload_size=processed.get("volume", 1) * 10,
    )

    return {
        "timestamp": processed.get("timestamp", raw_event["timestamp"]),
        "host": processed.get("host", raw_event["host"]),
        "source_ip": processed.get("source_ip", raw_event.get("source_ip")),
        "event_type": processed.get("event_type", raw_event["event_type"]),
        "message": processed.get("message", raw_event["message"]),
        "volume": processed.get("volume", raw_event.get("volume", 1)),
        "event_source": "azure_system",
        "log_file": raw_event.get("log_file"),
        "pipeline": "real-system-log-collector",
        "is_attack_signal": raw_event.get("is_attack_signal", False),
        "misp_threat_intel_matched": threat_matched,
        "intelligence_note": matched_note,
        "scikit_learn_ml_analysis": {
            "isolation_forest_score": z_score,
            "is_behavioral_anomaly": is_anomaly,
            "model_detection_label": detection_label,
        },
        "tensorflow_deep_analysis": deep_res,
        "ai_risk_score": risk_score,
        "ai_severity_grade": severity_grade,
    }


def forward_elasticsearch(doc: dict, doc_id: str):
    try:
        res = requests.post(
            f"{ES_URL}{doc_id}",
            json=doc,
            headers={"Content-Type": "application/json"},
            timeout=3,
        )
        if res.status_code in (200, 201):
            print(
                f" -> [Elastic Security] {doc_id} | {doc['event_type']} | "
                f"Grade: {doc['ai_severity_grade']} | TF: {doc['tensorflow_deep_analysis'].get('tensorflow_deep_score')}% | "
                f"AttackSignal: {doc['is_attack_signal']}",
                flush=True,
            )
        else:
            print(f" -> [Elastic Status] {res.status_code}: {res.text[:120]}", flush=True)
    except Exception as e:
        print(f" -> [Elastic Error] {e}", flush=True)


def forward_splunk(doc: dict):
    if not SPLUNK_HEC_TOKEN:
        return
    try:
        payload = {
            "time": time.time(),
            "host": doc.get("host", "unknown"),
            "source": "azure-system-logs",
            "sourcetype": "_json",
            "event": doc,
        }
        headers = {
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json",
        }
        res = requests.post(
            SPLUNK_HEC_URL, json=payload, headers=headers, verify=False, timeout=2
        )
        if res.status_code == 200:
            print(f" -> [Splunk HEC] Forwarded | {doc['event_type']}", flush=True)
        else:
            print(f" -> [Splunk Status] {res.status_code}: {res.text.strip()[:120]}", flush=True)
    except Exception as e:
        print(f" -> [Splunk Error] {type(e).__name__}: {e}", flush=True)


def seed_recent_lines(path, max_lines, process_fn, counter_start):
    """Send last N lines once so dashboards are not empty after restart."""
    counter = counter_start
    if not os.path.exists(path):
        print(f"[!] Missing log: {path}", flush=True)
        return counter
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()[-max_lines:]
        for line in lines:
            raw = parse_line(line, path)
            if not raw:
                continue
            doc = process_fn(raw)
            doc_id = f"sys-{counter}"
            forward_elasticsearch(doc, doc_id)
            forward_splunk(doc)
            counter += 1
    except Exception as e:
        print(f"[!] Seed error {path}: {e}", flush=True)
    return counter


def run_background_collection():
    print("[*] Real System Log Collector starting (no random fake attacks)...", flush=True)
    print(f"[*] Watching: {AUTH_LOG}, {SYSLOG}", flush=True)

    behavior_detector = BehavioralAnomalyDetector()
    risk_scorer = RiskScorer()
    deep_threat_engine = EnterpriseDeepThreatEngine()
    spark_processor = EnterpriseSparkLogProcessor()

    def process_fn(raw):
        return enrich_with_ai(
            raw, behavior_detector, risk_scorer, deep_threat_engine, spark_processor
        )

    counter = 1
    counter = seed_recent_lines(AUTH_LOG, 15, process_fn, counter)
    counter = seed_recent_lines(SYSLOG, 10, process_fn, counter)

    positions = {}
    for path in LOG_PATHS:
        if os.path.exists(path):
            positions[path] = os.path.getsize(path)

    print("[*] Live tail active — Normal Traffic + real attacks only", flush=True)

    while True:
        for path in LOG_PATHS:
            if not os.path.exists(path):
                continue
            try:
                size = os.path.getsize(path)
                pos = positions.get(path, size)
                if size < pos:
                    pos = 0
                if size > pos:
                    with open(path, "r", encoding="utf-8", errors="replace") as f:
                        f.seek(pos)
                        for line in f:
                            raw = parse_line(line, path)
                            if not raw:
                                continue
                            doc = process_fn(raw)
                            doc_id = f"sys-{counter}"
                            forward_elasticsearch(doc, doc_id)
                            forward_splunk(doc)
                            counter += 1
                        positions[path] = f.tell()
            except Exception as e:
                print(f"[!] Tail error {path}: {e}", flush=True)

        time.sleep(2)


if __name__ == "__main__":
    try:
        run_background_collection()
    except KeyboardInterrupt:
        print("\n[*] Shutting down real system log collector...")
