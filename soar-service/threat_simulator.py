import os
import time
import json
import random
import logging
import requests
import urllib3
from engine.decision_tree import DynamicDecisionEngine
from engine.thehive_cortex_integrator import IncidentIntegrator
from engine.action_executor import ActionExecutor

# AI Engine imports (GAP 1, 2, 6, 7 fixes)
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from ai_engine.spark_processor import EnterpriseSparkLogProcessor
    from ai_engine.behavioral_ml import BehavioralAnomalyDetector
    AI_ENGINE_AVAILABLE = True
except ImportError as e:
    print(f"[WARN] AI engine not available: {e}")
    AI_ENGINE_AVAILABLE = False

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = logging.getLogger("SOAR-ThreatSimulator")

class ThreatSimulator:
    def __init__(self):
        self.es_doc_url = os.getenv("ES_URL", "http://elasticsearch:9200/enterprise-security-logs/_doc/")
        self.splunk_hec_url = os.getenv("SPLUNK_HEC_URL", "http://splunk:8088/services/collector")
        self.splunk_hec_token = os.getenv("SPLUNK_HEC_TOKEN")

        elastic_base = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
        if not os.getenv("ES_URL"):
            self.es_doc_url = f"{elastic_base.rstrip('/')}/enterprise-security-logs/_doc/"

        self.decision_engine = DynamicDecisionEngine()
        self.integrator = IncidentIntegrator()
        self.action_executor = ActionExecutor()

        # GAP 2: Spark init
        self.spark_processor = None
        if AI_ENGINE_AVAILABLE:
            try:
                self.spark_processor = EnterpriseSparkLogProcessor()
            except Exception as e:
                print(f"[WARN] Spark init failed: {e}")

        # GAP 6: Behavioral ML init
        self.behavioral_detector = None
        if AI_ENGINE_AVAILABLE:
            try:
                self.behavioral_detector = BehavioralAnomalyDetector()
            except Exception as e:
                print(f"[WARN] Behavioral ML init failed: {e}")

    def generate_threat_payload(self):
        attack_tactics = [
            {
                "attack_type": "Insider_Data_Exfiltration",
                "source_ip": "10.0.4.55",
                "host": "HR-WORKSTATION-09",
                "user": "j.smith",
                "payload_details": "User j.smith accessed 500+ sensitive files at 2:00 AM and uploaded 2.5GB to external cloud storage.",
                "failed_attempts": 1,
                "misp_ioc_match": False,
                "volume": 500,
                "is_off_hours": 1,
            },
            {
                "attack_type": "DDoS",
                "source_ip": "185.143.223.17",
                "host": "EDGE-LB-01",
                "user": "external",
                "payload_details": "High-volume volumetric DDoS flood targeting public-facing load balancer.",
                "failed_attempts": 50,
                "misp_ioc_match": True,
                "volume": 50000,
                "is_off_hours": 0,
            },
            {
                "attack_type": "Zero_Day_Exploitation",
                "source_ip": "91.219.237.45",
                "host": "WEB-APP-01",
                "user": "www-data",
                "payload_details": "Unknown exploit targeting unpatched web service, shellcode injection observed.",
                "failed_attempts": 3,
                "misp_ioc_match": True,
                "volume": 100,
                "is_off_hours": 1,
            },
            {
                "attack_type": "Ransomware_Execution_Attempt",
                "source_ip": "103.27.202.88",
                "host": "FILE-SERVER-03",
                "user": "backup_svc",
                "payload_details": "Ransomware payload detected attempting mass file encryption.",
                "failed_attempts": 8,
                "misp_ioc_match": True,
                "volume": 800,
                "is_off_hours": 0,
            },
        ]

        selected = random.choice(attack_tactics)
        selected["alert_id"] = f"THREAT-SIM-{int(time.time())}"
        selected["message"] = selected["payload_details"]
        return selected

    def build_siem_document(self, alert, decision_meta, behavioral_result=None):
        score = decision_meta.get("calculated_score", 50)
        severity = decision_meta.get("severity", "MEDIUM")

        return {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()),
            "host": alert.get("host", "unknown"),
            "source_ip": alert.get("source_ip"),
            "event_type": alert.get("attack_type"),
            "message": alert.get("payload_details") or alert.get("message"),
            "volume": alert.get("volume", alert.get("failed_attempts", 1)),
            "user": alert.get("user"),
            "alert_id": alert.get("alert_id"),
            "event_source": "threat_simulator",
            "pipeline": "threat-simulator",
            "is_attack_signal": True,
            "misp_threat_intel_matched": bool(alert.get("misp_ioc_match")),
            "misp_event_id": decision_meta.get("misp_event_id"),
            "misp_event_info": decision_meta.get("misp_event_info"),
            "intelligence_note": f"Simulated Threat | {alert.get('attack_type')}",
            "ai_risk_score": int(score),
            "ai_severity_grade": severity,
            "playbook": decision_meta.get("playbook"),
            "is_dangerous": decision_meta.get("is_dangerous"),
            "scikit_learn_ml_analysis": {
                "isolation_forest_score": behavioral_result.get("z_score", 0.0) if behavioral_result else 0.0,
                "is_behavioral_anomaly": behavioral_result.get("is_anomaly", False) if behavioral_result else False,
                "model_detection_label": behavioral_result.get("detection_label", "N/A") if behavioral_result else "N/A",
            },
            "tensorflow_deep_analysis": {
                "tensorflow_deep_score": decision_meta.get("tensorflow_deep_score", 0.0),
                "is_advanced_threat": decision_meta.get("is_advanced_threat", False),
            },
        }

    def simulate_siem_ingestion(self, alert_payload, siem_doc):
        print("\n[SIEM INGESTION] Pushing threat telemetry to Elasticsearch / Splunk...")
        doc_id = alert_payload["alert_id"]

        try:
            res = requests.post(f"{self.es_doc_url}{doc_id}", json=siem_doc,
                              headers={"Content-Type": "application/json"}, timeout=5)
            if res.status_code in (200, 201):
                print(f"[ELASTICSEARCH] Indexed {doc_id} | {siem_doc['event_type']} | score={siem_doc['ai_risk_score']}")
        except Exception as e:
            print(f"[ELASTICSEARCH] Error: {e}")

        if self.splunk_hec_token:
            try:
                payload = {
                    "time": time.time(),
                    "host": siem_doc.get("host", "unknown"),
                    "source": "threat-simulator",
                    "sourcetype": "_json",
                    "event": siem_doc,
                }
                headers = {"Authorization": f"Splunk {self.splunk_hec_token}", "Content-Type": "application/json"}
                res = requests.post(self.splunk_hec_url, json=payload, headers=headers, verify=False, timeout=5)
                if res.status_code == 200:
                    print(f"[SPLUNK HEC] Forwarded | {siem_doc['event_type']} | IP={siem_doc['source_ip']}")
            except Exception as e:
                print(f"[SPLUNK HEC] Error: {e}")

    def run_simulation(self):
        print("==================================================")
        print("[*] Initiating Multi-Vector Threat Simulation")
        print("==================================================")

        alert_data = self.generate_threat_payload()

        print(f"[*] Threat Generated: {alert_data['attack_type']}")
        print(f"[*] Source IP / Host: {alert_data['source_ip']} | User: {alert_data.get('user', 'N/A')} | Alert ID: {alert_data['alert_id']}")
        print(f"[*] Details: {alert_data['payload_details']}")

        # === GAP 6: BEHAVIORAL ML ANALYSIS ===
        behavioral_result = None
        if self.behavioral_detector:
            print("\n[AI BEHAVIORAL ANALYSIS] Running IsolationForest behavioral detection...")
            z_score, is_anomaly, label = self.behavioral_detector.analyze_behavior(
                host=alert_data.get("host", "unknown"),
                volume=alert_data.get("volume", 1),
                is_off_hours=alert_data.get("is_off_hours", 0)
            )
            behavioral_result = {"z_score": z_score, "is_anomaly": is_anomaly, "detection_label": label}
            logger.info(f"[BEHAVIORAL PROOF] Host={alert_data.get('host')} | Volume={alert_data.get('volume')} | Z-Score={z_score}")
            logger.info(f"[BEHAVIORAL PROOF] Anomaly={is_anomaly} | Label={label}")

        # === DECISION ENGINE (ML + MISP + TensorFlow) ===
        print("\n[AI DECISION ENGINE] Evaluating threat context...")
        decision_meta = self.decision_engine.evaluate_threat_context(alert_data)
        score = decision_meta.get("calculated_score")
        print(f"[AI SCORE] Risk Score: {score} | Severity: {decision_meta.get('severity')}")
        print(f"[AI PLAYBOOK] Selected: {decision_meta.get('playbook')} | Dangerous: {decision_meta.get('is_dangerous')}")

        # === BUILD + INGEST SIEM DOC ===
        siem_doc = self.build_siem_document(alert_data, decision_meta, behavioral_result)
        self.simulate_siem_ingestion(alert_data, siem_doc)

        # === GAP 2 + 7: SPARK PROCESSING + AGGREGATION ===
        if self.spark_processor:
            print("\n[SPARK] Submitting batch log analysis job...")
            batch_logs = [
                {"source_ip": alert_data["source_ip"], "event_type": alert_data["attack_type"],
                 "ai_risk_score": score, "volume": alert_data.get("volume", 1)},
                {"source_ip": alert_data["source_ip"], "event_type": alert_data["attack_type"],
                 "ai_risk_score": max(score - 5, 0), "volume": alert_data.get("volume", 1)},
                {"source_ip": alert_data["source_ip"], "event_type": alert_data["attack_type"],
                 "ai_risk_score": max(score - 10, 0), "volume": alert_data.get("volume", 1)},
            ]
            self.spark_processor.process_log_stream_batch(batch_logs)
            self.spark_processor.aggregate_alerts(batch_logs)

        # === SOAR PIPELINE ===
        print("\n[SOAR ENGINE] Triggering Automated Response Pipeline...")
        print(f"[SOAR] Target IP for response actions: {alert_data['source_ip']}")
        
        # decision_meta ke andar MISP ID pass ho rahi hai, jo integrator use karega
        soar_result = self.integrator.create_thehive_case(alert_data, decision_meta)

        # === GAP 5: ACTION EXECUTOR ===
        print("\n[ACTION EXECUTOR] Executing playbook actions...")
        action_result = self.action_executor.execute_playbook_action(decision_meta, alert_data)
        print(f"[ACTION EXECUTOR] Result: {json.dumps(action_result, indent=2)}")

        print("\n==================================================")
        print("[+] Simulation Completed Successfully!")
        print(f"[+] Result Summary: {json.dumps(soar_result, indent=2)}")
        print("==================================================")


if __name__ == "__main__":
    simulator = ThreatSimulator()
    simulator.run_simulation()
