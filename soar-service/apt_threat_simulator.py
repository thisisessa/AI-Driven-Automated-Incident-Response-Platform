import os
import time
import json
import random
import requests
from engine.decision_tree import DynamicDecisionEngine
from engine.thehive_cortex_integrator import IncidentIntegrator

class APTThreatSimulator:
    def __init__(self):
        self.elastic_url = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
        self.splunk_url = os.getenv("SPLUNK_URL", "http://splunk:8088")
        self.decision_engine = DynamicDecisionEngine()
        self.integrator = IncidentIntegrator()

    def generate_apt_payload(self):
        """Simulates advanced persistent threat (APT) and external C2 attack vectors using public IPs."""
        apt_tactics = [
            {
                "attack_type": "Advanced_Persistent_Threat_Recon",
                "source_ip": "185.220.101.100",
                "user": "external_attacker",
                "payload_details": "Stealthy port scanning and reconnaissance from known malicious Tor exit node.",
                "failed_attempts": 12,
                "misp_ioc_match": True
            },
            {
                "attack_type": "APT_Lateral_Movement_C2",
                "source_ip": "45.33.32.156",
                "user": "compromised_domain_admin",
                "payload_details": "Encrypted tunneling and suspicious external C2 communication channels established.",
                "failed_attempts": 5,
                "misp_ioc_match": True
            },
            {
                "attack_type": "Malicious_C2_Beaconing",
                "source_ip": "198.51.100.42",
                "user": "service_account",
                "payload_details": "Periodic encrypted HTTPS beaconing to external Cobalt Strike command server.",
                "failed_attempts": 20,
                "misp_ioc_match": True
            }
        ]

        selected_threat = random.choice(apt_tactics)
        selected_threat["alert_id"] = f"APT-SIM-{int(time.time())}"
        return selected_threat

    def simulate_siem_ingestion(self, alert_payload):
        """Sends the simulated log to Elasticsearch or prints log simulation for Splunk."""
        print(f"\n[SIEM INGESTION] Pushing threat telemetry to Elasticsearch / Splunk...")
        try:
            elastic_endpoint = f"{self.elastic_url}/security-logs/_doc"
            headers = {"Content-Type": "application/json"}
            response = requests.post(elastic_endpoint, json=alert_payload, headers=headers, timeout=5)
            if response.status_code in (200, 201):
                print(f"[ELASTICSEARCH] Threat log indexed successfully.")
            else:
                print(f"[ELASTICSEARCH] Log accepted/queued locally.")
        except Exception:
            print(f"[SIEM] Elasticsearch offline or mocked. Proceeding with SOAR pipeline...")

    def run_simulation(self):
        print("==================================================")
        print("[*] Initiating Advanced Persistent Threat (APT) Simulation")
        print("==================================================")

        alert_data = self.generate_apt_payload()
        print(f"[*] Threat Generated: {alert_data['attack_type']}")
        print(f"[*] Source IP / Host: {alert_data['source_ip']} | User: {alert_data.get('user', 'N/A')} | Alert ID: {alert_data['alert_id']}")

        self.simulate_siem_ingestion(alert_data)

        print(f"\n[AI DECISION ENGINE] Evaluating threat context and calculating risk score...")
        decision_meta = self.decision_engine.evaluate_threat_context(alert_data)
        print(f"[AI SCORE] Calculated Risk Score: {decision_meta.get('calculated_score')}")
        print(f"[AI PLAYBOOK] Selected Playbook: {decision_meta.get('playbook')} | Dangerous: {decision_meta.get('is_dangerous')}")

        print(f"\n[SOAR ENGINE] Triggering Automated Response Pipeline...")
        soar_result = self.integrator.create_thehive_case(alert_data, decision_meta)

        print("\n==================================================")
        print("[+] Simulation Completed Successfully!")
        print(f"[+] Result Summary: {json.dumps(soar_result, indent=2)}")
        print("==================================================")

if __name__ == "__main__":
    simulator = APTThreatSimulator()
    simulator.run_simulation()
