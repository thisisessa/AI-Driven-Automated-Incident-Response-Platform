import os
import json
import logging
from ai_engine.risk_scorer import RiskScorer
from ai_engine.deep_threat_net import EnterpriseDeepThreatEngine

logger = logging.getLogger("SOAR-Decision-Engine")

class DynamicDecisionEngine:
    def __init__(self):
        self.HIGH_CRITICALITY_SCORE = 75
        self.MEDIUM_CRITICALITY_SCORE = 45
        self.risk_scorer = RiskScorer()
        self.deep_engine = EnterpriseDeepThreatEngine()

    def check_misp_intel(self, source_ip):
        """
        GAP 3 FIX: MISP Event ID print karo
        """
        # Real MISP API call (agar available hai)
        try:
            from pymisp import PyMISP
            misp_url = os.getenv("MISP_URL", "https://misp.local")
            misp_key = os.getenv("MISP_API_KEY", "")
            if misp_key:
                misp = PyMISP(misp_url, misp_key, ssl=False, timeout=5)
                results = misp.search(controller='attributes', value=source_ip, type_attribute='ip-src')
                if results:
                    event = results[0].get('Event', {})
                    event_id = event.get('id', 'UNKNOWN')
                    event_info = event.get('info', 'N/A')
                    logger.info(f"[MISP HIT] Source IP={source_ip} MATCHED!")
                    logger.info(f"[MISP HIT] Event ID={event_id} | Info={event_info}")
                    return {"matched": True, "event_id": event_id, "info": event_info}
        except Exception as e:
            logger.debug(f"[MISP] Lookup skipped: {e}")

        # Fallback: MISP database se direct lookup (simulated)
        logger.info(f"[MISP] Simulated lookup for IP={source_ip} (MISP DB)")
        # Demo ke liye: known malicious IPs
        known_iocs = {
            "185.143.223.17": {"event_id": "2114", "info": "Enterprise Attack - DDoS Botnet"},
            "91.219.237.45": {"event_id": "2113", "info": "APT - Zero Day Exploitation"},
            "103.27.202.88": {"event_id": "2110", "info": "Ransomware Campaign 2026"},
            "185.220.101.100": {"event_id": "2108", "info": "Tor Exit Node / APT Recon"},
        }
        if source_ip in known_iocs:
            info = known_iocs[source_ip]
            logger.info(f"[MISP HIT] Source IP={source_ip} MATCHED!")
            logger.info(f"[MISP HIT] Event ID={info['event_id']} | Info={info['info']}")
            return {"matched": True, "event_id": info['event_id'], "info": info['info']}
        return {"matched": False}

    def evaluate_threat_context(self, alert_data):
        attack_type = alert_data.get("attack_type", "General")
        src_ip = alert_data.get("source_ip", "")
        failed_attempts = alert_data.get("failed_attempts", 0)

        # === MISP MATCHING (GAP 3) ===
        misp_result = self.check_misp_intel(src_ip)
        ioc_matched = misp_result.get("matched", False)

        # === ML RISK SCORE (GAP 1) ===
        is_anomaly = attack_type in ["Insider_Threat", "Insider_Data_Exfiltration"]
        ml_score, ml_severity = self.risk_scorer.calculate_risk(
            event_type=attack_type,
            threat_matched=ioc_matched,
            is_anomaly=is_anomaly,
            volume=failed_attempts
        )
        logger.info(f"[DECISION ENGINE] ML-based Risk Score={ml_score} | Severity={ml_severity}")

        # === DEEP THREAT ANALYSIS (TensorFlow) ===
        deep_result = self.deep_engine.predict_deep_threat(
            risk_score=ml_score,
            anomaly_score=failed_attempts,
            misp_match=ioc_matched,
            time_dev=0.5,
            payload_size=failed_attempts * 10
        )
        logger.info(f"[DECISION ENGINE] TensorFlow Deep Score={deep_result['tensorflow_deep_score']} | Advanced Threat={deep_result['is_advanced_threat']}")

        # === PLAYBOOK SELECTION ===
        playbook_map = {
            "Ransomware_Execution_Attempt": ("PLAYBOOK_RANSOMWARE_CONTAINMENT_AND_ISOLATION", "EMERGENCY_HOST_ISOLATION"),
            "Advanced_Persistent_Threat": ("PLAYBOOK_APT_FORENSIC_CAPTURE_AND_CONTAINMENT", "IP_BLOCK"),
            "APT_Lateral_Movement_C2": ("PLAYBOOK_APT_FORENSIC_CAPTURE_AND_CONTAINMENT", "IP_BLOCK"),
            "Advanced_Persistent_Threat_Recon": ("PLAYBOOK_APT_FORENSIC_CAPTURE_AND_CONTAINMENT", "IP_BLOCK"),
            "Insider_Threat": ("PLAYBOOK_INSIDER_CREDENTIAL_REVOCATION_AND_AUDIT", "SESSION_REVOCATION"),
            "Insider_Data_Exfiltration": ("PLAYBOOK_INSIDER_CREDENTIAL_REVOCATION_AND_AUDIT", "SESSION_REVOCATION"),
            "Malicious_C2_Beaconing": ("PLAYBOOK_C2_BEACON_BLOCK_AND_ISOLATE", "IP_BLOCK"),
            "Zero_Day_Exploitation": ("PLAYBOOK_EMERGENCY_PATCH_AND_NETWORK_SEGMENTATION", "NETWORK_SEGMENTATION"),
            "Supply_Chain_Attack": ("PLAYBOOK_REGISTRY_QUARANTINE_AND_DEPENDENCY_AUDIT", "CONTAINER_QUARANTINE"),
            "DDoS": ("PLAYBOOK_DDOS_WAF_RATE_LIMITING_AND_BGP_SCRUBBING", "TRAFFIC_SCRUBBING"),
            "Phishing": ("PLAYBOOK_PHISHING_EMAIL_QUARANTINE_AND_PASSWORD_RESET", "MAILBOX_QUARANTINE"),
            "Bruteforce": ("PLAYBOOK_BRUTEFORCE_IP_RATE_LIMIT_AND_BLOCK", "IP_BLOCK"),
        }
        playbook, action_level = playbook_map.get(attack_type, ("PLAYBOOK_DEFAULT_GENERAL_MONITOR", "LOG_AND_OBSERVE"))

        score = ml_score
        is_dangerous = score >= self.HIGH_CRITICALITY_SCORE

        logger.info(f"[DECISION ENGINE] Threat: {attack_type} | Risk Score: {score} | Playbook: {playbook} | Dangerous: {is_dangerous}")

        return {
            "attack_type": attack_type,
            "calculated_score": score,
            "severity": ml_severity,
            "playbook": playbook,
            "action_level": action_level,
            "is_dangerous": is_dangerous,
            "source_ip": src_ip,
            "misp_matched": ioc_matched,
            "misp_event_id": misp_result.get("event_id"),
            "misp_event_info": misp_result.get("info"),
            "tensorflow_deep_score": deep_result['tensorflow_deep_score'],
            "is_advanced_threat": deep_result['is_advanced_threat'],
        }
