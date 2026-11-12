import os
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("SOAR-Decision-Engine")

class DynamicDecisionEngine:
    def __init__(self):
        # Criticality thresholds for adaptive response
        self.HIGH_CRITICALITY_SCORE = 75
        self.MEDIUM_CRITICALITY_SCORE = 45

    def evaluate_threat_context(self, alert_data):
        """
        Calculates dynamic risk score based on multi-vector attack types,
        source IP reputation, threat intel (MISP) alignment, and behavioral metrics.
        """
        score = 50
        attack_type = alert_data.get("attack_type", "General")
        src_ip = alert_data.get("source_ip", "")
        ioc_matched = alert_data.get("misp_ioc_match", False)
        failed_attempts = alert_data.get("failed_attempts", 0)

        # Multi-Vector Attack Matrix & Adaptive Playbook Selection
        if attack_type == "Ransomware_Execution_Attempt":
            score = 95
            playbook = "PLAYBOOK_RANSOMWARE_CONTAINMENT_AND_ISOLATION"
            action_level = "EMERGENCY_HOST_ISOLATION"
        elif attack_type in ["Advanced_Persistent_Threat", "APT_Lateral_Movement_C2", "Advanced_Persistent_Threat_Recon"]:
            score = 90
            playbook = "PLAYBOOK_APT_FORENSIC_CAPTURE_AND_CONTAINMENT"
            action_level = "IP_BLOCK"
        elif attack_type in ["Insider_Threat", "Insider_Data_Exfiltration"]:
            score = 85
            playbook = "PLAYBOOK_INSIDER_CREDENTIAL_REVOCATION_AND_AUDIT"
            action_level = "SESSION_REVOCATION"
        elif attack_type == "Malicious_C2_Beaconing":
            score = 88
            playbook = "PLAYBOOK_C2_BEACON_BLOCK_AND_ISOLATE"
            action_level = "IP_BLOCK"
        elif attack_type == "Zero_Day_Exploitation":
            score = 98
            playbook = "PLAYBOOK_EMERGENCY_PATCH_AND_NETWORK_SEGMENTATION"
            action_level = "NETWORK_SEGMENTATION"
        elif attack_type == "Supply_Chain_Attack":
            score = 90
            playbook = "PLAYBOOK_REGISTRY_QUARANTINE_AND_DEPENDENCY_AUDIT"
            action_level = "CONTAINER_QUARANTINE"
        elif attack_type == "DDoS":
            score = 80
            playbook = "PLAYBOOK_DDOS_WAF_RATE_LIMITING_AND_BGP_SCRUBBING"
            action_level = "TRAFFIC_SCRUBBING"
        elif attack_type == "Phishing":
            score = 75
            playbook = "PLAYBOOK_PHISHING_EMAIL_QUARANTINE_AND_PASSWORD_RESET"
            action_level = "MAILBOX_QUARANTINE"
        elif attack_type == "Bruteforce":
            score = 70 if failed_attempts > 10 else 40
            playbook = "PLAYBOOK_BRUTEFORCE_IP_RATE_LIMIT_AND_BLOCK"
            action_level = "IP_BLOCK"
        else:
            score = 50
            playbook = "PLAYBOOK_DEFAULT_GENERAL_MONITOR"
            action_level = "LOG_AND_OBSERVE"

        # Threat Intel (MISP) Context Enhancement
        if ioc_matched:
            score += 10
            if score > 100:
                score = 100

        # Behavioral Frequency Impact
        if failed_attempts > 15:
            score += 5
            if score > 100:
                score = 100

        is_dangerous = score >= self.HIGH_CRITICALITY_SCORE

        logger.info(f"[DECISION ENGINE] Threat: {attack_type} | Risk Score: {score} | Playbook: {playbook} | Dangerous: {is_dangerous}")

        return {
            "attack_type": attack_type,
            "calculated_score": score,
            "playbook": playbook,
            "action_level": action_level,
            "is_dangerous": is_dangerous,
            "source_ip": src_ip
        }
