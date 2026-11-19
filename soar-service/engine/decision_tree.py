import os
import json
import time
import logging
from ai_engine.risk_scorer import RiskScorer
from ai_engine.deep_threat_net import EnterpriseDeepThreatEngine

logger = logging.getLogger("SOAR-Decision-Engine")

MAPPING_FILE = "misp_mapping.json"

class DynamicDecisionEngine:
    def __init__(self):
        self.HIGH_CRITICALITY_SCORE = 75
        self.MEDIUM_CRITICALITY_SCORE = 45
        self.risk_scorer = RiskScorer()
        self.deep_engine = EnterpriseDeepThreatEngine()

    def _load_mapping(self):
        if os.path.exists(MAPPING_FILE):
            try:
                with open(MAPPING_FILE, 'r') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

    def _save_mapping(self, mapping):
        try:
            with open(MAPPING_FILE, 'w') as f:
                json.dump(mapping, f, indent=4)
        except Exception as e:
            logger.error(f"[MAPPING ERROR] Could not save mapping: {e}")

    # Yahan attack_type pass kiya hai taake event ka naam aur tags dynamic ho sakein
    def check_misp_intel(self, source_ip, attack_type="Unknown Attack"):
        mapping = self._load_mapping()

        # 1. Local Memory Check
        if source_ip in mapping:
            logger.info(f"[MISP MEMORY HIT] IP={source_ip} found in local JSON memory.")
            return {"matched": True, "event_id": mapping[source_ip], "info": "Locally mapped MISP Event"}

        # 2. Real MISP API Check & Auto-Create
        try:
            from pymisp import PyMISP, MISPEvent, MISPAttribute
            misp_url = os.getenv("MISP_URL", "https://misp.local")
            misp_key = os.getenv("MISP_API_KEY", "")

            if misp_key:
                misp = PyMISP(misp_url, misp_key, ssl=False, timeout=5)

                results = misp.search(controller='attributes', value=source_ip, pythonify=True)

                if results:
                    event_id = str(results[0].Event.id)
                    event_info = results[0].Event.info
                    logger.info(f"[MISP API HIT] IP={source_ip} matched Event ID={event_id}")
                    mapping[source_ip] = event_id
                    self._save_mapping(mapping)
                    return {"matched": True, "event_id": event_id, "info": event_info}

                else:
                    logger.info(f"[MISP AUTO-CREATE] New IP {source_ip} detected. Creating new MISP event...")

                    event = MISPEvent()
                    
                    # --- CHANGE 1: PROFESSIONAL DYNAMIC NAMING ---
                    event.info = f"Simulated {attack_type} from {source_ip}"
                    
                    event.distribution = 0
                    event.threat_level_id = 2
                    event.analysis = 0
                    
                    # --- CHANGE 2: PROFESSIONAL COLORFUL TAGS ---
                    event.add_tag('tlp:clear')
                    event.add_tag('type:OSINT')
                    event.add_tag('simulation')
                    event.add_tag(f'attack-type:{attack_type}')
                    event.add_tag('mitre-attack')

                    attr = MISPAttribute()
                    attr.type = 'ip-src'
                    attr.value = source_ip
                    attr.category = 'Network activity'
                    attr.to_ids = True
                    attr.distribution = 0
                    event.attributes.append(attr)

                    new_event = misp.add_event(event)

                    # --- BULLETPROOF ID EXTRACTION ---
                    if hasattr(new_event, 'id'):
                        event_id = str(new_event.id)
                    elif isinstance(new_event, dict) and 'id' in new_event:
                        event_id = str(new_event['id'])
                    elif isinstance(new_event, dict) and 'Event' in new_event:
                        event_id = str(new_event['Event']['id'])
                    else:
                        time.sleep(2)
                        chk = misp.search(controller='events', value=source_ip, pythonify=True)
                        if chk:
                            ev2 = chk[0].get('Event', {})
                            event_id = str(ev2.get('id') if isinstance(ev2, dict) else ev2.id)
                        else:
                            raise ValueError(f"Could not parse ID from MISP response: {new_event}")
                    
                    logger.info(f"[MISP AUTO-CREATE] Successfully created Event {event_id} with IP {source_ip}")
                    mapping[source_ip] = event_id
                    self._save_mapping(mapping)

                    return {"matched": True, "event_id": event_id, "info": "New MISP Event"}

        except Exception as e:
            logger.error(f"[MISP API ERROR] Failed to create event: {e}")

        # 3. Fallback
        fallback_event_id = str(int(time.time()))
        logger.warning(f"[MISP FALLBACK] MISP API DOWN. Generating Local ID: {fallback_event_id} for IP: {source_ip}")
        mapping[source_ip] = fallback_event_id
        self._save_mapping(mapping)
        return {"matched": True, "event_id": fallback_event_id, "info": "Dynamic Simulated Event"}

    def evaluate_threat_context(self, alert_data):
        attack_type = alert_data.get("attack_type", "General")
        src_ip = alert_data.get("source_ip", "")
        failed_attempts = alert_data.get("failed_attempts", 0)

        # Yahan humne attack_type bhi pass kar diya
        misp_result = self.check_misp_intel(src_ip, attack_type)
        ioc_matched = misp_result.get("matched", False)

        is_anomaly = attack_type in ["Insider_Threat", "Insider_Data_Exfiltration"]
        ml_score, ml_severity = self.risk_scorer.calculate_risk(
            event_type=attack_type,
            threat_matched=ioc_matched,
            is_anomaly=is_anomaly,
            volume=failed_attempts
        )

        deep_result = self.deep_engine.predict_deep_threat(
            risk_score=ml_score,
            anomaly_score=failed_attempts,
            misp_match=ioc_matched,
            time_dev=0.5,
            payload_size=failed_attempts * 10
        )

        playbook_map = {
            "Ransomware_Execution_Attempt": ("PLAYBOOK_RANSOMWARE_CONTAINMENT_AND_ISOLATION", "EMERGENCY_HOST_ISOLATION"),
            "Advanced_Persistent_Threat": ("PLAYBOOK_APT_FORENSIC_CAPTURE_AND_CONTAINMENT", "IP_BLOCK"),
            "Insider_Threat": ("PLAYBOOK_INSIDER_CREDENTIAL_REVOCATION_AND_AUDIT", "SESSION_REVOCATION"),
            "Insider_Data_Exfiltration": ("PLAYBOOK_INSIDER_CREDENTIAL_REVOCATION_AND_AUDIT", "SESSION_REVOCATION"),
            "Zero_Day_Exploitation": ("PLAYBOOK_EMERGENCY_PATCH_AND_NETWORK_SEGMENTATION", "NETWORK_SEGMENTATION"),
            "DDoS": ("PLAYBOOK_DDOS_WAF_RATE_LIMITING_AND_BGP_SCRUBBING", "TRAFFIC_SCRUBBING"),
            "Phishing": ("PLAYBOOK_PHISHING_EMAIL_QUARANTINE_AND_PASSWORD_RESET", "MAILBOX_QUARANTINE"),
            "Bruteforce": ("PLAYBOOK_BRUTEFORCE_IP_RATE_LIMIT_AND_BLOCK", "IP_BLOCK"),
        }
        playbook, action_level = playbook_map.get(attack_type, ("PLAYBOOK_DEFAULT_GENERAL_MONITOR", "LOG_AND_OBSERVE"))

        score = ml_score
        is_dangerous = score >= self.HIGH_CRITICALITY_SCORE

        logger.info(f"[DECISION ENGINE] Threat: {attack_type} | Risk Score: {score} | MISP Event: {misp_result.get('event_id')}")

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
