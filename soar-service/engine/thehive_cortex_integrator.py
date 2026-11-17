import os
import time
import hashlib
import logging
import requests
from engine.action_executor import ActionExecutor

logger = logging.getLogger("SOAR-Integrator")


class IncidentIntegrator:
    def __init__(self):
        self.thehive_url = os.getenv(
            "THEHIVE_URL", "http://thehive:9000"
        ).rstrip("/")
        self.thehive_key = os.getenv("THEHIVE_API_KEY")
        self.org_name = os.getenv("THEHIVE_ORG", "EduQual_SOC")

        self.session = requests.Session()
        self.headers = {
            "Authorization": f"Bearer {self.thehive_key}",
            "X-Organisation": self.org_name,
            "Content-Type": "application/json"
        }

        if not self.thehive_key:
            raise ValueError("THEHIVE_API_KEY is missing")

    def _request(self, method, endpoint, **kwargs):
        url = f"{self.thehive_url}{endpoint}"
        response = self.session.request(
            method, url, headers=self.headers, timeout=30, **kwargs
        )

        if not response.ok:
            raise RuntimeError(
                f"TheHive API error {response.status_code}: "
                f"{response.text[:1000]}"
            )

        if response.status_code == 204 or not response.text.strip():
            return None

        return response.json()

    def _alert_tag(self, alert_data):
        # Prefer a unique ID supplied by the SIEM.
        identity = alert_data.get("alert_id")

        # Demo fallback: identical attack type + IP = same alert.
        if not identity:
            identity = (
                f"{alert_data.get('attack_type', 'Threat')}|"
                f"{alert_data.get('source_ip', 'Unknown')}"
            )

        digest = hashlib.sha256(
            str(identity).encode("utf-8")
        ).hexdigest()[:16]

        return f"SOAR-ALERT-{digest}"

    def _find_existing_case(self, alert_tag):
        # Check recent cases for the same SOAR alert fingerprint.
        result = self._request(
            "POST",
            "/api/v1/query",
            json={
                "query": [
                    {"_name": "listCase"},
                    {"_name": "sort",
                     "_fields": [{"_createdAt": "desc"}]},
                    {"_name": "page", "from": 0, "to": 100}
                ]
            }
        )

        if not isinstance(result, list):
            return None

        for case in result:
            if alert_tag in (case.get("tags") or []):
                return case.get("id") or case.get("_id")

        return None

    def _get_analyzer(self, analyzer_name, observable_type):
        analyzers = self._request(
            "GET", "/api/connector/cortex/analyzer"
        )

        for analyzer in analyzers or []:
            if (
                analyzer.get("name") == analyzer_name
                and observable_type in analyzer.get("dataTypeList", [])
            ):
                return analyzer

        raise RuntimeError(
            f"Analyzer {analyzer_name} supporting "
            f"{observable_type} was not found in TheHive."
        )

    def _run_cortex_job(
        self,
        observable_id,
        analyzer_name="IP-API_1_1",
        observable_type="ip"
    ):
        analyzer = self._get_analyzer(
            analyzer_name, observable_type
        )

        analyzer_id = analyzer.get("id")
        cortex_ids = analyzer.get("cortexIds") or []

        if not analyzer_id:
            raise RuntimeError("Analyzer response has no analyzer ID.")

        if not cortex_ids:
            raise RuntimeError(
                f"No Cortex instance is associated with {analyzer_name}."
            )

        payload = {
            "analyzerId": analyzer_id,
            "cortexId": cortex_ids[0],
            "artifactId": observable_id
        }

        logger.info(
            "[CORTEX] Starting %s for observable %s",
            analyzer_name, observable_id
        )

        job = self._request(
            "POST",
            "/api/connector/cortex/job",
            json=payload
        )

        job_id = (job or {}).get("id") or (job or {}).get("_id")

        if not job_id:
            raise RuntimeError(
                f"TheHive did not return a Cortex job ID: {job}"
            )

        # Wait for the actual job result.
        job_endpoint = f"/api/connector/cortex/job/{job_id}"

        for attempt in range(1, 25):
            result = self._request("GET", job_endpoint)
            status = (result or {}).get("status", "Unknown")

            logger.info(
                "[CORTEX] Job %s status: %s (attempt %s/24)",
                job_id, status, attempt
            )

            if status == "Success":
                report = result.get("report")

                if not report:
                    raise RuntimeError(
                        f"Cortex job {job_id} succeeded but report is missing."
                    )

                return {
                    "status": "Success",
                    "job_id": job_id,
                    "cortex_job_id": result.get("cortexJobId"),
                    "analyzer": result.get("analyzerName"),
                    "report": report
                }

            if status in ("Failure", "Deleted"):
                raise RuntimeError(
                    f"Cortex job {job_id} finished with status {status}: "
                    f"{result}"
                )

            time.sleep(5)

        raise TimeoutError(
            f"Cortex job {job_id} did not finish within 120 seconds."
        )

    def create_thehive_case(self, alert_data, decision_meta):
        alert_data = alert_data or {}
        decision_meta = decision_meta or {}

        source_ip = alert_data.get("source_ip")
        if not source_ip:
            raise ValueError("Alert is missing source_ip.")

        alert_tag = self._alert_tag(alert_data)

        # Duplicate check before creating a new case.
        existing_case_id = self._find_existing_case(alert_tag)

        if existing_case_id:
            logger.warning(
                "[THEHIVE] Duplicate alert detected. "
                "Existing case: %s", existing_case_id
            )
            return {
                "status": "Duplicate",
                "case_id": existing_case_id,
                "alert_tag": alert_tag
            }

        title = (
            f"[AUTO-IR] "
            f"{alert_data.get('attack_type', 'Threat')} "
            f"detected from {source_ip}"
        )

        description = (
            "Automated incident response triggered.\n\n"
            f"Attack Type: {alert_data.get('attack_type')}\n"
            f"Calculated Severity Score: "
            f"{decision_meta.get('calculated_score')}\n"
            f"Executed Playbook: {decision_meta.get('playbook')}\n"
            f"Source IP: {source_ip}\n"
            f"Alert ID: {alert_data.get('alert_id', 'Not provided')}\n"
        )

        # === MISP Tag Add Karne Ka Code (Gap 3 Fix) ===
        tags = [
            "SOAR",
            "Auto-Response",
            alert_data.get("attack_type", "General"),
            alert_tag
        ]
        
        misp_event_id = decision_meta.get("misp_event_id")
        if misp_event_id:
            tags.append(f"misp-event-{misp_event_id}")
            logger.info(f"[THEHIVE] MISP event ID {misp_event_id} added to case tags.")
        # ===============================================

        payload = {
            "title": title,
            "description": description,
            "severity": (
                3 if decision_meta.get("is_dangerous") else 2
            ),
            "startDate": int(time.time() * 1000),
            "tags": tags,  # <-- Yahan updated tags list use ho rahi hai
            "flag": bool(decision_meta.get("is_dangerous", False))
        }

        # 1. Create case.
        case_data = self._request(
            "POST", "/api/v1/case", json=payload
        )

        case_id = (
            case_data.get("id") or case_data.get("_id")
        )

        if not case_id:
            raise RuntimeError(
                f"TheHive created no identifiable case: {case_data}"
            )

        logger.info("[THEHIVE] Created case %s", case_id)

        # 2. Add observable to this case.
        observable_payload = {
            "dataType": "ip",
            "data": source_ip,
            "tlp": 2,
            "pap": 2,
            "ioc": True,
            "message": "Automatically added by SOAR integration engine"
        }

        observable_data = self._request(
            "POST",
            f"/api/v1/case/{case_id}/observable",
            json=observable_payload
        )

        if isinstance(observable_data, list):
            observable = (
                observable_data[0] if observable_data else {}
            )
        else:
            observable = observable_data or {}

        observable_id = (
            observable.get("id") or observable.get("_id")
        )

        if not observable_id:
            raise RuntimeError(
                f"Observable was not created correctly: {observable_data}"
            )

        logger.info(
            "[THEHIVE] Observable %s added to case %s",
            observable_id, case_id
        )

        # 3. Run Cortex through TheHive connector.
        cortex_result = self._run_cortex_job(
            observable_id=observable_id,
            analyzer_name="IP-API_1_1",
            observable_type="ip"
        )

        logger.info(
            "[CORTEX] Analysis completed for case %s",
            case_id
        )

        # 4. Execute Automated Playbook Actions based on Decision Engine
        action_executor = ActionExecutor()
        playbook_actions = action_executor.execute_playbook_action(decision_meta, alert_data)
        logger.info(f"[SOAR] Playbook Actions Executed: {playbook_actions}")

        return {
            "status": "Success",
            "case_id": case_id,
            "observable_id": observable_id,
            "alert_tag": alert_tag,
            "cortex_result": cortex_result,
            "playbook_actions": playbook_actions
        }
