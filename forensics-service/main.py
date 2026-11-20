from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
import os
import logging
import requests
from core.evidence_manager import secure_evidence
from core.forensics_engine import acquire_and_analyze_memory
from core.cortex_integrator import enrich_hash_cortex
from scanners.concurrent_scanner import run_all_scanners
from core.report_generator import generate_html_report

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("DFIR-Service")

app = FastAPI(title="Enterprise DFIR Microservice", version="2.0")

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://thehive:9000")
THEHIVE_KEY = os.getenv("THEHIVE_API_KEY", "")

class ForensicRequest(BaseModel):
    case_id: str
    target_ip: str

def upload_to_thehive(case_id, report_path, hash_val, yara_matches):
    """TheHive mein Report aur Hash bhejne ka logic"""
    headers = {"Authorization": f"Bearer {THEHIVE_KEY}"}
    
    # 1. Hash ko TheHive mein Observable ke taur par add karein
    obs_payload = {
        "dataType": "hash",
        "data": hash_val,
        "message": "RAM Dump Hash - Integrity Validated by DFIR Engine"
    }
    try:
        requests.post(f"{THEHIVE_URL}/api/v1/case/{case_id}/observable", json=obs_payload, headers=headers, timeout=10)
        logger.info(f"[THEHIVE] Hash {hash_val} pushed as Observable.")
    except Exception as e:
        logger.error(f"[THEHIVE] Failed to push observable: {e}")

    # 2. HTML Report ko Attachment ke taur par bhejein
    try:
        with open(report_path, 'rb') as f:
            files = {'attachment': (os.path.basename(report_path), f, 'text/html')}
            res = requests.post(f"{THEHIVE_URL}/api/v1/case/{case_id}/attachment", files=files, headers=headers, timeout=10)
            logger.info(f"[THEHIVE] Forensic Report attached to case {case_id}. Status: {res.status_code}")
    except Exception as e:
        logger.error(f"[THEHIVE] Failed to attach report: {e}")

@app.post("/api/v1/forensics/analyze")
async def run_deep_forensics(req: ForensicRequest, background_tasks: BackgroundTasks):
    logger.info(f"[DFIR INITIATED] Case: {req.case_id} | Target: {req.target_ip}")

    try:
        # 1. Acquire RAM
        dump_path, dump_name, volatility_data = acquire_and_analyze_memory(req.case_id)

        # 2. Parallel Scanners (YARA + ClamAV)
        logger.info("[DFIR] Running concurrent malware scanners...")
        scan_results = run_all_scanners(dump_path)

        # 3. Threat Intel Enrichment (Cortex)
        hash_val, encrypted_path = secure_evidence(req.case_id, dump_path, dump_name)

        if scan_results.get("clamav", {}).get("status") == "MALWARE_DETECTED":
            logger.warning(f"[DFIR] Malware Detected! Enriching hash {hash_val} with Cortex...")
            cortex_report = enrich_hash_cortex(hash_val)
            scan_results["cortex_intel"] = cortex_report

        # 4. Generate Reports
        report_path = generate_html_report(req.case_id, req.target_ip, hash_val, volatility_data, scan_results)

        # 5. Push to TheHive (Async)
        background_tasks.add_task(upload_to_thehive, req.case_id, report_path, hash_val, scan_results.get("yara", []))

        return {
            "status": "SUCCESS",
            "case_id": req.case_id,
            "evidence_secured": encrypted_path,
            "sha256": hash_val,
            "yara_hits": len(scan_results.get("yara", [])),
            "clamav_status": scan_results.get("clamav", {}).get("status")
        }

    except Exception as e:
        logger.error(f"[DFIR FATAL ERROR] {e}")
        raise HTTPException(status_code=500, detail=str(e))
