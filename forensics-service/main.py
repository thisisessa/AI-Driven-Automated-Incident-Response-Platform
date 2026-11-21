from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
import os
import logging
import requests
import time
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
THEHIVE_ORG = os.getenv("THEHIVE_ORG", "EduQual_SOC")

class ForensicRequest(BaseModel):
    case_id: str
    target_ip: str

def upload_to_thehive(case_id, report_path, hash_val, yara_matches):
    headers = {
        "Authorization": f"Bearer {THEHIVE_KEY}",
        "X-Organisation": THEHIVE_ORG
    }
    
    # 1. Hash Observable Add
    try:
        obs_payload = {"dataType": "hash", "data": hash_val, "message": "RAM Dump Hash - Validated by DFIR"}
        requests.post(f"{THEHIVE_URL}/api/v1/case/{case_id}/observable", json=obs_payload, headers=headers)
        logger.info("[THEHIVE] Observable added.")
    except Exception as e:
        logger.error(f"[THEHIVE] Observable fail: {e}")

    # 2. Task Create
    task_id = None
    try:
        task_payload = {
            "title": "Deep Digital Forensics & Evidence Gathering",
            "description": f"Automated DFIR executed.\nYARA Hits: {len(yara_matches)}\nHash: {hash_val}",
            "status": "Completed"
        }
        res_task = requests.post(f"{THEHIVE_URL}/api/v1/case/{case_id}/task", json=task_payload, headers=headers)
        
        # Error handling for task creation
        if res_task.status_code in [200, 201]:
            task_data = res_task.json()
            task_id = task_data.get('id') or task_data.get('_id')
            logger.info("[THEHIVE] Task created.")
        else:
            logger.error(f"[THEHIVE] Task creation failed: {res_task.text}")
            
    except Exception as e:
        logger.error(f"[THEHIVE] Task fail: {e}")

    # 3. Attachment Upload (Attaching to Task instead of Case to avoid 404)
    if task_id:
        try:
            with open(report_path, 'rb') as f:
                # TheHive HTML file ko block karta hai, isliye octet-stream bhej rahe hain
                files = {'attachment': (os.path.basename(report_path), f, 'application/octet-stream')}
                res_att = requests.post(f"{THEHIVE_URL}/api/v1/task/{task_id}/attachment", files=files, headers=headers)
                
                if res_att.status_code in [200, 201]:
                    logger.info(f"[THEHIVE] Attachment SUCCESS (Attached to Task).")
                else:
                    logger.error(f"[THEHIVE] Attachment FAILED: {res_att.text}")
        except Exception as e:
            logger.error(f"[THEHIVE] Attachment Exception: {e}")
    else:
        logger.error("[THEHIVE] Task ID missing, cannot attach file.")

    # 4. Case Resolve (Using 'Closed' status)
    try:
        status_payload = {"status": "Closed"} 
        res_patch = requests.patch(f"{THEHIVE_URL}/api/v1/case/{case_id}", json=status_payload, headers=headers)
        
        if res_patch.status_code == 200:
            logger.info(f"[THEHIVE] Case successfully Closed.")
        else:
            logger.error(f"[THEHIVE] Resolve Failed: {res_patch.text}")
    except Exception as e:
        logger.error(f"[THEHIVE] Resolve Exception: {e}")


@app.post("/api/v1/forensics/analyze")
async def run_deep_forensics(req: ForensicRequest, background_tasks: BackgroundTasks):
    logger.info(f"[DFIR INITIATED] Case: {req.case_id} | Target: {req.target_ip}")

    try:
        # 1. RAM Dump aur Volatility
        dump_path, dump_name, volatility_data = acquire_and_analyze_memory(req.case_id)

        # 2. YARA + ClamAV Scanners (Parallel)
        scan_results = run_all_scanners(dump_path)

        # 3. Hash Generate karna aur Evidence Secure karna
        hash_val, encrypted_path = secure_evidence(req.case_id, dump_path, dump_name)

        # 4. Cortex Threat Intel
        if scan_results.get("clamav", {}).get("status") == "MALWARE_DETECTED":
            logger.warning(f"[DFIR] Malware Detected! Enriching hash {hash_val} with Cortex...")
            cortex_report = enrich_hash_cortex(hash_val)
            scan_results["cortex_intel"] = cortex_report

        # 5. HTML Report Generate karna
        report_path = generate_html_report(req.case_id, req.target_ip, hash_val, volatility_data, scan_results)
        
        # 6. Background Task: TheHive Update
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
