import requests
import os

CORTEX_URL = os.getenv("CORTEX_URL", "http://cortex:9001")
CORTEX_KEY = os.getenv("CORTEX_API_KEY", "")

def enrich_hash_cortex(file_hash):
    """Sends malware hash to Cortex for VirusTotal analysis"""
    headers = {"Authorization": f"Bearer {CORTEX_KEY}"}
    payload = {
        "analyzerId": "VirusTotal_GetReport_3_0",
        "data": file_hash,
        "dataType": "hash"
    }
    try:
        res = requests.post(f"{CORTEX_URL}/api/analyzer/run", json=payload, headers=headers, timeout=15)
        if res.status_code == 200:
            return res.json()
        return {"error": "Cortex returned non-200"}
    except Exception as e:
        return {"error": str(e)}
