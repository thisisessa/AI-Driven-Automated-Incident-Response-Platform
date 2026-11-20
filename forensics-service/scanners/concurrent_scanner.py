import concurrent.futures
from scanners.yara_scanner import scan_with_yara
from scanners.clamav_scanner import scan_with_clamav
import logging

logger = logging.getLogger("SOAR-Forensics")

def run_all_scanners(filepath):
    """Runs YARA and ClamAV concurrently to save time"""
    results = {"yara": [], "clamav": {}}
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_yara = executor.submit(scan_with_yara, filepath)
        future_clamav = executor.submit(scan_with_clamav, filepath)
        
        try:
            results["yara"] = future_yara.result(timeout=30)
            results["clamav"] = future_clamav.result(timeout=30)
        except Exception as e:
            logger.error(f"[SCANNER ERROR] Timeout or failure: {e}")
            
    return results
