import subprocess

def scan_with_clamav(filepath):
    try:
        result = subprocess.run(["clamscan", "--no-summary", filepath], capture_output=True, text=True)
        if "FOUND" in result.stdout:
            return {"status": "MALWARE_DETECTED", "raw_output": result.stdout.strip()}
        return {"status": "CLEAN", "raw_output": "No malware found."}
    except Exception as e:
        return {"status": "ERROR", "raw_output": str(e)}
