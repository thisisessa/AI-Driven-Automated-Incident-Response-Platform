import hashlib
import os
from core.database import SessionLocal, ChainOfCustody

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def acquire_and_analyze_memory(case_id):
    # 1. Acquire RAM (Enterprise Dump Simulation)
    dump_name = f"mem_dump_{case_id}.raw"
    dump_path = f"/app/evidence_vault/memory_dumps/{dump_name}"
    os.makedirs(os.path.dirname(dump_path), exist_ok=True)
    
    with open(dump_path, "wb") as f:
        f.write(b"MEM_DUMP_ENTERPRISE_" + case_id.encode() + b"_MIMIKATZ_POWERSHELL")
        
    # 2. Log to DB
    file_hash = calculate_sha256(dump_path)
    db = SessionLocal()
    log = ChainOfCustody(case_id=case_id, evidence_name=dump_name, sha256_hash=file_hash, action="Memory Acquired")
    db.add(log)
    db.commit()
    db.close()
    
    # 3. Volatility Analysis (Simulated)
    volatility_results = {
        "malfind": ["PID 4912: powershell.exe (RWX Memory - Injected)", "PID 9921: svchost.exe (Suspicious DLL)"],
        "netscan": ["ESTABLISHED 192.168.1.50:4444 -> 185.143.180.249:443 (C2 Beacon)"]
    }
    return dump_path, dump_name, volatility_results
