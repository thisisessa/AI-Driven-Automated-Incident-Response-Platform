import hashlib
import os
import zipfile
from cryptography.fernet import Fernet
from core.database import SessionLocal, ChainOfCustody

# Encryption Key (In production, use Vault/KMS)
SECRET_KEY = Fernet.generate_key()
cipher = Fernet(SECRET_KEY)

def calculate_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    return sha256.hexdigest()

def secure_evidence(case_id, filepath, evidence_name):
    """Zips and Encrypts evidence for Chain of Custody"""
    # 1. Hash original file
    original_hash = calculate_sha256(filepath)
    
    # 2. Zip the file
    zip_path = f"{filepath}.zip"
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(filepath, os.path.basename(filepath))
        
    # 3. Encrypt the zip file
    with open(zip_path, 'rb') as f:
        encrypted_data = cipher.encrypt(f.read())
        
    encrypted_path = f"{zip_path}.enc"
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)
        
    # 4. Log to Database
    db = SessionLocal()
    log = ChainOfCustody(
        case_id=case_id, evidence_name=evidence_name, 
        sha256_hash=original_hash, action="Encrypted & Vaulted", integrity_status="VALID"
    )
    db.add(log)
    db.commit()
    db.close()
    
    return original_hash, encrypted_path
