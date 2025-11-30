import os
import json
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
try:
    import win32crypt
except ImportError:
    win32crypt = None

KEY_FILE = "master.key"

def load_master_key() -> bytes:
    """Load or generate encrypted master key using Windows DPAPI."""
    from backend.utils.paths import get_app_data_dir
    
    app_data = get_app_data_dir()
    key_path = os.path.join(app_data, KEY_FILE)
    
    if os.path.exists(key_path):
        with open(key_path, "rb") as f:
            encrypted_key = f.read()
            if win32crypt:
                try:
                    # DPAPI Decrypt
                    # entropy=None, reserved=None, prompt_struct=None, flags=0
                    _, key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)
                    return key
                except Exception as e:
                    # Fallback or error handling
                    raise RuntimeError(f"Failed to decrypt master key: {e}")
            else:
                # Fallback for non-windows (testing) - just return raw if not using DPAPI
                return encrypted_key
    else:
        # Generate new key
        key = AESGCM.generate_key(bit_length=256)
        
        if win32crypt:
            # DPAPI Encrypt
            # description=None, entropy=None, reserved=None, prompt_struct=None, flags=0
            encrypted_key = win32crypt.CryptProtectData(key, "AI Credential Hygiene Master Key", None, None, None, 0)
        else:
            encrypted_key = key
            
        # Ensure dir exists
        os.makedirs(app_data, exist_ok=True)
        with open(key_path, "wb") as f:
            f.write(encrypted_key)
            
        return key

def encrypt_value(master_key: bytes, plaintext: str) -> bytes:
    """AES-GCM encrypt."""
    if not plaintext:
        return b""
    
    aesgcm = AESGCM(master_key)
    nonce = os.urandom(12)
    data = plaintext.encode('utf-8')
    ciphertext = aesgcm.encrypt(nonce, data, None)
    
    # Return nonce + ciphertext
    return nonce + ciphertext

def decrypt_value(master_key: bytes, ciphertext: bytes) -> str:
    """AES-GCM decrypt."""
    if not ciphertext:
        return ""
        
    try:
        aesgcm = AESGCM(master_key)
        nonce = ciphertext[:12]
        data = ciphertext[12:]
        plaintext = aesgcm.decrypt(nonce, data, None)
        return plaintext.decode('utf-8')
    except Exception:
        return "[DECRYPTION FAILED]"
