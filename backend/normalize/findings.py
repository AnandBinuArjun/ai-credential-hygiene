import hashlib
import json

class CredentialFinding:
    def __init__(self, source_type, location, secret_hash, preview, username, domain, metadata, secret_value=None):
        self.source_type = source_type
        self.location = location
        self.secret_hash = secret_hash
        self.preview = preview
        self.username = username
        self.domain = domain
        self.metadata = metadata
        self.issue_flags = []
        self.risk_score = 0
        # Transient field, do not persist to DB
        self._secret_value = secret_value

def normalize_raw_finding(raw: dict) -> CredentialFinding:
    """Convert raw collector output into normalized CredentialFinding."""
    secret_value = raw.get("secret_value", "")
    username = raw.get("username")
    domain = raw.get("domain")
    
    # Compute Hash
    secret_hash = hashlib.sha256(secret_value.encode('utf-8')).hexdigest()
    
    # Create Preview (Masked)
    if len(secret_value) <= 4:
        preview = "*" * len(secret_value)
    else:
        preview = secret_value[:2] + "*" * (len(secret_value) - 4) + secret_value[-2:]
        
    # Normalize domain if possible (simple strip for now)
    if domain:
        domain = domain.lower().strip()
        
    return CredentialFinding(
        source_type=raw["source_type"],
        location=raw["location"],
        secret_hash=secret_hash,
        preview=preview,
        username=username,
        domain=domain,
        metadata=raw.get("metadata", {}),
        secret_value=secret_value
    )
