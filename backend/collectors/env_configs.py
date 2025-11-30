import os
from backend.collectors.filesystem import detect_secrets_in_file

def scan_common_config_files() -> list:
    """Detect secrets in ~/.aws, ~/.kube, gcloud configs, etc."""
    findings = []
    home = os.path.expanduser("~")
    
    paths_to_check = [
        os.path.join(home, ".aws", "credentials"),
        os.path.join(home, ".kube", "config"),
        os.path.join(home, ".azure", "accessTokens.json"),
        os.path.join(home, ".config", "gcloud", "credentials.db"), # Might be binary
    ]
    
    for path in paths_to_check:
        if os.path.exists(path) and os.path.isfile(path):
            # Reuse filesystem detector
            # Note: Some of these might need specialized parsers, but regex is a good start
            file_findings = detect_secrets_in_file(path)
            for f in file_findings:
                f['source_type'] = 'env_config'
            findings.extend(file_findings)
            
    return findings
