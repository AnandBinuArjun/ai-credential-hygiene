import os
import re
from backend.utils.filetypes import is_text_file

# Common patterns
PATTERNS = [
    {
        "name": "AWS Access Key",
        "regex": re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}"),
        "score": 10
    },
    {
        "name": "Private Key",
        "regex": re.compile(r"-----BEGIN (RSA|DSA|EC|OPENSSH|PRIVATE) KEY-----"),
        "score": 10
    },
    {
        "name": "Generic Secret",
        "regex": re.compile(r"(api_key|apikey|secret|token|password)[\s]*[=:]+[\s]*['\"]?([a-zA-Z0-9\-_]{16,})['\"]?", re.IGNORECASE),
        "score": 5
    },
    {
        "name": "Slack Token",
        "regex": re.compile(r"xox[baprs]-([0-9a-zA-Z]{10,48})"),
        "score": 10
    }
]

MAX_FILE_SIZE = 1024 * 1024 * 5  # 5MB

def scan_directory(path: str) -> list:
    """Walk directory and return candidate secrets from files."""
    findings = []
    
    # Skip common ignore dirs
    ignore_dirs = {'.git', 'node_modules', 'venv', '__pycache__', '.idea', '.vscode', 'dist', 'build'}
    
    for root, dirs, files in os.walk(path):
        # Modify dirs in-place to skip ignored
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        
        for file in files:
            file_path = os.path.join(root, file)
            
            # Skip if too large
            try:
                if os.path.getsize(file_path) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
                
            # Skip if not text (simple check)
            if not is_text_file(file_path):
                continue
                
            file_findings = detect_secrets_in_file(file_path)
            findings.extend(file_findings)
            
    return findings

def detect_secrets_in_file(path: str) -> list:
    """Run regex + heuristics against one file."""
    findings = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        lines = content.splitlines()
        
        for pattern in PATTERNS:
            for match in pattern["regex"].finditer(content):
                # Find line number
                start_index = match.start()
                line_num = content.count('\n', 0, start_index) + 1
                
                # Extract match value
                full_match = match.group(0)
                # If groups exist, take the last one as the secret usually
                secret_value = match.group(match.lastindex) if match.lastindex else full_match
                
                # Context (line content)
                context = lines[line_num - 1] if line_num <= len(lines) else ""
                
                findings.append({
                    "source_type": "file_secret",
                    "location": {
                        "path": path,
                        "line": line_num
                    },
                    "secret_value": secret_value,
                    "username": None,
                    "domain": None,
                    "metadata": {
                        "pattern_name": pattern["name"],
                        "context": context.strip()[:100], # Limit context length
                        "score": pattern["score"]
                    }
                })
                
    except Exception as e:
        # print(f"Error scanning file {path}: {e}")
        pass
        
    return findings
