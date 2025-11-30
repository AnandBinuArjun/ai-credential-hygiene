import os
import subprocess
from backend.collectors.filesystem import detect_secrets_in_file, PATTERNS

def find_git_repos(root_paths: list) -> list:
    """Return paths to .git repos."""
    repos = []
    for root_path in root_paths:
        if not os.path.exists(root_path):
            continue
            
        for root, dirs, files in os.walk(root_path):
            if '.git' in dirs:
                repos.append(root)
                # Don't recurse into a git repo (submodules handled separately usually, or just simple scan)
                dirs.remove('.git') 
                
    return repos

def scan_git_working_tree(repo_path: str) -> list:
    """Search working tree for secrets."""
    findings = []
    try:
        # Get list of tracked files
        result = subprocess.run(
            ['git', 'ls-files'], 
            cwd=repo_path, 
            capture_output=True, 
            text=True, 
            check=True
        )
        files = result.stdout.splitlines()
        
        for file in files:
            full_path = os.path.join(repo_path, file)
            if os.path.exists(full_path):
                file_findings = detect_secrets_in_file(full_path)
                # Tag as git_secret
                for f in file_findings:
                    f['source_type'] = 'git_secret'
                    f['location']['repo'] = repo_path
                findings.extend(file_findings)
                
    except subprocess.CalledProcessError:
        pass
    except Exception as e:
        print(f"Error scanning git repo {repo_path}: {e}")
        
    return findings

def scan_git_history(repo_path: str, max_commits: int = 500) -> list:
    """Search commit history for secrets."""
    findings = []
    try:
        # git log -p -n 500
        # We process the output line by line.
        # This is a simple implementation. A robust one would parse diff headers.
        
        cmd = ['git', 'log', '-p', f'-n {max_commits}']
        process = subprocess.Popen(
            cmd, 
            cwd=repo_path, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            errors='ignore'
        )
        
        current_commit = None
        current_file = None
        
        # We'll read line by line
        # This is memory efficient but we need to track context
        
        for line in process.stdout:
            line = line.rstrip()
            
            if line.startswith('commit '):
                current_commit = line.split(' ')[1]
                continue
            
            if line.startswith('diff --git'):
                # diff --git a/file b/file
                parts = line.split(' ')
                if len(parts) >= 4:
                    current_file = parts[-1].lstrip('b/')
                continue
                
            # Only check added lines
            if line.startswith('+') and not line.startswith('+++'):
                content = line[1:]
                for pattern in PATTERNS:
                    match = pattern["regex"].search(content)
                    if match:
                        full_match = match.group(0)
                        secret_value = match.group(match.lastindex) if match.lastindex else full_match
                        
                        findings.append({
                            "source_type": "git_history",
                            "location": {
                                "repo": repo_path,
                                "commit": current_commit,
                                "path": current_file
                            },
                            "secret_value": secret_value,
                            "username": None,
                            "domain": None,
                            "metadata": {
                                "pattern_name": pattern["name"],
                                "context": content.strip()[:100],
                                "score": pattern["score"]
                            }
                        })
                        
    except Exception as e:
        print(f"Error scanning git history {repo_path}: {e}")
        
    return findings
