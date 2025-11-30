def detect_exposure(finding) -> list:
    """Check if secret is in git history, plain text, insecure dirs, etc."""
    flags = []
    
    # Check source type
    if finding.source_type == 'git_history':
        flags.append("exposed_in_git_history")
    elif finding.source_type == 'git_secret':
        flags.append("committed_to_git")
    elif finding.source_type == 'file_secret':
        flags.append("plaintext_file")
        
    # Check location
    if finding.location:
        path = ""
        if isinstance(finding.location, dict):
            path = finding.location.get('path', '')
        elif isinstance(finding.location, str):
            path = finding.location
            
        path = str(path).lower()
        if 'desktop' in path or 'downloads' in path:
            flags.append("insecure_location")
            
    return flags
