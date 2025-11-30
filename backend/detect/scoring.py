def compute_risk_score(finding, reuse_count: int = 0) -> int:
    """Assign score 0–100 based on weakness, reuse, exposure, domain importance."""
    score = 0
    
    # 1. Domain Importance (Heuristic)
    domain = finding.domain or ""
    if any(x in domain for x in ['google', 'facebook', 'twitter', 'github', 'aws', 'azure', 'bank', 'chase', 'paypal']):
        score += 40
    elif domain:
        score += 10
        
    # 2. Weakness (Flags from strength analysis)
    if "weak_password" in finding.issue_flags:
        score += 20
    if "short_password" in finding.issue_flags:
        score += 10
        
    # 3. Reuse
    if reuse_count > 1:
        score += 15
    if reuse_count >= 5:
        score += 15 # Cumulative
        
    # 4. Exposure
    if "exposed_in_git_history" in finding.issue_flags:
        score += 20
    if "committed_to_git" in finding.issue_flags:
        score += 30
    if "plaintext_file" in finding.issue_flags:
        score += 15
    if "insecure_location" in finding.issue_flags:
        score += 10
        
    return max(0, min(score, 100))
