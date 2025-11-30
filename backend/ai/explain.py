def generate_explanation(finding) -> str:
    """Generate user-friendly explanation and remediation steps."""
    # Mock implementation
    risk = finding.risk_score
    flags = ", ".join(finding.issue_flags)
    
    if risk > 80:
        return f"CRITICAL: This credential has a risk score of {risk}. Issues: {flags}. Rotate immediately."
    elif risk > 40:
        return f"HIGH: Risk score {risk}. Issues: {flags}. Consider rotating."
        
    return f"INFO: Risk score {risk}. Issues: {flags}."
