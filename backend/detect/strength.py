from zxcvbn import zxcvbn

def analyze_strength(finding) -> dict:
    """Return flags about password strength, entropy, and weak patterns."""
    secret = finding.preview # We only have preview in finding object usually, BUT 
    # Wait, the finding object has 'secret_hash' and 'preview'. 
    # The raw secret is NOT in the normalized finding object to protect memory.
    # However, for strength analysis, we need the secret.
    # The architecture says "Collectors run raw extraction... Normalization... Detection".
    # If we want to analyze strength, we should probably do it BEFORE throwing away the secret 
    # OR we pass the raw secret to this function during the pipeline before it's discarded.
    
    # Let's assume the 'finding' passed here is the Normalized object, which DOES NOT have the secret.
    # This is a design constraint. 
    # Solution: The 'run_detection' method in Service likely iterates over (finding, raw_secret) tuples 
    # or we compute strength metadata during normalization/collection and store it in metadata.
    
    # Let's adjust the plan: We will compute strength flags in the Service layer while we still have the raw secret,
    # OR we assume 'finding' here is a temporary object that might still have the secret attached if we modify the class.
    
    # For now, I will implement this function assuming it receives the RAW secret string, 
    # and the Service layer calls it before finalizing the Finding object.
    pass

def analyze_strength_raw(secret_value: str) -> dict:
    """Return flags about password strength."""
    if not secret_value:
        return {}
        
    results = zxcvbn(secret_value)
    score = results.get('score', 0)
    
    flags = []
    if score <= 1:
        flags.append("weak_password")
    if len(secret_value) < 8:
        flags.append("short_password")
        
    return {
        "score": score,
        "entropy": results.get('guesses_log10', 0),
        "flags": flags
    }
