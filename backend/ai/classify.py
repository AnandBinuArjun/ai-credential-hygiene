def classify_secret(metadata: dict) -> dict:
    """
    Use heuristics (mocking LLM) to decide credential type:
    - password
    - api_key
    - session_cookie
    - ssh_key
    - db_connection
    - unknown
    """
    pattern_name = metadata.get("pattern_name", "")
    origin = metadata.get("origin", "")
    
    if "AWS" in pattern_name:
        return {"type": "api_key", "service_guess": "AWS"}
    if "Slack" in pattern_name:
        return {"type": "api_key", "service_guess": "Slack"}
    if "Private Key" in pattern_name:
        return {"type": "ssh_key", "service_guess": "SSH"}
        
    if origin:
        if "github.com" in origin:
            return {"type": "password", "service_guess": "GitHub"}
        if "google.com" in origin:
            return {"type": "password", "service_guess": "Google"}
            
    return {"type": "unknown", "service_guess": "Unknown"}
