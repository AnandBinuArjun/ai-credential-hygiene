def sanitize_for_storage(value: str) -> str:
    """Mask sensitive fields before encryption."""
    if not value:
        return ""
    if len(value) <= 4:
        return "*" * len(value)
    
    # Keep first 2 and last 2
    return value[:2] + "*" * (len(value) - 4) + value[-2:]
