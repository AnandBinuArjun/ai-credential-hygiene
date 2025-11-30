def calculate_reuse(findings: list, db_reuse_groups: dict) -> dict:
    """
    Return mapping: secret_hash -> reuse_count.
    findings: list of current scan findings (CredentialFinding objects)
    db_reuse_groups: dict from DB.get_reuse_groups()
    """
    reuse_counts = {}
    
    # Count in current batch
    local_counts = {}
    for f in findings:
        h = f.secret_hash
        local_counts[h] = local_counts.get(h, 0) + 1
        
    # Merge with DB stats
    for h, count in local_counts.items():
        db_count = len(db_reuse_groups.get(h, []))
        # Total reuse is (db_count + current_scan_count) - overlap?
        # Actually, simpler: just track if hash appears multiple times.
        # If we are running a full scan, local_counts is the truth for the current state.
        # If we are doing incremental, it's harder.
        # Let's assume full scan for v1.
        
        total = count
        # If we have historical data that isn't in this scan (e.g. other machines?), we might add it.
        # For local app, let's just use local_counts as the primary source for "current reuse".
        
        reuse_counts[h] = total
        
    return reuse_counts
