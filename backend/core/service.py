from datetime import datetime
from backend.collectors.browsers import run_browser_collectors
from backend.collectors.filesystem import scan_directory
from backend.collectors.git_scanner import find_git_repos, scan_git_working_tree, scan_git_history
from backend.collectors.env_configs import scan_common_config_files
from backend.normalize.findings import normalize_raw_finding
from backend.detect.strength import analyze_strength_raw
from backend.detect.reuse import calculate_reuse
from backend.detect.exposure import detect_exposure
from backend.detect.scoring import compute_risk_score
from backend.ai.classify import classify_secret
from backend.ai.explain import generate_explanation

class ScanService:
    def __init__(self, db, config):
        self.db = db
        self.config = config

    def run_full_scan(self) -> dict:
        """Orchestrates collectors → normalization → detection → AI enrichment."""
        start_time = datetime.now()
        
        # 1. Collect
        raw_findings = self.run_collectors()
        
        # 2. Normalize
        findings = self.normalize_findings(raw_findings)
        
        # 3. Detect (Strength, Exposure, Reuse, Scoring)
        self.run_detection(findings)
        
        # 4. AI Enrichment (Classification, Explanation)
        self.run_ai_enrichment(findings)
        
        # 5. Persist
        for f in findings:
            self.db.insert_finding(f)
            
        # 6. Cloud Sync (Optional)
        if hasattr(self.config, 'cloud_url') and self.config.cloud_url:
            self.sync_to_cloud(findings)
            
        # Log scan
        end_time = datetime.now()
        # self.db.log_scan(...) # TODO: Implement log_scan in DB
        
        return {
            "status": "success",
            "findings_count": len(findings),
            "duration_seconds": (end_time - start_time).total_seconds()
        }

    def sync_to_cloud(self, findings: list):
        """Push encrypted/hashed findings to cloud."""
        import requests
        import platform
        import socket
        
        try:
            # 1. Heartbeat
            agent_id = socket.gethostname() # Simple ID for now
            requests.post(f"{self.config.cloud_url}/api/v1/agents/heartbeat", json={
                "agent_id": agent_id,
                "hostname": socket.gethostname(),
                "os": platform.system()
            }, timeout=5)
            
            # 2. Push Findings
            payload = []
            for f in findings:
                # ONLY send metadata and hash. NEVER send the secret preview to cloud 
                # unless you implement client-side public key encryption here.
                payload.append({
                    "agent_id": agent_id,
                    "secret_hash": f.secret_hash,
                    "risk_score": f.risk_score,
                    "source_type": f.source_type,
                    "metadata": f.metadata
                })
                
            requests.post(f"{self.config.cloud_url}/api/v1/findings/sync", json=payload, timeout=5)
            print(f"Synced {len(payload)} findings to cloud.")
            
        except Exception as e:
            print(f"Cloud sync failed: {e}")

    def run_collectors(self) -> list:
        """Runs all collectors and returns raw findings."""
        raw_findings = []
        
        # Browsers
        if self.config.include_browser_scans:
            try:
                raw_findings.extend(run_browser_collectors())
            except Exception as e:
                print(f"Browser collector failed: {e}")
                
        # Filesystem
        for path in self.config.scan_paths:
            try:
                raw_findings.extend(scan_directory(path))
            except Exception as e:
                print(f"Filesystem collector failed for {path}: {e}")
                
        # Git
        if self.config.include_git_scans:
            try:
                repos = find_git_repos(self.config.scan_paths)
                for repo in repos:
                    raw_findings.extend(scan_git_working_tree(repo))
                    raw_findings.extend(scan_git_history(repo))
            except Exception as e:
                print(f"Git collector failed: {e}")
                
        # Env/Config
        if self.config.include_env_scans:
            try:
                raw_findings.extend(scan_common_config_files())
            except Exception as e:
                print(f"Env collector failed: {e}")
                
        return raw_findings

    def normalize_findings(self, raw_findings: list) -> list:
        """Converts raw collector results into canonical CredentialFinding objects."""
        normalized = []
        for raw in raw_findings:
            try:
                normalized.append(normalize_raw_finding(raw))
            except Exception as e:
                print(f"Normalization failed for finding: {e}")
        return normalized

    def run_detection(self, findings: list) -> list:
        """Runs scoring modules and updates DB with risk scores."""
        # 1. Strength & Exposure (Per finding)
        for f in findings:
            # Strength
            if f._secret_value:
                strength = analyze_strength_raw(f._secret_value)
                f.issue_flags.extend(strength.get("flags", []))
                f.metadata["strength_score"] = strength.get("score")
                f.metadata["entropy"] = strength.get("entropy")
                
            # Exposure
            exposure_flags = detect_exposure(f)
            f.issue_flags.extend(exposure_flags)
            
        # 2. Reuse (Batch)
        # Get existing reuse groups from DB to compare against
        db_reuse = self.db.get_reuse_groups()
        reuse_counts = calculate_reuse(findings, db_reuse)
        
        # 3. Scoring (Per finding)
        for f in findings:
            count = reuse_counts.get(f.secret_hash, 0)
            f.metadata["reuse_count"] = count
            if count > 1:
                f.issue_flags.append("reused_password")
                
            f.risk_score = compute_risk_score(f, count)
            
        return findings

    def run_ai_enrichment(self, findings: list) -> None:
        """Adds AI classification + explanations to high-risk findings."""
        for f in findings:
            # Only enrich high risk or unknown types
            if f.risk_score > 40:
                classification = classify_secret(f.metadata)
                f.ai_type = classification.get("type")
                f.ai_service_guess = classification.get("service_guess")
                
                # Generate explanation
                # f.ai_explanation = generate_explanation(f) # TODO: Implement

