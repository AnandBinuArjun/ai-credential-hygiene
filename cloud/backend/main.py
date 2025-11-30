from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

app = FastAPI(title="Credential Hygiene Cloud API")

# --- Models ---
class FindingCreate(BaseModel):
    agent_id: str
    secret_hash: str
    risk_score: int
    source_type: str
    metadata: dict

class AgentHeartbeat(BaseModel):
    agent_id: str
    hostname: str
    os: str

# --- In-Memory Store (Replace with Postgres) ---
findings_db = []
agents_db = {}

@app.get("/")
def health():
    return {"status": "online", "version": "1.0.0"}

@app.post("/api/v1/agents/heartbeat")
def heartbeat(data: AgentHeartbeat):
    """Register or update an agent."""
    agents_db[data.agent_id] = {
        "last_seen": datetime.now(),
        "hostname": data.hostname,
        "os": data.os
    }
    return {"status": "ok"}

@app.post("/api/v1/findings/sync")
def sync_findings(findings: List[FindingCreate]):
    """Receive encrypted findings from agents."""
    # In a real app, verify JWT token here
    count = 0
    for f in findings:
        findings_db.append(f.dict())
        count += 1
    return {"synced": count}

@app.get("/api/v1/dashboard/summary")
def get_dashboard_summary():
    """Data for Mobile/Web Dashboard."""
    total_risks = sum(1 for f in findings_db if f['risk_score'] > 50)
    return {
        "active_agents": len(agents_db),
        "total_findings": len(findings_db),
        "critical_risks": total_risks,
        "recent_activity": list(agents_db.values())
    }
