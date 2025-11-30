import os
from fastapi import FastAPI
from backend.storage.db import Database
from backend.core.config import Config
from backend.core.service import ScanService
from backend.api.routes_scan import register_scan_routes
from backend.utils.paths import get_app_data_dir

app = FastAPI()

# Dependency Injection / Global State
# In a real app, use Depends()
db_path = os.path.join(get_app_data_dir(), "credentials.db")
db = Database(db_path)
config = Config.load()
service = ScanService(db, config)

# Register Routes
register_scan_routes(app, service)

@app.on_event("startup")
def startup_event():
    db.init()

@app.get("/status")
def status():
    return {"ok": True, "db": db_path}

@app.get("/findings")
def list_findings():
    """Return current findings."""
    return db.get_all_findings()
