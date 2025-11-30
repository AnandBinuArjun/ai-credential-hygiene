import json
import os
from backend.utils.paths import get_app_data_dir

CONFIG_FILE = "config.json"

class Config:
    def __init__(self):
        self.scan_paths = [
            os.path.expanduser("~/Desktop"),
            os.path.expanduser("~/Documents"),
            os.path.expanduser("~/Downloads"),
        ]
        self.include_browser_scans = True
        self.include_git_scans = True
        self.include_env_scans = True
        self.cloud_url = "" # e.g. "http://localhost:8080"

    @staticmethod
    def load() -> "Config":
        """Load config from disk."""
        app_data = get_app_data_dir()
        config_path = os.path.join(app_data, CONFIG_FILE)
        
        cfg = Config()
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    data = json.load(f)
                    cfg.scan_paths = data.get("scan_paths", cfg.scan_paths)
                    cfg.include_browser_scans = data.get("include_browser_scans", True)
                    cfg.include_git_scans = data.get("include_git_scans", True)
                    cfg.include_env_scans = data.get("include_env_scans", True)
            except Exception:
                pass # Fallback to default
        return cfg

    def save(self):
        """Persist config to disk."""
        app_data = get_app_data_dir()
        config_path = os.path.join(app_data, CONFIG_FILE)
        
        data = {
            "scan_paths": self.scan_paths,
            "include_browser_scans": self.include_browser_scans,
            "include_git_scans": self.include_git_scans,
            "include_env_scans": self.include_env_scans
        }
        
        with open(config_path, 'w') as f:
            json.dump(data, f, indent=2)
