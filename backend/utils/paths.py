# Utils for path handling
import os

def get_app_data_dir() -> str:
    """Get the application data directory."""
    # Windows specific
    local_app_data = os.environ.get('LOCALAPPDATA')
    if not local_app_data:
        local_app_data = os.path.expanduser("~\\AppData\\Local")
    
    path = os.path.join(local_app_data, "AI Credential Hygiene Assistant")
    if not os.path.exists(path):
        os.makedirs(path)
    return path
