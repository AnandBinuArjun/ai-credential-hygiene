import uvicorn
import os
import sys

if __name__ == "__main__":
    # Add project root to path
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    
    print("Starting AI Credential Hygiene Assistant Backend...")
    uvicorn.run("backend.api.server:app", host="127.0.0.1", port=8000, reload=True)
