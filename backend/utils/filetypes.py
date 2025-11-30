# Utils for file type detection

def is_text_file(path: str) -> bool:
    """Check if file is text."""
    # Check extension
    text_extensions = {
        '.txt', '.md', '.json', '.yaml', '.yml', '.env', '.ini', '.cfg', '.conf', 
        '.py', '.js', '.ts', '.tsx', '.jsx', '.sh', '.ps1', '.html', '.css', '.xml',
        '.java', '.c', '.cpp', '.h', '.go', '.rs', '.php', '.rb'
    }
    ext = os.path.splitext(path)[1].lower()
    if ext in text_extensions:
        return True
        
    # Check content for null bytes
    try:
        with open(path, 'rb') as f:
            chunk = f.read(1024)
            if b'\0' in chunk:
                return False
    except OSError:
        return False
        
    return True
