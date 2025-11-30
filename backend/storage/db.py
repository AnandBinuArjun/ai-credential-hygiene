import sqlite3
import json
import os
from backend.security.crypto import encrypt_value, decrypt_value, load_master_key

class Database:
    def __init__(self, path):
        self.path = path
        self.conn = None
        self.master_key = None

    def init(self):
        """Initialize encrypted SQLite schema."""
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.master_key = load_master_key()
        
        cursor = self.conn.cursor()
        
        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_type TEXT NOT NULL,
                location_json TEXT NOT NULL,
                secret_hash TEXT NOT NULL,
                secret_preview_enc BLOB,
                username_enc BLOB,
                domain TEXT,
                metadata_json TEXT,
                issue_flags_json TEXT,
                risk_score INTEGER DEFAULT 0,
                ai_type TEXT,
                ai_service_guess TEXT,
                ai_explanation_enc BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Scans table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                finished_at TIMESTAMP,
                status TEXT,
                num_findings INTEGER DEFAULT 0
            )
        """)
        
        # Settings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        
        self.conn.commit()

    def insert_finding(self, finding):
        """Insert or update a finding."""
        if not self.conn:
            self.init()
            
        # Encrypt sensitive fields
        preview_enc = encrypt_value(self.master_key, finding.preview)
        username_enc = encrypt_value(self.master_key, finding.username) if finding.username else None
        
        # Check if hash exists to update or insert
        cursor = self.conn.cursor()
        cursor.execute("SELECT id FROM findings WHERE secret_hash = ?", (finding.secret_hash,))
        existing = cursor.fetchone()
        
        if existing:
            cursor.execute("""
                UPDATE findings SET
                    source_type = ?,
                    location_json = ?,
                    secret_preview_enc = ?,
                    username_enc = ?,
                    domain = ?,
                    metadata_json = ?,
                    issue_flags_json = ?,
                    risk_score = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (
                finding.source_type,
                json.dumps(finding.location),
                preview_enc,
                username_enc,
                finding.domain,
                json.dumps(finding.metadata),
                json.dumps(finding.issue_flags),
                finding.risk_score,
                existing['id']
            ))
        else:
            cursor.execute("""
                INSERT INTO findings (
                    source_type, location_json, secret_hash, secret_preview_enc, 
                    username_enc, domain, metadata_json, issue_flags_json, risk_score
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.source_type,
                json.dumps(finding.location),
                finding.secret_hash,
                preview_enc,
                username_enc,
                finding.domain,
                json.dumps(finding.metadata),
                json.dumps(finding.issue_flags),
                finding.risk_score
            ))
            
        self.conn.commit()

    def get_all_findings(self) -> list:
        """Retrieve all findings from storage."""
        if not self.conn:
            self.init()
            
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM findings ORDER BY risk_score DESC")
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            # Decrypt for display/processing
            # Note: In a real app, we might only decrypt on demand
            preview = decrypt_value(self.master_key, row['secret_preview_enc'])
            username = decrypt_value(self.master_key, row['username_enc']) if row['username_enc'] else None
            explanation = decrypt_value(self.master_key, row['ai_explanation_enc']) if row['ai_explanation_enc'] else None
            
            results.append({
                "id": row['id'],
                "source_type": row['source_type'],
                "location": json.loads(row['location_json']),
                "secret_hash": row['secret_hash'],
                "preview": preview,
                "username": username,
                "domain": row['domain'],
                "metadata": json.loads(row['metadata_json']),
                "issue_flags": json.loads(row['issue_flags_json']) if row['issue_flags_json'] else [],
                "risk_score": row['risk_score'],
                "ai_type": row['ai_type'],
                "ai_service_guess": row['ai_service_guess'],
                "ai_explanation": explanation,
                "created_at": row['created_at']
            })
            
        return results

    def get_reuse_groups(self) -> dict:
        """Return mapping secret_hash -> list of findings."""
        if not self.conn:
            self.init()
            
        cursor = self.conn.cursor()
        cursor.execute("SELECT secret_hash, id FROM findings")
        rows = cursor.fetchall()
        
        groups = {}
        for row in rows:
            h = row['secret_hash']
            if h not in groups:
                groups[h] = []
            groups[h].append(row['id'])
            
        # Filter for reuse > 1
        return {k: v for k, v in groups.items() if len(v) > 1}
