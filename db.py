import sqlite3
import os
import json
from datetime import datetime, timedelta
from typing import List, Dict, Any

DATA_DIR = os.getenv("DATA_DIR", os.path.dirname(__file__))
DB_PATH = os.path.join(DATA_DIR, 'vuln_alerts.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # Dedup table: permanent index of seen vulnerabilities
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS dedup (
            source TEXT,
            cve_id TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (source, cve_id)
        )
    ''')
    # Findings table: full record, pruned after retention days
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            source TEXT,
            cve_id TEXT,
            severity TEXT,
            description TEXT,
            url TEXT,
            published TEXT,
            affected_version TEXT,
            fixed_version TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (source, cve_id)
        )
    ''')
    # Source Meta table: tracking baseline, failures
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS source_meta (
            source TEXT PRIMARY KEY,
            baseline_done BOOLEAN DEFAULT 0,
            consecutive_failures INTEGER DEFAULT 0,
            last_attempt TIMESTAMP,
            last_error TEXT,
            ok BOOLEAN
        )
    ''')
    conn.commit()
    conn.close()

def is_baseline_done(source: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT baseline_done FROM source_meta WHERE source = ?', (source,))
    row = cursor.fetchone()
    conn.close()
    return row is not None and row[0] == 1

def mark_baseline(source: str, findings: List[Dict[str, Any]]):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Ensure source exists in meta
    cursor.execute('''
        INSERT INTO source_meta (source, baseline_done, consecutive_failures, ok, last_attempt) 
        VALUES (?, 1, 0, 1, CURRENT_TIMESTAMP)
        ON CONFLICT(source) DO UPDATE SET baseline_done = 1, ok = 1, consecutive_failures = 0, last_attempt = CURRENT_TIMESTAMP
    ''', (source,))

    for f in findings:
        cursor.execute('INSERT OR IGNORE INTO dedup (source, cve_id) VALUES (?, ?)', (source, f['cve_id']))
        cursor.execute('''
            INSERT OR REPLACE INTO findings 
            (source, cve_id, severity, description, url, published, affected_version, fixed_version) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            source, f['cve_id'], f['severity'], f['description'], f['url'], 
            f['published'], f['affected_version'], f['fixed_version']
        ))
    
    conn.commit()
    conn.close()

def is_new_finding(source: str, cve_id: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM dedup WHERE source = ? AND cve_id = ?', (source, cve_id))
    row = cursor.fetchone()
    conn.close()
    return row is None

def record_finding(f: Dict[str, Any]):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    source = f['source']
    cursor.execute('INSERT OR IGNORE INTO dedup (source, cve_id) VALUES (?, ?)', (source, f['cve_id']))
    cursor.execute('''
        INSERT OR REPLACE INTO findings 
        (source, cve_id, severity, description, url, published, affected_version, fixed_version) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        source, f['cve_id'], f['severity'], f['description'], f['url'], 
        f['published'], f['affected_version'], f['fixed_version']
    ))
    conn.commit()
    conn.close()

def record_source_status(source: str, ok: bool, error_msg: str = ""):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT consecutive_failures FROM source_meta WHERE source = ?', (source,))
    row = cursor.fetchone()
    failures = 0
    if row:
        failures = row[0]
    
    if ok:
        failures = 0
        error_msg = ""
    else:
        failures += 1
        
    cursor.execute('''
        INSERT INTO source_meta (source, consecutive_failures, ok, last_error, last_attempt) 
        VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(source) DO UPDATE SET 
            consecutive_failures = ?, 
            ok = ?, 
            last_error = ?, 
            last_attempt = CURRENT_TIMESTAMP
    ''', (source, failures, ok, error_msg, failures, ok, error_msg))
    
    conn.commit()
    conn.close()

def get_source_failures(source: str) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT consecutive_failures FROM source_meta WHERE source = ?', (source,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else 0

def prune_findings(retention_days: int) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cutoff_date = (datetime.utcnow() - timedelta(days=retention_days)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('DELETE FROM findings WHERE first_seen < ?', (cutoff_date,))
    deleted = cursor.rowcount
    conn.commit()
    conn.close()
    return deleted

def get_findings_since(days: int) -> List[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cutoff_date = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    cursor.execute('''
        SELECT source, cve_id, severity, description, url, published, affected_version, fixed_version, first_seen 
        FROM findings WHERE first_seen >= ?
    ''', (cutoff_date,))
    rows = cursor.fetchall()
    conn.close()
    
    findings = []
    for r in rows:
        findings.append({
            'source': r[0], 'cve_id': r[1], 'severity': r[2], 'description': r[3],
            'url': r[4], 'published': r[5], 'affected_version': r[6], 'fixed_version': r[7],
            'first_seen': r[8]
        })
    return findings
