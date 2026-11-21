"""
NetSecure SQLite Database Module
Stores sessions, packet details, ping results, and security alerts.
"""

import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from backend.config import DB_PATH, DEFAULT_MACHINE_A_IP, DEFAULT_MACHINE_B_IP

def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        interface TEXT,
        started_at TEXT NOT NULL,
        stopped_at TEXT,
        packet_count INTEGER DEFAULT 0,
        status TEXT DEFAULT 'active',
        pcap_file TEXT,
        source_type TEXT DEFAULT 'live'
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER NOT NULL,
        packet_num INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        src_mac TEXT,
        dst_mac TEXT,
        protocol TEXT NOT NULL,
        length INTEGER NOT NULL,
        info TEXT,
        l4_proto TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        icmp_type INTEGER,
        icmp_code INTEGER,
        icmp_meaning TEXT,
        payload_hex TEXT,
        payload_ascii TEXT,
        details_json TEXT,
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ping_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_ip TEXT NOT NULL,
        source_ip TEXT,
        packets_sent INTEGER,
        packets_received INTEGER,
        packet_loss_pct REAL,
        min_rtt_ms REAL,
        avg_rtt_ms REAL,
        max_rtt_ms REAL,
        jitter_ms REAL,
        status TEXT,
        raw_output TEXT,
        timestamp TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id INTEGER,
        timestamp TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        protocol TEXT,
        evidence TEXT,
        remediation TEXT
    );
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS lab_settings (
        key TEXT PRIMARY KEY,
        value TEXT
    );
    """)

    # Seed default lab settings if not set
    default_settings = {
        "machine_a_ip": DEFAULT_MACHINE_A_IP,
        "machine_a_mac": "Auto-Detect",
        "machine_b_ip": DEFAULT_MACHINE_B_IP,
        "machine_b_mac": "00:0c:29:4d:5e:6f",
        "tshark_custom_path": "",
        "team_info": json.dumps({
            "leader": "Student Lead (Machine A)",
            "member2": "Machine B Operator",
            "member3": "Security Demo Lead",
            "member4": "Report & Analytics Lead"
        })
    }

    for k, v in default_settings.items():
        cursor.execute("INSERT OR IGNORE INTO lab_settings (key, value) VALUES (?, ?)", (k, v))

    conn.commit()
    conn.close()

# Session operations
def create_session(name: str, interface: str, source_type: str = "live", pcap_file: str = "") -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO sessions (name, interface, started_at, packet_count, status, pcap_file, source_type)
        VALUES (?, ?, ?, 0, 'active', ?, ?)
    """, (name, interface, now, pcap_file, source_type))
    session_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return session_id

def stop_session(session_id: int, pcap_file: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    if pcap_file:
        cursor.execute("""
            UPDATE sessions SET status = 'completed', stopped_at = ?, pcap_file = ? WHERE id = ?
        """, (now, pcap_file, session_id))
    else:
        cursor.execute("""
            UPDATE sessions SET status = 'completed', stopped_at = ? WHERE id = ?
        """, (now, session_id))
    conn.commit()
    conn.close()

def get_latest_session() -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_all_sessions() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sessions ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Packet operations
def insert_packet(session_id: int, packet_data: Dict[str, Any]) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    
    details_str = json.dumps(packet_data.get("details", {}))
    
    cursor.execute("""
        INSERT INTO packets (
            session_id, packet_num, timestamp, src_ip, dst_ip, src_mac, dst_mac,
            protocol, length, info, l4_proto, src_port, dst_port,
            icmp_type, icmp_code, icmp_meaning, payload_hex, payload_ascii, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        session_id,
        packet_data.get("packet_num", 0),
        packet_data.get("timestamp", datetime.now().strftime("%H:%M:%S.%f")[:-3]),
        packet_data.get("src_ip", "N/A"),
        packet_data.get("dst_ip", "N/A"),
        packet_data.get("src_mac", "N/A"),
        packet_data.get("dst_mac", "N/A"),
        packet_data.get("protocol", "OTHER"),
        packet_data.get("length", 0),
        packet_data.get("info", ""),
        packet_data.get("l4_proto", ""),
        packet_data.get("src_port"),
        packet_data.get("dst_port"),
        packet_data.get("icmp_type"),
        packet_data.get("icmp_code"),
        packet_data.get("icmp_meaning", ""),
        packet_data.get("payload_hex", ""),
        packet_data.get("payload_ascii", ""),
        details_str
    ))
    
    pkt_id = cursor.lastrowid
    
    # Update packet_count in session
    cursor.execute("UPDATE sessions SET packet_count = packet_count + 1 WHERE id = ?", (session_id,))
    conn.commit()
    conn.close()
    return pkt_id

def insert_packets_bulk(session_id: int, packets: List[Dict[str, Any]]):
    if not packets:
        return
    conn = get_connection()
    cursor = conn.cursor()
    
    rows = []
    for p in packets:
        details_str = json.dumps(p.get("details", {}))
        rows.append((
            session_id,
            p.get("packet_num", 0),
            p.get("timestamp", datetime.now().strftime("%H:%M:%S.%f")[:-3]),
            p.get("src_ip", "N/A"),
            p.get("dst_ip", "N/A"),
            p.get("src_mac", "N/A"),
            p.get("dst_mac", "N/A"),
            p.get("protocol", "OTHER"),
            p.get("length", 0),
            p.get("info", ""),
            p.get("l4_proto", ""),
            p.get("src_port"),
            p.get("dst_port"),
            p.get("icmp_type"),
            p.get("icmp_code"),
            p.get("icmp_meaning", ""),
            p.get("payload_hex", ""),
            p.get("payload_ascii", ""),
            details_str
        ))
    
    cursor.executemany("""
        INSERT INTO packets (
            session_id, packet_num, timestamp, src_ip, dst_ip, src_mac, dst_mac,
            protocol, length, info, l4_proto, src_port, dst_port,
            icmp_type, icmp_code, icmp_meaning, payload_hex, payload_ascii, details_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)
    
    cursor.execute("UPDATE sessions SET packet_count = packet_count + ? WHERE id = ?", (len(packets), session_id))
    conn.commit()
    conn.close()

def get_packets(
    session_id: Optional[int] = None,
    protocol: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 500,
    offset: int = 0
) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM packets WHERE 1=1"
    params = []
    
    if session_id:
        query += " AND session_id = ?"
        params.append(session_id)
        
    if protocol and protocol.upper() != "ALL":
        query += " AND protocol = ?"
        params.append(protocol.upper())
        
    if search:
        search_pattern = f"%{search}%"
        query += " AND (src_ip LIKE ? OR dst_ip LIKE ? OR info LIKE ? OR src_mac LIKE ? OR dst_mac LIKE ?)"
        params.extend([search_pattern, search_pattern, search_pattern, search_pattern, search_pattern])
        
    query += " ORDER BY packet_num ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        d = dict(r)
        if d.get("details_json"):
            try:
                d["details"] = json.loads(d["details_json"])
            except Exception:
                d["details"] = {}
        results.append(d)
    return results

def get_packet_by_id(packet_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM packets WHERE id = ?", (packet_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("details_json"):
        try:
            d["details"] = json.loads(d["details_json"])
        except Exception:
            d["details"] = {}
    return d

def clear_session_packets(session_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM packets WHERE session_id = ?", (session_id,))
    cursor.execute("UPDATE sessions SET packet_count = 0 WHERE id = ?", (session_id,))
    conn.commit()
    conn.close()

# Ping logs operations
def insert_ping_log(log_data: Dict[str, Any]) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO ping_logs (
            target_ip, source_ip, packets_sent, packets_received, packet_loss_pct,
            min_rtt_ms, avg_rtt_ms, max_rtt_ms, jitter_ms, status, raw_output, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        log_data.get("target_ip"),
        log_data.get("source_ip", DEFAULT_MACHINE_A_IP),
        log_data.get("packets_sent", 4),
        log_data.get("packets_received", 0),
        log_data.get("packet_loss_pct", 0.0),
        log_data.get("min_rtt_ms", 0.0),
        log_data.get("avg_rtt_ms", 0.0),
        log_data.get("max_rtt_ms", 0.0),
        log_data.get("jitter_ms", 0.0),
        log_data.get("status", "SUCCESS"),
        log_data.get("raw_output", ""),
        now
    ))
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id

def get_ping_logs(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM ping_logs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Security Alerts
def insert_security_alert(alert_data: Dict[str, Any]) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()
    cursor.execute("""
        INSERT INTO security_alerts (
            session_id, timestamp, alert_type, severity, title, description, protocol, evidence, remediation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        alert_data.get("session_id"),
        now,
        alert_data.get("alert_type", "PLAINTEXT_CREDENTIALS"),
        alert_data.get("severity", "HIGH"),
        alert_data.get("title", ""),
        alert_data.get("description", ""),
        alert_data.get("protocol", "HTTP"),
        alert_data.get("evidence", ""),
        alert_data.get("remediation", "")
    ))
    alert_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return alert_id

def get_security_alerts() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM security_alerts ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Lab Settings
def get_lab_settings() -> Dict[str, str]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT key, value FROM lab_settings")
    rows = cursor.fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}

def update_lab_setting(key: str, value: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO lab_settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()
