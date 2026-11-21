"""
NetSecure CSV Exporter
Exports packet captures and statistics to CSV for external data analysis (Excel, Pandas).
"""

import csv
from datetime import datetime
from pathlib import Path
from backend.config import REPORTS_DIR
from backend.database import get_packets

def export_packets_to_csv(session_id: int = None, filename: str = "") -> str:
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"NetSecure_Packets_{timestamp}.csv"

    csv_path = REPORTS_DIR / filename
    packets = get_packets(session_id=session_id, limit=5000)

    fieldnames = [
        "packet_num", "timestamp", "src_ip", "dst_ip", "src_mac", "dst_mac",
        "protocol", "length", "info", "l4_proto", "src_port", "dst_port",
        "icmp_type", "icmp_code", "icmp_meaning"
    ]

    with open(csv_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for p in packets:
            writer.writerow(p)

    return str(csv_path)
