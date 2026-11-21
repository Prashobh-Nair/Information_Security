"""
NetSecure Statistics Engine
Aggregates network statistics, protocol distributions, bandwidth timelines, and top talkers.
"""

from typing import Dict, Any, List
from collections import Counter, defaultdict

def compute_session_statistics(packets: List[Dict[str, Any]]) -> Dict[str, Any]:
    total_packets = len(packets)
    if total_packets == 0:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "counts": {
                "TCP": 0, "UDP": 0, "ICMP": 0, "HTTP": 0,
                "HTTPS": 0, "DNS": 0, "ARP": 0, "FTP": 0, "OTHER": 0
            },
            "protocol_distribution": [],
            "traffic_timeline": [],
            "top_talkers": [],
            "security_summary": {
                "credential_leaks": 0,
                "unencrypted_http": 0,
                "total_alerts": 0
            }
        }

    counts = Counter()
    total_bytes = 0
    talkers = Counter()
    timeline_buckets = defaultdict(lambda: {"packets": 0, "bytes": 0, "icmp": 0, "http": 0, "https": 0})
    credential_leaks = 0
    unencrypted_http = 0

    for p in packets:
        proto = p.get("protocol", "OTHER").upper()
        pkt_len = p.get("length", 0)
        total_bytes += pkt_len
        counts[proto] += 1
        
        # Track HTTP / HTTPS specific counts
        if proto == "HTTP":
            unencrypted_http += 1
        
        # Check security flags
        details = p.get("details", {})
        if details.get("security", {}).get("has_credentials"):
            credential_leaks += 1

        # Track top IP talkers
        src = p.get("src_ip", "N/A")
        dst = p.get("dst_ip", "N/A")
        if src != "N/A" and dst != "N/A":
            pair = f"{src} ⇄ {dst}"
            talkers[pair] += 1

        # Timeline bucket by timestamp seconds (e.g. "14:25:30")
        ts = p.get("timestamp", "")
        sec_key = ts.split(".")[0] if "." in ts else ts
        if not sec_key:
            sec_key = "00:00:00"
        timeline_buckets[sec_key]["packets"] += 1
        timeline_buckets[sec_key]["bytes"] += pkt_len
        if proto == "ICMP":
            timeline_buckets[sec_key]["icmp"] += 1
        elif proto == "HTTP":
            timeline_buckets[sec_key]["http"] += 1
        elif proto == "HTTPS":
            timeline_buckets[sec_key]["https"] += 1

    # Protocol Distribution for Recharts PieChart
    palette = {
        "ICMP": "#10b981",  # Emerald Green
        "HTTP": "#f59e0b",  # Amber
        "HTTPS": "#06b6d4", # Cyan
        "DNS": "#8b5cf6",   # Purple
        "ARP": "#ec4899",   # Pink
        "FTP": "#ef4444",   # Red
        "TCP": "#3b82f6",   # Blue
        "UDP": "#6366f1",   # Indigo
        "OTHER": "#94a3b8"  # Slate
    }

    distribution = []
    for proto, cnt in counts.most_common():
        pct = round((cnt / total_packets) * 100, 1)
        distribution.append({
            "name": proto,
            "value": cnt,
            "percentage": pct,
            "color": palette.get(proto, "#64748b")
        })

    # Format timeline (sort by timestamp key)
    timeline = []
    sorted_times = sorted(timeline_buckets.keys())
    # Keep up to 50 buckets for clean chart rendering
    for t in sorted_times[-50:]:
        timeline.append({
            "time": t,
            "packets": timeline_buckets[t]["packets"],
            "bytes": timeline_buckets[t]["bytes"],
            "icmp": timeline_buckets[t]["icmp"],
            "http": timeline_buckets[t]["http"],
            "https": timeline_buckets[t]["https"],
        })

    # Top conversations
    top_talkers_list = []
    for pair, count in talkers.most_common(5):
        top_talkers_list.append({
            "conversation": pair,
            "packet_count": count,
            "share_pct": round((count / total_packets) * 100, 1)
        })

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "counts": {
            "TCP": counts.get("TCP", 0),
            "UDP": counts.get("UDP", 0),
            "ICMP": counts.get("ICMP", 0),
            "HTTP": counts.get("HTTP", 0),
            "HTTPS": counts.get("HTTPS", 0),
            "DNS": counts.get("DNS", 0),
            "ARP": counts.get("ARP", 0),
            "FTP": counts.get("FTP", 0),
            "OTHER": counts.get("OTHER", 0),
        },
        "protocol_distribution": distribution,
        "traffic_timeline": timeline,
        "top_talkers": top_talkers_list,
        "security_summary": {
            "credential_leaks": credential_leaks,
            "unencrypted_http": unencrypted_http,
            "total_alerts": credential_leaks + (1 if unencrypted_http > 0 else 0)
        }
    }
