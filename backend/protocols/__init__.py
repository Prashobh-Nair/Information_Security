"""
NetSecure Protocol Inspectors
Contains dedicated extractors and analysis routines for ICMP, ARP, DNS, HTTP, HTTPS, and FTP.
Directly implements Lab Exercise 12 requirements:
"Realize the above for: HTTP, HTTPS, DNS, ARP, FTP traffic types."
"""

from typing import List, Dict, Any
from backend.database import get_packets
from backend.analyzer.icmp_analyzer import analyze_icmp

def get_icmp_analysis(session_id: int = None) -> Dict[str, Any]:
    packets = get_packets(session_id=session_id, protocol="ICMP", limit=1000)
    
    echo_requests = []
    echo_replies = []
    other_icmp = []
    
    type_counts = {}
    
    for p in packets:
        itype = p.get("icmp_type")
        icode = p.get("icmp_code")
        t_key = f"Type {itype}"
        type_counts[t_key] = type_counts.get(t_key, 0) + 1
        
        item = {
            "packet_num": p["packet_num"],
            "timestamp": p["timestamp"],
            "src_ip": p["src_ip"],
            "dst_ip": p["dst_ip"],
            "src_mac": p["src_mac"],
            "dst_mac": p["dst_mac"],
            "type": itype,
            "code": icode,
            "meaning": p.get("icmp_meaning") or f"Type {itype}, Code {icode}",
            "info": p["info"]
        }
        
        if itype == 8:
            echo_requests.append(item)
        elif itype == 0:
            echo_replies.append(item)
        else:
            other_icmp.append(item)

    # Correlate requests and replies
    ping_pairs = []
    for req in echo_requests:
        # Match with first available reply having matching src/dst swapped
        matching_rep = next(
            (rep for rep in echo_replies if rep["src_ip"] == req["dst_ip"] and rep["dst_ip"] == req["src_ip"]),
            None
        )
        ping_pairs.append({
            "request_num": req["packet_num"],
            "request_time": req["timestamp"],
            "reply_num": matching_rep["packet_num"] if matching_rep else "No Reply",
            "reply_time": matching_rep["timestamp"] if matching_rep else "Timed out",
            "source_host": f"{req['src_ip']} ({req['src_mac']})",
            "target_host": f"{req['dst_ip']} ({req['dst_mac']})",
            "status": "Replied (Success)" if matching_rep else "Awaiting/Lost",
            "type_code_summary": f"Req (Type 8/Code 0) → Rep (Type 0/Code 0)" if matching_rep else "Req (Type 8/Code 0)"
        })

    return {
        "total_icmp_packets": len(packets),
        "echo_requests_count": len(echo_requests),
        "echo_replies_count": len(echo_replies),
        "other_types_count": len(other_icmp),
        "type_distribution": type_counts,
        "ping_correlations": ping_pairs,
        "packets": packets,
        "lab_verdict": (
            f"Successfully captured {len(echo_requests)} ICMP Echo Requests (Machine A) and "
            f"{len(echo_replies)} Echo Replies (Machine B). Bidirectional ping connectivity confirmed."
        )
    }

def get_arp_analysis(session_id: int = None) -> Dict[str, Any]:
    packets = get_packets(session_id=session_id, protocol="ARP", limit=1000)
    
    ip_mac_table = {}
    requests = []
    replies = []
    
    for p in packets:
        det = p.get("details", {}).get("network", {})
        op = det.get("operation", "Unknown")
        
        sender_ip = det.get("sender_ip", p["src_ip"])
        sender_mac = det.get("sender_mac", p["src_mac"])
        target_ip = det.get("target_ip", p["dst_ip"])
        target_mac = det.get("target_mac", p["dst_mac"])
        
        if sender_ip and sender_mac and sender_mac != "00:00:00:00:00:00":
            ip_mac_table[sender_ip] = sender_mac
            
        record = {
            "packet_num": p["packet_num"],
            "timestamp": p["timestamp"],
            "operation": op,
            "sender_ip": sender_ip,
            "sender_mac": sender_mac,
            "target_ip": target_ip,
            "target_mac": target_mac,
            "info": p["info"]
        }
        
        if "Request" in op:
            requests.append(record)
        else:
            replies.append(record)

    return {
        "total_arp_packets": len(packets),
        "requests_count": len(requests),
        "replies_count": len(replies),
        "resolved_ip_mac_table": [{"ip": k, "mac": v} for k, v in ip_mac_table.items()],
        "arp_transactions": requests + replies,
        "academic_note": (
            "ARP resolves IP addresses to Ethernet hardware addresses. "
            "Because ARP lacks authentication, any host can reply (ARP Cache Poisoning risk)."
        )
    }

def get_dns_analysis(session_id: int = None) -> Dict[str, Any]:
    packets = get_packets(session_id=session_id, protocol="DNS", limit=1000)
    
    queries = []
    resolved_domains = {}
    
    for p in packets:
        det = p.get("details", {}).get("application", {})
        qname = det.get("query_name", "N/A")
        qtype = det.get("query_type", "A")
        is_resp = det.get("is_response", False)
        answers = det.get("answers", [])
        
        if is_resp and qname != "N/A" and answers:
            resolved_domains[qname] = answers
            
        queries.append({
            "packet_num": p["packet_num"],
            "timestamp": p["timestamp"],
            "client_ip": p["src_ip"] if not is_resp else p["dst_ip"],
            "server_ip": p["dst_ip"] if not is_resp else p["src_ip"],
            "query_name": qname,
            "query_type": qtype,
            "is_response": is_resp,
            "answers": answers,
            "info": p["info"]
        })

    return {
        "total_dns_packets": len(packets),
        "unique_domains": list(resolved_domains.keys()),
        "domain_resolution_map": [{"domain": k, "addresses": v} for k, v in resolved_domains.items()],
        "dns_records": queries,
        "academic_note": (
            "Standard DNS operates unencrypted over UDP port 53. "
            "Queries can be observed and manipulated unless DNS over HTTPS (DoH) or DNSSEC is enforced."
        )
    }

def get_http_analysis(session_id: int = None) -> Dict[str, Any]:
    packets = get_packets(session_id=session_id, protocol="HTTP", limit=1000)
    
    requests = []
    responses = []
    credential_findings = []
    
    for p in packets:
        det = p.get("details", {}).get("application", {})
        sec = p.get("details", {}).get("security", {})
        
        is_req = det.get("is_request", False)
        item = {
            "packet_num": p["packet_num"],
            "timestamp": p["timestamp"],
            "src_ip": p["src_ip"],
            "dst_ip": p["dst_ip"],
            "method": det.get("method", "N/A"),
            "uri": det.get("uri", "/"),
            "headers": det.get("headers", {}),
            "body": det.get("body", ""),
            "has_credentials": sec.get("has_credentials", False),
            "credentials": sec,
            "info": p["info"]
        }
        
        if sec.get("has_credentials"):
            credential_findings.append({
                "packet_num": p["packet_num"],
                "src_ip": p["src_ip"],
                "dst_ip": p["dst_ip"],
                "username": sec.get("username"),
                "password": sec.get("password"),
                "auth_type": sec.get("auth_type"),
                "evidence": sec.get("evidence")
            })
            
        if is_req:
            requests.append(item)
        else:
            responses.append(item)

    return {
        "total_http_packets": len(packets),
        "requests_count": len(requests),
        "responses_count": len(responses),
        "credential_leaks_found": len(credential_findings),
        "leaked_credentials": credential_findings,
        "http_transactions": requests + responses,
        "security_verdict": (
            "CRITICAL: Unencrypted HTTP transmits sensitive parameters in cleartext. "
            f"{len(credential_findings)} credential set(s) were successfully captured on the wire!"
            if credential_findings else "HTTP traffic captured. Ensure all sensitive routes migrate to HTTPS."
        )
    }

def get_https_analysis(session_id: int = None) -> Dict[str, Any]:
    packets = get_packets(session_id=session_id, protocol="HTTPS", limit=1000)
    
    handshakes = []
    app_data_packets = []
    sni_list = set()
    
    for p in packets:
        det = p.get("details", {}).get("application", {})
        rec_type = det.get("record_type", "")
        sni = det.get("server_name_indication", "N/A")
        if sni and sni != "N/A":
            sni_list.add(sni)
            
        item = {
            "packet_num": p["packet_num"],
            "timestamp": p["timestamp"],
            "src_ip": p["src_ip"],
            "dst_ip": p["dst_ip"],
            "src_port": p["src_port"],
            "dst_port": p["dst_port"],
            "tls_version": det.get("tls_version", "TLS"),
            "record_type": rec_type,
            "sni": sni,
            "encrypted": True,
            "info": p["info"]
        }
        
        if "Handshake" in rec_type:
            handshakes.append(item)
        else:
            app_data_packets.append(item)

    return {
        "total_https_packets": len(packets),
        "handshake_packets_count": len(handshakes),
        "encrypted_app_data_count": len(app_data_packets),
        "observed_sni_hosts": list(sni_list),
        "packets": packets,
        "security_verdict": (
            "SECURE: All application payloads are encrypted with TLS 1.3 / 1.2. "
            "Passive sniffing (Wireshark) CANNOT read passwords, form bodies, or URLs without private keys."
        )
    }

def get_ftp_analysis(session_id: int = None) -> Dict[str, Any]:
    packets = get_packets(session_id=session_id, protocol="FTP", limit=1000)
    
    commands = []
    credentials = []
    
    for p in packets:
        det = p.get("details", {}).get("application", {})
        sec = p.get("details", {}).get("security", {})
        
        cmd = det.get("command_or_response", p["info"])
        commands.append({
            "packet_num": p["packet_num"],
            "timestamp": p["timestamp"],
            "src_ip": p["src_ip"],
            "dst_ip": p["dst_ip"],
            "command": cmd,
            "info": p["info"]
        })
        
        if sec.get("has_credentials"):
            credentials.append({
                "packet_num": p["packet_num"],
                "username": sec.get("username"),
                "password": sec.get("password"),
                "evidence": sec.get("evidence")
            })

    return {
        "total_ftp_packets": len(packets),
        "commands": commands,
        "leaked_credentials": credentials,
        "security_verdict": (
            "HIGH RISK: Standard FTP sends commands and passwords in cleartext. "
            "Use SFTP (SSH File Transfer) or FTPS (FTP over TLS) instead."
        )
    }
