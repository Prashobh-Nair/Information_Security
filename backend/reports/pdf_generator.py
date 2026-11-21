"""
NetSecure PDF Report Generator
Generates a formal academic network security analysis report using ReportLab.
"""

import os
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch

from backend.config import REPORTS_DIR, DEFAULT_TEAM_INFO
from backend.database import get_packets, get_security_alerts, get_lab_settings
from backend.analyzer.statistics_engine import compute_session_statistics
from backend.protocols import (
    get_icmp_analysis, get_arp_analysis, get_dns_analysis,
    get_http_analysis, get_https_analysis, get_ftp_analysis
)

def generate_pdf_report(session_id: int = None, filename: str = "") -> str:
    if not filename:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"NetSecure_Security_Report_{timestamp}.pdf"

    pdf_path = REPORTS_DIR / filename
    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=letter,
        rightMargin=36,
        leftMargin=36,
        topMargin=36,
        bottomMargin=36
    )

    styles = getSampleStyleSheet()
    
    # Custom Cyber / Academic Styles
    primary_color = colors.HexColor("#0f172a")    # Slate 900
    accent_blue = colors.HexColor("#0284c7")      # Cyan 600
    accent_green = colors.HexColor("#059669")     # Emerald 600
    accent_red = colors.HexColor("#dc2626")       # Red 600
    bg_light = colors.HexColor("#f8fafc")

    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=20,
        leading=24,
        textColor=primary_color,
        spaceAfter=4
    )
    
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#475569"),
        spaceAfter=12
    )

    h2_style = ParagraphStyle(
        "DocH2",
        parent=styles["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=accent_blue,
        spaceBefore=10,
        spaceAfter=6
    )

    body_style = ParagraphStyle(
        "DocBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b")
    )

    body_bold = ParagraphStyle(
        "DocBodyBold",
        parent=body_style,
        fontName="Helvetica-Bold"
    )

    badge_danger = ParagraphStyle(
        "BadgeDanger",
        parent=body_style,
        textColor=accent_red,
        fontName="Helvetica-Bold"
    )

    badge_success = ParagraphStyle(
        "BadgeSuccess",
        parent=body_style,
        textColor=accent_green,
        fontName="Helvetica-Bold"
    )

    story = []

    # 1. Header Banner
    story.append(Paragraph("NETSECURE: NETWORK TRAFFIC MONITORING & SECURITY ANALYSIS", title_style))
    story.append(Paragraph("Academic Information Security Lab Report — Laboratory Exercise 12", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=accent_blue, spaceAfter=12))

    # 2. Metadata Table
    settings = get_lab_settings()
    now_str = datetime.now().strftime("%B %d, %Y - %H:%M:%S")
    
    meta_data = [
        [Paragraph("<b>Course:</b>", body_style), Paragraph(DEFAULT_TEAM_INFO["course"], body_style),
         Paragraph("<b>Date Generated:</b>", body_style), Paragraph(now_str, body_style)],
        [Paragraph("<b>Machine A (Examiner):</b>", body_style), Paragraph(settings.get("machine_a_ip", "192.168.1.10"), body_style),
         Paragraph("<b>Machine B (Target):</b>", body_style), Paragraph(settings.get("machine_b_ip", "192.168.1.20"), body_style)],
        [Paragraph("<b>Network Topology:</b>", body_style), Paragraph("Ethernet 802.3 Local Area Network", body_style),
         Paragraph("<b>Capture Engine:</b>", body_style), Paragraph("Wireshark TShark / NetSecure Dual Engine", body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[1.4*inch, 2.1*inch, 1.4*inch, 2.1*inch])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), bg_light),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 12))

    # Fetch Data
    packets = get_packets(session_id=session_id, limit=2000)
    stats = compute_session_statistics(packets)
    icmp_data = get_icmp_analysis(session_id)
    arp_data = get_arp_analysis(session_id)
    dns_data = get_dns_analysis(session_id)
    http_data = get_http_analysis(session_id)
    https_data = get_https_analysis(session_id)
    ftp_data = get_ftp_analysis(session_id)
    alerts = get_security_alerts()

    # 3. Executive Statistics Table
    story.append(Paragraph("1. Network Traffic Volume & Protocol Distribution", h2_style))
    proto_counts = stats["counts"]
    
    stat_table_data = [
        ["Total Packets", "TCP", "UDP", "ICMP (Ping)", "HTTP", "HTTPS", "DNS", "ARP", "FTP"],
        [
            str(stats["total_packets"]),
            str(proto_counts.get("TCP", 0)),
            str(proto_counts.get("UDP", 0)),
            str(proto_counts.get("ICMP", 0)),
            str(proto_counts.get("HTTP", 0)),
            str(proto_counts.get("HTTPS", 0)),
            str(proto_counts.get("DNS", 0)),
            str(proto_counts.get("ARP", 0)),
            str(proto_counts.get("FTP", 0))
        ]
    ]
    t_stat = Table(stat_table_data, colWidths=[0.78*inch]*9)
    t_stat.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1e293b")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,-1), 8),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#94a3b8")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_stat)
    story.append(Spacer(1, 10))

    # 4. ICMP Analysis Section
    story.append(Paragraph("2. ICMP Traffic Analysis (Ping Verification)", h2_style))
    story.append(Paragraph(
        f"<b>Observations:</b> {icmp_data['lab_verdict']} "
        f"Identified {icmp_data['echo_requests_count']} Echo Requests (Type 8, Code 0) originating from Machine A "
        f"and {icmp_data['echo_replies_count']} Echo Replies (Type 0, Code 0) returned by Machine B.",
        body_style
    ))
    story.append(Spacer(1, 6))

    # ICMP Sample Ping Table
    icmp_rows = [["Req #", "Req Time", "Reply #", "Source (Machine A)", "Target (Machine B)", "ICMP Type/Code", "Status"]]
    for pair in icmp_data["ping_correlations"][:5]:
        icmp_rows.append([
            str(pair["request_num"]),
            pair["request_time"],
            str(pair["reply_num"]),
            pair["source_host"][:18],
            pair["target_host"][:18],
            "Type 8/0 → 0/0",
            pair["status"]
        ])
    if len(icmp_rows) > 1:
        t_icmp = Table(icmp_rows, colWidths=[0.6*inch, 0.9*inch, 0.6*inch, 1.7*inch, 1.7*inch, 1.1*inch, 0.9*inch])
        t_icmp.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#334155")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 7.5),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('TOPPADDING', (0,0), (-1,-1), 3),
            ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ]))
        story.append(t_icmp)
    story.append(Spacer(1, 10))

    # 5. Protocol Dissection Summary (ARP, DNS, HTTPS, FTP)
    story.append(Paragraph("3. Multi-Protocol Inspection Summary", h2_style))
    proto_summary_data = [
        [Paragraph("<b>Protocol</b>", body_bold), Paragraph("<b>Key Observed Data</b>", body_bold), Paragraph("<b>Security Implication</b>", body_bold)],
        [
            Paragraph("<b>ARP</b>", body_style),
            Paragraph(f"Resolved {len(arp_data['resolved_ip_mac_table'])} IP-MAC bindings. {arp_data['requests_count']} Requests, {arp_data['replies_count']} Replies.", body_style),
            Paragraph("Lacks cryptographic authentication; susceptible to ARP cache spoofing / MITM on LAN.", body_style)
        ],
        [
            Paragraph("<b>DNS</b>", body_style),
            Paragraph(f"{dns_data['total_dns_packets']} packets. Lookups: {', '.join(dns_data['unique_domains'][:3]) or 'Standard queries'}", body_style),
            Paragraph("Cleartext UDP port 53 permits eavesdropping on queried destinations.", body_style)
        ],
        [
            Paragraph("<b>HTTPS</b>", body_style),
            Paragraph(f"{https_data['total_https_packets']} packets. {https_data['handshake_packets_count']} Handshakes, {https_data['encrypted_app_data_count']} Encrypted Records.", body_style),
            Paragraph(f"<font color='{accent_green}'><b>CONFIDENTIAL:</b> Payload encrypted via TLS. Passive sniffers cannot read data.</font>", body_style)
        ],
        [
            Paragraph("<b>FTP</b>", body_style),
            Paragraph(f"{ftp_data['total_ftp_packets']} packets. {len(ftp_data['leaked_credentials'])} plaintext authentication events observed.", body_style),
            Paragraph(f"<font color='{accent_red}'><b>HIGH RISK:</b> Sends USER and PASS in plaintext across the LAN.</font>", body_style)
        ]
    ]
    t_proto = Table(proto_summary_data, colWidths=[1.0*inch, 3.4*inch, 2.6*inch])
    t_proto.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#f1f5f9")),
        ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t_proto)
    story.append(Spacer(1, 10))

    # 6. HTTP Password Sniffing Demonstration (Core Lab Requirement)
    story.append(Paragraph("4. HTTP Password Sniffing Demonstration & Security Findings", h2_style))
    story.append(Paragraph(
        "<b>Lab Demonstration Objective:</b> Prove how unencrypted HTTP transactions allow passive network sniffers (Wireshark) "
        "to intercept confidential authentication credentials without decrypting any data.",
        body_style
    ))
    story.append(Spacer(1, 6))

    leaked = http_data["leaked_credentials"]
    if leaked:
        leak_rows = [["Pkt #", "Source IP", "Target IP", "Auth Type", "Sniffed Username", "Sniffed Plaintext Password"]]
        for l in leaked[:5]:
            leak_rows.append([
                str(l["packet_num"]),
                l["src_ip"],
                l["dst_ip"],
                l.get("auth_type", "HTTP POST"),
                l.get("username", "N/A"),
                l.get("password", "N/A")
            ])
        t_leak = Table(leak_rows, colWidths=[0.6*inch, 1.2*inch, 1.2*inch, 1.4*inch, 1.3*inch, 1.3*inch])
        t_leak.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#dc2626")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#991b1b")),
            ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor("#f87171")),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ]))
        story.append(t_leak)
    else:
        story.append(Paragraph(
            "<i>No unencrypted credentials currently present in this active filter session. "
            "Execute the Dummy Web Login Demonstration in the NetSecure UI to log an live audit event.</i>",
            body_style
        ))
    story.append(Spacer(1, 10))

    # 7. Remediation & Recommendations
    story.append(Paragraph("5. Hardening & Mitigation Recommendations", h2_style))
    recs = [
        "<b>1. Mandatory HTTPS (TLS 1.3):</b> Enforce transport layer encryption on all web applications. Utilize modern cipher suites (AES-256-GCM, ChaCha20-Poly1305).",
        "<b>2. HTTP Strict Transport Security (HSTS):</b> Implement 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header to stop downgrade attacks.",
        "<b>3. Replace Legacy Protocols:</b> Migrate from unencrypted FTP (port 21) to SFTP (port 22) or FTPS (FTP over TLS).",
        "<b>4. LAN Layer 2 Defense:</b> Implement Dynamic ARP Inspection (DAI) and DHCP Snooping on managed network switches to prevent ARP poisoning.",
        "<b>5. Encrypted DNS:</b> Adopt DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT) to preserve query privacy."
    ]
    for r in recs:
        story.append(Paragraph(r, body_style))
        story.append(Spacer(1, 3))

    doc.build(story)
    return str(pdf_path)
