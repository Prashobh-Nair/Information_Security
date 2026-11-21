"""
NetSecure Payload Inspector
Generates classic Wireshark-style Hex Dump + ASCII byte views and scans for unencrypted plaintext sensitive data.
"""

import re
from typing import Dict, Any, List

def format_hex_ascii_dump(raw_bytes: bytes) -> str:
    """
    Formats binary bytes into Wireshark / hexdump format:
    0000  00 0c 29 1a 2b 3c 00 0c  29 4d 5e 6f 08 00 45 00  ..).+<..)M^o..E.
    """
    if not raw_bytes:
        return "No payload data"
    
    lines = []
    length = len(raw_bytes)
    
    for offset in range(0, length, 16):
        chunk = raw_bytes[offset:offset + 16]
        hex_parts = []
        ascii_parts = []
        
        for i, b in enumerate(chunk):
            hex_parts.append(f"{b:02x}")
            # Non-printable characters rendered as '.'
            if 32 <= b <= 126:
                ascii_parts.append(chr(b))
            else:
                ascii_parts.append(".")
        
        # Wireshark splits into two 8-byte groups with extra space
        if len(hex_parts) > 8:
            hex_str = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:])
        else:
            hex_str = " ".join(hex_parts)
            
        # Pad hex display to align ASCII column
        hex_padding = 49 - (len(hex_parts) * 3 + (1 if len(hex_parts) > 8 else 0))
        if hex_padding > 0:
            hex_str += " " * hex_padding
            
        ascii_str = "".join(ascii_parts)
        lines.append(f"{offset:04x}  {hex_str}  |{ascii_str}|")
        
    return "\n".join(lines)

def extract_printable_ascii(raw_bytes: bytes, min_len: int = 4) -> List[str]:
    """Extracts strings of printable ASCII characters of length >= min_len."""
    try:
        text = raw_bytes.decode("latin1", errors="ignore")
        return re.findall(rf"[ -~]{{{min_len},}}", text)
    except Exception:
        return []

def scan_for_credentials(payload_str: str) -> Dict[str, Any]:
    """
    Inspects payload strings for common cleartext credential formats
    such as HTTP POST parameters: username=...&password=... or JSON {"username":..., "password":...}
    or FTP USER and PASS commands.
    """
    findings = {
        "has_credentials": False,
        "username": None,
        "password": None,
        "auth_type": None,
        "risk_level": "LOW",
        "evidence": ""
    }

    if not payload_str:
        return findings

    # 1. HTTP URL-encoded or JSON login parameters
    user_match = re.search(r"(?:username|user|email|login|uname)[=:\"]+([^&\s\"\']+)", payload_str, re.IGNORECASE)
    pass_match = re.search(r"(?:password|pass|pwd|secret)[=:\"]+([^&\s\"\']+)", payload_str, re.IGNORECASE)
    
    if user_match and pass_match:
        findings["has_credentials"] = True
        findings["username"] = user_match.group(1)
        findings["password"] = pass_match.group(1)
        findings["auth_type"] = "HTTP Plaintext Form Submission"
        findings["risk_level"] = "CRITICAL"
        findings["evidence"] = f"POST Body: {user_match.group(0)} & {pass_match.group(0)}"
        return findings

    # 2. FTP USER & PASS commands
    ftp_user = re.search(r"^USER\s+([^\r\n]+)", payload_str, re.IGNORECASE | re.MULTILINE)
    ftp_pass = re.search(r"^PASS\s+([^\r\n]+)", payload_str, re.IGNORECASE | re.MULTILINE)
    
    if ftp_user:
        findings["has_credentials"] = True
        findings["username"] = ftp_user.group(1)
        findings["auth_type"] = "FTP Plaintext Authentication"
        findings["risk_level"] = "HIGH"
        findings["evidence"] = ftp_user.group(0)
        
    if ftp_pass:
        findings["has_credentials"] = True
        findings["password"] = ftp_pass.group(1)
        findings["auth_type"] = "FTP Plaintext Authentication"
        findings["risk_level"] = "CRITICAL"
        findings["evidence"] = ftp_pass.group(0)

    # 3. HTTP Basic Auth Header
    basic_match = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", payload_str, re.IGNORECASE)
    if basic_match:
        import base64
        try:
            decoded = base64.b64decode(basic_match.group(1)).decode("utf-8", errors="ignore")
            if ":" in decoded:
                u, p = decoded.split(":", 1)
                findings["has_credentials"] = True
                findings["username"] = u
                findings["password"] = p
                findings["auth_type"] = "HTTP Basic Auth (Base64 Encoded - Cleartext)"
                findings["risk_level"] = "CRITICAL"
                findings["evidence"] = basic_match.group(0)
        except Exception:
            pass

    return findings
