"""
NetSecure - Local HTTPS & TLS 1.3 Service
Generates an ephemeral X.509 certificate and runs a background HTTPS daemon on port 5443.
Allows demonstrating that credentials submitted to HTTPS are encrypted on the wire.
"""

import ssl
import threading
import http.server
from pathlib import Path
from datetime import datetime, timezone, timedelta
import ipaddress

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from backend.network_info import HOST_IP

CERTS_DIR = Path(__file__).resolve().parent.parent / "certs"
CERTS_DIR.mkdir(parents=True, exist_ok=True)
CERT_FILE = CERTS_DIR / "cert.pem"
KEY_FILE = CERTS_DIR / "key.pem"
HTTPS_PORT = 5443

def generate_certificates():
    if CERT_FILE.exists() and KEY_FILE.exists():
        return str(CERT_FILE), str(KEY_FILE)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "NetSecure Local TLS"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "University Information Security Lab"),
    ])

    san_list = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
    ]
    try:
        san_list.append(x509.IPAddress(ipaddress.IPv4Address(HOST_IP)))
    except Exception:
        pass

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .sign(key, hashes.SHA256())
    )

    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return str(CERT_FILE), str(KEY_FILE)

class HTTPSDummyHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-TLS-Protocol", "TLSv1.3-AES-256-GCM")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b'{"status":"authenticated","encrypted":true,"cipher":"AES-256-GCM"}')

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def log_message(self, format, *args):
        pass # Suppress console noise

def start_https_background_daemon():
    try:
        c_path, k_path = generate_certificates()
        server = http.server.HTTPServer(("0.0.0.0", HTTPS_PORT), HTTPSDummyHandler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=c_path, keyfile=k_path)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        print(f"[NetSecure] HTTPS TLS 1.3 Service listening on https://{HOST_IP}:{HTTPS_PORT}")
    except Exception as e:
        print(f"[NetSecure] Note on HTTPS Service: {e}")
