"""Create a self-signed HTTPS certificate for using DSC Signer on the local network.

Usage (from the project folder):
    .venv\\Scripts\\python.exe scripts\\make_lan_cert.py
    .venv\\Scripts\\python.exe scripts\\make_lan_cert.py --name dsc-pc --ip 192.168.1.50

Writes certs\\server.crt and certs\\server.key, valid for this PC's name, its current IPv4
addresses, localhost and 127.0.0.1 (plus any --name / --ip you add). Then set in .env:

    SSL_CERTFILE=C:\\dsc-signer\\certs\\server.crt
    SSL_KEYFILE=C:\\dsc-signer\\certs\\server.key

Browsers show a one-time "not private" warning for a self-signed certificate. To remove it,
import certs\\server.crt on each user's PC into "Trusted Root Certification Authorities"
(see INSTALL.md). Re-run this script if the PC's IP address changes.
"""
from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import socket
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent.parent


def local_ipv4() -> set[str]:
    ips: set[str] = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    try:  # the address used for outbound traffic (no packet is sent)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return {ip for ip in ips if not ip.startswith(("127.", "169.254."))}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", action="append", default=[], help="extra host name (repeatable)")
    ap.add_argument("--ip", action="append", default=[], help="extra IP address (repeatable)")
    ap.add_argument("--days", type=int, default=825, help="validity in days (default 825)")
    ap.add_argument("--out", default=str(ROOT / "certs"), help="output folder")
    args = ap.parse_args()

    host = socket.gethostname()
    names = sorted({host, host.lower(), "localhost", *args.name})
    ips = sorted(local_ipv4() | {"127.0.0.1", *args.ip}, key=lambda i: ipaddress.ip_address(i))

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, host),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DSC Signer (local network)"),
    ])
    now = dt.datetime.now(dt.timezone.utc)
    san = [x509.DNSName(n) for n in names] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=args.days))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=True,
                                     content_commitment=False, data_encipherment=False, key_agreement=False,
                                     crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    crt_path, key_path = out / "server.crt", out / "server.key"
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                           serialization.NoEncryption()))

    print(f"Certificate: {crt_path}")
    print(f"Private key: {key_path}  (keep it on this PC only)")
    print("Valid for:   " + ", ".join(names + ips))
    print("\nAdd to .env, then re-run scripts\\install_service.ps1:")
    print(f"  SSL_CERTFILE={crt_path}")
    print(f"  SSL_KEYFILE={key_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
