"""The portal's own self-signed certificate for network access (P9).

Made on first start in network mode and kept in /data/tls. It is reissued
only when the names it covers change or it is within 30 days of expiry;
either way the new fingerprint is printed in the log.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import os
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

# Apple platforms refuse TLS server certificates valid for more than 825
# days, even ones the user trusts by hand.
VALID_DAYS = 825
RENEW_DAYS = 30


def _names(hosts: tuple[str, ...]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    for h in hosts:
        h = h.strip("[]")
        try:
            ip = ipaddress.ip_address(h)
            gn: x509.GeneralName = x509.IPAddress(ip)
        except ValueError:
            gn = x509.DNSName(h)
        if gn not in out:
            out.append(gn)
    return out


def fingerprint(cert_pem: bytes) -> str:
    der = ssl.PEM_cert_to_DER_cert(cert_pem.decode())
    d = hashlib.sha256(der).hexdigest().upper()
    return ":".join(d[i:i + 2] for i in range(0, len(d), 2))


def _needs_new(cert_path: Path, names: list[x509.GeneralName], now: dt.datetime) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except (OSError, ValueError, x509.ExtensionNotFound):
        return True
    if set(san) != set(names):
        return True
    return cert.not_valid_after_utc - now < dt.timedelta(days=RENEW_DAYS)


def ensure(data_dir: str, hosts: tuple[str, ...], product: str = "Bridgekeep") -> tuple[str, str, str, bool]:
    """Return (cert path, key path, SHA-256 fingerprint, made_now)."""
    d = Path(data_dir) / "tls"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    cert_path, key_path = d / "cert.pem", d / "key.pem"
    names = _names(hosts)
    now = dt.datetime.now(dt.timezone.utc)
    made = False
    if not key_path.exists() or _needs_new(cert_path, names, now):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{product} portal")])
        cert = (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(minutes=5))
                .not_valid_after(now + dt.timedelta(days=VALID_DAYS))
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .sign(key, hashes.SHA256()))
        old = os.umask(0o077)
        try:
            tmp = key_path.with_suffix(".tmp")
            tmp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
            os.replace(tmp, key_path)
            tmp = cert_path.with_suffix(".tmp")
            tmp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            os.replace(tmp, cert_path)
        finally:
            os.umask(old)
        made = True
    return str(cert_path), str(key_path), fingerprint(cert_path.read_bytes()), made


def server_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx
