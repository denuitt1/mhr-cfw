"""
MITM certificate manager for HTTPS interception.

Generates a CA certificate (once, stored as files) and per-domain
certificates (on the fly, cached in memory) so the local proxy can
decrypt HTTPS traffic and relay it through Apps Script.

The user must install ca/ca.crt in their browser's trusted CAs once.

Requires: pip install cryptography
"""

import datetime
import logging
import os
import re
import ssl
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

log = logging.getLogger("MITM")

# CA lives at the project root (../ca/ relative to this file in src/).
# The installed trusted root was generated there; keep using it.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_THIS_DIR)
CA_DIR = os.path.join(_PROJECT_ROOT, "ca")
CA_KEY_FILE = os.path.join(CA_DIR, "ca.key")
CA_CERT_FILE = os.path.join(CA_DIR, "ca.crt")


# Filename-safe form of an SNI / hostname.  Windows forbids colons,
# question marks, etc., so IPv6 literals (and stray Unicode) must be
# rewritten before they become part of a cached cert file path.
_UNSAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def _safe_domain_filename(domain: str) -> str:
    cleaned = _UNSAFE_NAME_RE.sub("_", domain.strip(".").lower())
    return cleaned[:120] or "unknown"


class MITMCertManager:
    def __init__(self):
        self._ca_key = None
        self._ca_cert = None
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        self._cert_dir = tempfile.mkdtemp(prefix="domainfront_certs_")
        self._ensure_ca()

    def _ensure_ca(self):
        if os.path.exists(CA_KEY_FILE) and os.path.exists(CA_CERT_FILE):
            with open(CA_KEY_FILE, "rb") as f:
                self._ca_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )
            with open(CA_CERT_FILE, "rb") as f:
                self._ca_cert = x509.load_pem_x509_certificate(f.read())
            log.info("Loaded CA from %s", CA_DIR)
        else:
            self._create_ca()

    def _create_ca(self):
        os.makedirs(CA_DIR, exist_ok=True)

        self._ca_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "mhr-cfw"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "mhr-cfw"),
        ])
        now = datetime.datetime.now(datetime.timezone.utc)
        self._ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self._ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0), critical=True
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        with open(CA_KEY_FILE, "wb") as f:
            f.write(
                self._ca_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )
        # Restrict the CA private key to the current user on POSIX.
        # os.chmod is a no-op for permission bits on Windows.
        if os.name == "posix":
            try:
                os.chmod(CA_KEY_FILE, 0o600)
            except OSError:
                pass
        with open(CA_CERT_FILE, "wb") as f:
            f.write(self._ca_cert.public_bytes(serialization.Encoding.PEM))

        log.warning("Generated new CA certificate: %s", CA_CERT_FILE)
        log.warning(">>> Install this file in your browser's Trusted Root CAs! <<<")

    def get_server_context(self, domain: str) -> ssl.SSLContext:
        if domain not in self._ctx_cache:
            key_pem, cert_pem = self._generate_domain_cert(domain)

            safe = _safe_domain_filename(domain)
            cert_file = os.path.join(self._cert_dir, f"{safe}.crt")
            key_file = os.path.join(self._cert_dir, f"{safe}.key")

            ca_pem = self._ca_cert.public_bytes(serialization.Encoding.PEM)
            with open(cert_file, "wb") as f:
                f.write(cert_pem + ca_pem)
            with open(key_file, "wb") as f:
                f.write(key_pem)

            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.set_alpn_protocols(["http/1.1"])
            ctx.load_cert_chain(cert_file, key_file)
            self._ctx_cache[domain] = ctx

        return self._ctx_cache[domain]

    def _generate_domain_cert(self, domain: str):
        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, domain[:64] or "unknown"),
        ])

        # SAN: IP literal vs DNS name — x509.DNSName rejects IPv6 literals.
        import ipaddress as _ipaddress
        try:
            san_entry = x509.IPAddress(_ipaddress.ip_address(domain))
        except ValueError:
            san_entry = x509.DNSName(domain)

        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([san_entry]),
                critical=False,
            )
            .sign(self._ca_key, hashes.SHA256())
        )

        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        return key_pem, cert_pem