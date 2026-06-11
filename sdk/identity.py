"""
SDK module (a): Certificate lifecycle management.

Wraps the Casa Monarca CA and X.509 certificate operations into a standalone
interface usable without Django.  Callers generate a CA once, then issue,
verify, and revoke certificates for users.

Algorithm choices:
  - CA key:   EC SECP256R1 (P-256) — compact, fast, widely supported.
  - User key: RSA-2048 — required for RSA-PSS document signing in other modules.
  - CA key protection: AES-256-GCM with PBKDF2-HMAC-SHA256 (600,000 iterations).

All PEM values are bytes.  Encrypted CA keys are opaque strings (hex-encoded
salt:nonce:ciphertext) safe to persist in a file or database column.
"""

import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key,
)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

_SEP = ":"
_PBKDF2_ITERATIONS = 600_000
_CA_VALID_YEARS = 5
_CERT_VALID_DAYS_DEFAULT = 365
_PRIVILEGED_ROLES = frozenset({"admin", "coordinador"})


# ── CA key encryption helpers ─────────────────────────────────────────────────

def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _encrypt_pem(pem_bytes: bytes, password: str) -> str:
    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, pem_bytes, None)
    return salt.hex() + _SEP + nonce.hex() + _SEP + ciphertext.hex()


def _decrypt_pem(encrypted_str: str, password: str) -> bytes:
    try:
        salt_hex, nonce_hex, ct_hex = encrypted_str.strip().split(_SEP)
        key = _derive_key(password, bytes.fromhex(salt_hex))
        return AESGCM(key).decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex), None)
    except Exception as exc:
        raise ValueError(
            "Failed to decrypt CA private key. Wrong password or corrupted data."
        ) from exc


# ── Public API ────────────────────────────────────────────────────────────────

def generate_ca(ca_password: str) -> tuple[bytes, str]:
    """Generate a new internal Certificate Authority key pair.

    Creates an EC SECP256R1 root CA valid for 5 years.  The private key is
    encrypted with AES-256-GCM derived from *ca_password* and returned as an
    opaque string suitable for file storage.

    Args:
        ca_password: Strong password used to protect the CA private key at rest.
            Never store this in code or version control.

    Returns:
        A tuple ``(ca_cert_pem, ca_key_encrypted)`` where:
          - ``ca_cert_pem`` is the public CA certificate in PEM format (bytes).
            This is safe to distribute.
          - ``ca_key_encrypted`` is the AES-GCM encrypted private key (str).
            Store securely; loss means the CA cannot sign new certificates.

    Raises:
        ValueError: If *ca_password* is empty.

    Example:
        >>> ca_cert_pem, ca_key_enc = generate_ca("secure-ca-password")
        >>> with open("ca.crt", "wb") as f: f.write(ca_cert_pem)
        >>> with open("ca_key.enc", "w") as f: f.write(ca_key_enc)
    """
    if not ca_password:
        raise ValueError("ca_password must not be empty.")

    private_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Monterrey"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Casa Monarca"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Autoridad Certificadora"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Casa Monarca Root CA"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=_CA_VALID_YEARS * 365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    ca_cert_pem = cert.public_bytes(Encoding.PEM)
    key_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return ca_cert_pem, _encrypt_pem(key_pem, ca_password)


def issue_certificate(
    user_id: int,
    username: str,
    role: str,
    area: str,
    ca_cert_pem: bytes,
    ca_key_encrypted: str,
    ca_password: str,
    valid_days: int = _CERT_VALID_DAYS_DEFAULT,
) -> tuple[bytes, bytes]:
    """Issue an X.509 certificate for a privileged user, signed by the CA.

    Only users with role ``"admin"`` or ``"coordinador"`` may receive
    certificates.  The RSA-2048 private key is returned to the caller and
    must never be stored on the server — it belongs to the end user.

    Args:
        user_id: Unique numeric identifier for the user (stored in the
            certificate's ``serialNumber`` attribute).
        username: Human-readable name embedded as the certificate's CN.
        role: Must be ``"admin"`` or ``"coordinador"``.
        area: Organizational unit for the certificate (e.g., ``"Legal"``).
        ca_cert_pem: CA certificate PEM bytes, as returned by :func:`generate_ca`.
        ca_key_encrypted: Encrypted CA private key string, as returned by
            :func:`generate_ca`.
        ca_password: Password to decrypt *ca_key_encrypted*.
        valid_days: Certificate validity period in days.  Default 365.

    Returns:
        A tuple ``(cert_pem, private_key_pem)`` where both values are PEM bytes.
        The private key must be delivered securely to the user and never logged.

    Raises:
        ValueError: If *role* is not in ``{"admin", "coordinador"}``.
        ValueError: If the CA key cannot be decrypted (wrong password).

    Example:
        >>> cert_pem, key_pem = issue_certificate(
        ...     user_id=1, username="mariel", role="admin", area="Administracion",
        ...     ca_cert_pem=ca_cert_pem, ca_key_encrypted=ca_key_enc,
        ...     ca_password="secure-ca-password",
        ... )
    """
    if role not in _PRIVILEGED_ROLES:
        raise ValueError(
            f"Only roles {sorted(_PRIVILEGED_ROLES)} may receive certificates. "
            f"Got: '{role}'."
        )

    ca_cert = load_pem_x509_certificate(ca_cert_pem)
    key_pem = _decrypt_pem(ca_key_encrypted, ca_password)
    ca_key = load_pem_private_key(key_pem, password=None)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "MX"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Monterrey"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Casa Monarca"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, area),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, str(user_id)),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=valid_days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(Encoding.PEM)
    priv_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return cert_pem, priv_pem


def verify_certificate(
    cert_pem: bytes,
    ca_cert_pem: bytes,
    revoked_serials: Optional[set] = None,
) -> dict:
    """Verify an X.509 certificate against the CA.

    Checks the CA signature, validity period, and optional revocation list.

    Args:
        cert_pem: Certificate to verify (PEM bytes).
        ca_cert_pem: Trusted CA certificate (PEM bytes).
        revoked_serials: Optional set of revoked serial numbers (uppercase hex
            strings).  If provided, a matching serial causes verification to
            fail with ``reason="revoked"``.

    Returns:
        A dict with keys:
          - ``valid`` (bool): Overall verification result.
          - ``reason`` (str): ``"ok"`` or a short failure code.
          - ``common_name`` (str): Certificate CN.
          - ``area`` (str): Certificate OU.
          - ``user_id`` (str): Numeric ID embedded in serialNumber.
          - ``serial_number`` (str): Certificate serial (uppercase hex).
          - ``expires_at`` (datetime): Expiry timestamp (UTC).

    Example:
        >>> info = verify_certificate(cert_pem, ca_cert_pem)
        >>> if info["valid"]:
        ...     print("Trusted:", info["common_name"])
    """
    result: dict = {
        "valid": False, "reason": "", "common_name": "", "area": "",
        "user_id": "", "serial_number": "", "expires_at": None,
    }
    try:
        cert = load_pem_x509_certificate(cert_pem)
        ca_cert = load_pem_x509_certificate(ca_cert_pem)
        ca_pub = ca_cert.public_key()

        try:
            if isinstance(ca_pub, ec.EllipticCurvePublicKey):
                ca_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                              ec.ECDSA(cert.signature_hash_algorithm))
            else:
                ca_pub.verify(cert.signature, cert.tbs_certificate_bytes,
                              padding.PKCS1v15(), cert.signature_hash_algorithm)
        except (InvalidSignature, Exception):
            result["reason"] = "invalid_ca_signature"
            return result

        now = datetime.now(timezone.utc)
        if now < cert.not_valid_before_utc:
            result["reason"] = "not_yet_valid"
            return result
        if now > cert.not_valid_after_utc:
            result["reason"] = "expired"
            return result

        serial_hex = format(cert.serial_number, "x").upper()
        if revoked_serials and serial_hex in revoked_serials:
            result["reason"] = "revoked"
            return result

        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ou_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        sn_attrs = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
        result.update({
            "valid": True,
            "reason": "ok",
            "common_name": cn_attrs[0].value if cn_attrs else "",
            "area": ou_attrs[0].value if ou_attrs else "",
            "user_id": sn_attrs[0].value if sn_attrs else "",
            "serial_number": serial_hex,
            "expires_at": cert.not_valid_after_utc,
        })
    except Exception as exc:
        result["reason"] = f"error: {str(exc)[:120]}"
    return result


def get_cert_metadata(cert_pem: bytes) -> dict:
    """Extract metadata from a certificate PEM for storage or display.

    Args:
        cert_pem: Certificate in PEM format (bytes).

    Returns:
        A dict with: ``serial_number``, ``fingerprint_sha256``,
        ``issued_at``, ``expires_at``, ``common_name``, ``area``, ``user_id``.

    Example:
        >>> meta = get_cert_metadata(cert_pem)
        >>> print(meta["fingerprint_sha256"])
    """
    cert = load_pem_x509_certificate(cert_pem)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    ou = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
    sn = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    return {
        "serial_number": format(cert.serial_number, "x").upper(),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "issued_at": cert.not_valid_before_utc,
        "expires_at": cert.not_valid_after_utc,
        "common_name": cn[0].value if cn else "",
        "area": ou[0].value if ou else "",
        "user_id": sn[0].value if sn else "",
    }


def get_ca_fingerprint(ca_cert_pem: bytes) -> str:
    """Return the SHA-256 fingerprint of a CA certificate in colon-separated hex.

    Args:
        ca_cert_pem: CA certificate PEM bytes.

    Returns:
        Fingerprint string, e.g. ``"AB:CD:EF:..."``.

    Example:
        >>> fp = get_ca_fingerprint(ca_cert_pem)
        >>> print("CA fingerprint:", fp)
    """
    cert = load_pem_x509_certificate(ca_cert_pem)
    raw = cert.fingerprint(hashes.SHA256())
    return ":".join(f"{b:02X}" for b in raw)


def check_key_matches_cert(cert_pem: bytes, private_key_pem: bytes) -> bool:
    """Verify that a private key corresponds to the public key in a certificate.

    Useful to validate that the user uploaded the correct key file before
    allowing a signing operation.

    Args:
        cert_pem: Certificate in PEM format (bytes).
        private_key_pem: Private key in PEM format (bytes, unencrypted).

    Returns:
        True if the keys match, False otherwise.

    Example:
        >>> ok = check_key_matches_cert(cert_pem, key_pem)
        >>> if not ok:
        ...     raise ValueError("Key does not match certificate.")
    """
    try:
        cert = load_pem_x509_certificate(cert_pem)
        key = load_pem_private_key(private_key_pem, password=None)
        cert_pub = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        key_pub = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return cert_pub == key_pub
    except Exception:
        return False
