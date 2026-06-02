import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone as dt_timezone, timedelta

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    load_der_private_key, load_pem_private_key,
)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.utils import timezone

from .models import AuditLog, UserCertificate


def _get_encryption_key() -> bytes:
    raw_key = getattr(settings, 'CERT_ENCRYPTION_KEY', None)
    if not raw_key:
        raise ImproperlyConfigured('CERT_ENCRYPTION_KEY must be set in Django settings.')

    if isinstance(raw_key, str):
        key_bytes = raw_key.encode('utf-8')
    else:
        key_bytes = raw_key

    if len(key_bytes) == 32:
        return key_bytes

    try:
        decoded = base64.urlsafe_b64decode(key_bytes)
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    return hashlib.sha256(key_bytes).digest()


def _get_issuer_name() -> str:
    return getattr(settings, 'CERT_ISSUER_NAME', 'Casa Monarca')


def _get_expiration_days() -> int:
    days = getattr(settings, 'CERT_EXPIRATION_DAYS', 30)
    try:
        return int(days)
    except (TypeError, ValueError):
        raise ImproperlyConfigured('CERT_EXPIRATION_DAYS must be an integer.')


def generate_certificate_payload(collaborator) -> dict:
    now = timezone.now()
    expires_at = now + timedelta(days=_get_expiration_days())
    return {
        'username': collaborator.username,
        'internal_id': collaborator.internal_id,
        'email': collaborator.email,
        'area': collaborator.area.name if collaborator.area else None,
        'access_level': collaborator.access_level,
        'role': collaborator.role,
        'issued_at': now.isoformat(),
        'expires_at': expires_at.isoformat(),
        'issuer': _get_issuer_name(),
    }


def encrypt_certificate(payload: dict) -> str:
    plaintext = json.dumps(payload, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode('utf-8')


def decrypt_certificate(encrypted_str: str) -> dict:
    try:
        payload_bytes = base64.urlsafe_b64decode(encrypted_str.encode('utf-8'))
        nonce = payload_bytes[:12]
        ciphertext = payload_bytes[12:]
        plaintext = AESGCM(_get_encryption_key()).decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))
    except (InvalidTag, ValueError, json.JSONDecodeError) as exc:
        raise ValueError('Invalid or tampered certificate.') from exc


def issue_encrypted_certificate(collaborator, issued_by):
    existing_cert = getattr(collaborator, 'certificate', None)
    if existing_cert and existing_cert.is_valid:
        raise PermissionError('Certificate already issued')

    payload = generate_certificate_payload(collaborator)
    encrypted_payload = encrypt_certificate(payload)
    fingerprint = hashlib.sha256(encrypted_payload.encode('utf-8')).hexdigest()
    expires_at = timezone.now() + timedelta(days=_get_expiration_days())

    if existing_cert:
        existing_cert.certificate_data = encrypted_payload
        existing_cert.fingerprint = fingerprint
        existing_cert.expires_at = expires_at
        existing_cert.is_revoked = False
        existing_cert.revoked_at = None
        existing_cert.revoked_by = None
        existing_cert.issued_by = issued_by
        existing_cert.save()
        certificate = existing_cert
    else:
        certificate = UserCertificate.objects.create(
            collaborator=collaborator,
            certificate_data=encrypted_payload,
            fingerprint=fingerprint,
            expires_at=expires_at,
            issued_by=issued_by,
        )

    AuditLog.objects.create(
        actor=issued_by,
        target=collaborator,
        action='CERTIFICATE_ISSUED',
        details=fingerprint,
    )
    return certificate


def validate_encrypted_certificate(collaborator, encrypted_str) -> bool:
    try:
        payload = decrypt_certificate(encrypted_str)
    except ValueError:
        AuditLog.objects.create(
            actor=collaborator,
            target=collaborator,
            action='CERTIFICATE_VALIDATION_FAILED',
            details='decrypt_failed',
        )
        return False

    if payload.get('username') != collaborator.username or payload.get('internal_id') != collaborator.internal_id:
        AuditLog.objects.create(
            actor=collaborator,
            target=collaborator,
            action='CERTIFICATE_VALIDATION_FAILED',
            details='payload_mismatch',
        )
        return False

    try:
        certificate = collaborator.certificate
    except UserCertificate.DoesNotExist:
        AuditLog.objects.create(
            actor=collaborator,
            target=collaborator,
            action='CERTIFICATE_VALIDATION_FAILED',
            details='certificate_missing',
        )
        return False

    if not certificate.is_valid:
        AuditLog.objects.create(
            actor=collaborator,
            target=collaborator,
            action='CERTIFICATE_VALIDATION_FAILED',
            details='certificate_invalid',
        )
        return False

    fingerprint = hashlib.sha256(encrypted_str.encode('utf-8')).hexdigest()
    if fingerprint != certificate.fingerprint:
        AuditLog.objects.create(
            actor=collaborator,
            target=collaborator,
            action='CERTIFICATE_VALIDATION_FAILED',
            details='fingerprint_mismatch',
        )
        return False

    AuditLog.objects.create(
        actor=collaborator,
        target=collaborator,
        action='CERTIFICATE_VALIDATED',
        details=fingerprint,
    )
    return True


# ---------------------------------------------------------------------------
# Coordinator certificate: RSA key pair + self-signed X.509 (.key / .cert)
# This mirrors the SAT e-firma format: PKCS#8 DER private key + PEM certificate.
# ---------------------------------------------------------------------------

def _encrypt_bytes(data: bytes) -> str:
    """AES-GCM encrypt arbitrary bytes; returns base64url string for DB storage."""
    key = _get_encryption_key()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, data, None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode('utf-8')


def _decrypt_bytes(encrypted_str: str) -> bytes:
    """Reverse of _encrypt_bytes."""
    payload = base64.urlsafe_b64decode(encrypted_str.encode('utf-8'))
    nonce, ciphertext = payload[:12], payload[12:]
    return AESGCM(_get_encryption_key()).decrypt(nonce, ciphertext, None)


def generate_coordinator_key_cert(collaborator) -> tuple:
    """
    Generate a 2048-bit RSA key pair and a self-signed X.509 certificate.
    Returns (key_der: bytes, cert_pem: bytes).
    The .key file is PKCS#8 DER (like SAT); the .cert file is PEM.
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.now(dt_timezone.utc)
    expires = now + timedelta(days=_get_expiration_days())

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'MX'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'CDMX'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, _get_issuer_name()),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, collaborator.area.name if collaborator.area else 'Sin área'),
        x509.NameAttribute(NameOID.COMMON_NAME, collaborator.username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, collaborator.email),
        x509.NameAttribute(NameOID.SERIAL_NUMBER, collaborator.internal_id),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=True,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    key_der = private_key.private_bytes(
        encoding=Encoding.DER,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    cert_pem = cert.public_bytes(Encoding.PEM)
    return key_der, cert_pem


def issue_coordinator_key_cert(collaborator, issued_by):
    """
    Issue .key and .cert files for a coordinator.
    Stores the PEM certificate in certificate_data and the AES-GCM encrypted
    DER private key in key_data.  Compatible with the existing UserCertificate model.
    """
    existing_cert = getattr(collaborator, 'certificate', None)
    if existing_cert and existing_cert.is_valid:
        raise PermissionError('Certificate already issued')

    key_der, cert_pem = generate_coordinator_key_cert(collaborator)

    cert_pem_str = cert_pem.decode('utf-8')
    fingerprint = hashlib.sha256(cert_pem).hexdigest()
    encrypted_key = _encrypt_bytes(key_der)
    expires_at = timezone.now() + timedelta(days=_get_expiration_days())

    if existing_cert:
        existing_cert.certificate_data = cert_pem_str
        existing_cert.fingerprint = fingerprint
        existing_cert.key_data = encrypted_key
        existing_cert.expires_at = expires_at
        existing_cert.is_revoked = False
        existing_cert.revoked_at = None
        existing_cert.revoked_by = None
        existing_cert.issued_by = issued_by
        existing_cert.save()
        certificate = existing_cert
    else:
        certificate = UserCertificate.objects.create(
            collaborator=collaborator,
            certificate_data=cert_pem_str,
            fingerprint=fingerprint,
            key_data=encrypted_key,
            expires_at=expires_at,
            issued_by=issued_by,
        )

    AuditLog.objects.create(
        actor=issued_by,
        target=collaborator,
        action='CERTIFICATE_ISSUED',
        details=fingerprint,
    )
    return certificate


def get_coordinator_key_bytes(certificate) -> bytes:
    """Return decrypted PKCS#8 DER private key bytes for download as .key file."""
    if not certificate.key_data:
        raise ValueError('No private key stored for this certificate.')
    return _decrypt_bytes(certificate.key_data)


def validate_coordinator_cert_and_key(collaborator, cert_pem_bytes: bytes, key_der_bytes: bytes) -> bool:
    """
    Validate coordinator login: verify the uploaded .cert and .key files.
    Checks:
      1. The private key matches the certificate's public key.
      2. The certificate fingerprint matches what is stored in the DB.
      3. The stored certificate is still valid (not revoked / not expired).
    """
    try:
        cert = load_pem_x509_certificate(cert_pem_bytes)
        try:
            private_key = load_der_private_key(key_der_bytes, password=None)
        except (ValueError, TypeError):
            private_key = load_pem_private_key(key_der_bytes, password=None)

        cert_pub = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        key_pub = private_key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

        if cert_pub != key_pub:
            AuditLog.objects.create(
                actor=collaborator, target=collaborator,
                action='CERTIFICATE_VALIDATION_FAILED', details='key_cert_mismatch',
            )
            return False

        try:
            db_cert = collaborator.certificate
        except UserCertificate.DoesNotExist:
            AuditLog.objects.create(
                actor=collaborator, target=collaborator,
                action='CERTIFICATE_VALIDATION_FAILED', details='certificate_missing',
            )
            return False

        if not db_cert.is_valid:
            AuditLog.objects.create(
                actor=collaborator, target=collaborator,
                action='CERTIFICATE_VALIDATION_FAILED', details='certificate_invalid',
            )
            return False

        uploaded_fingerprint = hashlib.sha256(cert_pem_bytes).hexdigest()
        if uploaded_fingerprint != db_cert.fingerprint:
            AuditLog.objects.create(
                actor=collaborator, target=collaborator,
                action='CERTIFICATE_VALIDATION_FAILED', details='fingerprint_mismatch',
            )
            return False

        AuditLog.objects.create(
            actor=collaborator, target=collaborator,
            action='CERTIFICATE_VALIDATED', details=db_cert.fingerprint,
        )
        return True

    except Exception as exc:
        AuditLog.objects.create(
            actor=collaborator, target=collaborator,
            action='CERTIFICATE_VALIDATION_FAILED', details=f'exception:{str(exc)[:120]}',
        )
        return False
