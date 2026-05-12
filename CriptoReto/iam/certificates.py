import base64
import hashlib
import json
import secrets
from datetime import timedelta

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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
