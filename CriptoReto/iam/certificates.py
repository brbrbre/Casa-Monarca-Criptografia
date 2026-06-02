"""
Gestión de certificados X.509 para Casa Monarca — capa de servicio Django.

TODA la criptografía delega a crypto_core.certificates y crypto_core.ca.
Este módulo solo contiene lógica de negocio Django (ORM, AuditLog, etc.).

Reglas absolutas:
  - Solo admin (nivel 1) y coordinador (nivel 2) reciben certificados.
  - La clave privada del usuario NUNCA se guarda en la BD.
  - Los certificados son firmados por la CA interna (no auto-firmados).
"""

import os
from pathlib import Path

from django.conf import settings
from django.utils import timezone

from .models import AuditLog, UserCertificate

# ── Carga de la CA ──────────────────────────────────────────────────────────────

def _get_ca_cert_pem() -> bytes:
    ca_cert_path = getattr(settings, 'CA_CERT_PATH', 'certs/ca_cert.pem')
    path = Path(ca_cert_path)
    if not path.is_absolute():
        path = Path(settings.BASE_DIR) / path
    if not path.exists():
        raise FileNotFoundError(
            f'Certificado de la CA no encontrado en {path}. '
            'Ejecuta: python scripts/init_system.py'
        )
    return path.read_bytes()


def _get_revoked_serials() -> set:
    """Retorna el conjunto de seriales revocados en la BD."""
    return set(
        UserCertificate.objects
        .filter(status=UserCertificate.STATUS_REVOKED)
        .values_list('serial_number', flat=True)
    )


# ── Emisión ─────────────────────────────────────────────────────────────────────

def issue_cert_and_key(collaborator, issued_by) -> UserCertificate:
    """
    Emite un certificado X.509 firmado por la CA para un colaborador.

    SOLO para niveles 1 (admin) y 2 (coordinador).
    La clave privada NO se guarda en la BD — se retorna en UserCertificate.pending_key_pem
    como atributo temporal para que la vista la entregue al usuario.

    Raises:
        PermissionError si el colaborador ya tiene certificado activo.
        ValueError si el rol no permite certificado.
    """
    from crypto_core.certificates import emit_certificate, get_cert_metadata

    # Validar que el nivel de acceso permite certificado
    level = getattr(collaborator, 'access_level', 4)
    if level > 2:
        raise ValueError(
            f'Solo los niveles 1 (admin) y 2 (coordinador) reciben certificados. '
            f'Nivel actual: {level}.'
        )

    existing_cert = getattr(collaborator, 'certificate', None)
    if existing_cert and existing_cert.is_valid:
        raise PermissionError('El colaborador ya tiene un certificado activo.')

    role = 'admin' if level == 1 else 'coordinador'
    area_name = collaborator.area.name if collaborator.area else 'Sin área'

    # Cargar CA
    ca_cert_pem = _get_ca_cert_pem()
    ca_key_encrypted = _load_ca_key_encrypted()
    ca_password = _get_ca_password()

    from crypto_core.ca import load_ca
    ca_cert, ca_key = load_ca(ca_cert_pem, ca_key_encrypted, ca_password)

    cert_pem, private_key_pem = emit_certificate(
        user_id=collaborator.pk,
        username=collaborator.username,
        role=role,
        area=area_name,
        ca_cert=ca_cert,
        ca_key=ca_key,
        valid_days=getattr(settings, 'CERT_EXPIRATION_DAYS', 365),
    )

    metadata = get_cert_metadata(cert_pem)
    expires_at = metadata['expires_at']

    if existing_cert:
        existing_cert.certificate_data = cert_pem.decode('utf-8')
        existing_cert.fingerprint = metadata['fingerprint_sha256']
        existing_cert.serial_number = metadata['serial_number']
        existing_cert.expires_at = expires_at
        existing_cert.is_revoked = False
        existing_cert.revoked_at = None
        existing_cert.revoked_by = None
        existing_cert.status = UserCertificate.STATUS_ACTIVE
        existing_cert.issued_by = issued_by
        existing_cert.key_data = ''  # La clave privada NO se guarda en BD
        existing_cert.save()
        certificate = existing_cert
    else:
        certificate = UserCertificate.objects.create(
            collaborator=collaborator,
            certificate_data=cert_pem.decode('utf-8'),
            fingerprint=metadata['fingerprint_sha256'],
            serial_number=metadata['serial_number'],
            expires_at=expires_at,
            issued_by=issued_by,
            key_data='',  # La clave privada NO se guarda en BD
        )

    AuditLog.objects.create(
        actor=issued_by,
        target=collaborator,
        action='CERTIFICATE_ISSUED',
        details=f'serial={metadata["serial_number"]} fingerprint={metadata["fingerprint_sha256"][:16]}…',
    )

    # Adjuntar la clave privada como atributo temporal (no persiste en BD)
    certificate._pending_private_key_pem = private_key_pem
    return certificate


def _load_ca_key_encrypted() -> str:
    ca_key_path = getattr(settings, 'CA_KEY_PATH', 'certs/ca_key.enc.pem')
    path = Path(ca_key_path)
    if not path.is_absolute():
        path = Path(settings.BASE_DIR) / path
    if not path.exists():
        raise FileNotFoundError(f'Clave de CA cifrada no encontrada en {path}.')
    return path.read_text()


def _get_ca_password() -> str:
    password = os.environ.get('CA_MASTER_PASSWORD')
    if not password:
        raise RuntimeError(
            'CA_MASTER_PASSWORD no está en el entorno. '
            'Esta contraseña es necesaria para emitir certificados.'
        )
    return password


# ── Validación ──────────────────────────────────────────────────────────────────

def validate_cert_and_key(collaborator, cert_pem_bytes: bytes, key_pem_bytes: bytes) -> bool:
    """
    Valida el par certificado/clave privada de un colaborador.

    Verifica:
      1. La clave privada corresponde al certificado.
      2. El certificado está firmado por la CA interna.
      3. El fingerprint coincide con el de la BD.
      4. El certificado no está revocado ni expirado.
    """
    from crypto_core.certificates import (
        verify_certificate, check_key_matches_cert, get_cert_fingerprint,
    )

    try:
        # 1. Verificar par cert/key
        if not check_key_matches_cert(cert_pem_bytes, key_pem_bytes):
            AuditLog.objects.create(
                actor=collaborator, target=collaborator,
                action='CERTIFICATE_VALIDATION_FAILED', details='key_cert_mismatch',
            )
            return False

        # 2. Verificar contra CA
        ca_cert_pem = _get_ca_cert_pem()
        revoked_serials = _get_revoked_serials()
        cert_info = verify_certificate(cert_pem_bytes, ca_cert_pem, revoked_serials)
        if not cert_info['valid']:
            AuditLog.objects.create(
                actor=collaborator, target=collaborator,
                action='CERTIFICATE_VALIDATION_FAILED', details=cert_info['reason'],
            )
            return False

        # 3. Verificar fingerprint contra BD
        try:
            db_cert = collaborator.certificate
        except UserCertificate.DoesNotExist:
            AuditLog.objects.create(
                actor=collaborator, target=collaborator,
                action='CERTIFICATE_VALIDATION_FAILED', details='certificate_missing',
            )
            return False

        uploaded_fp = get_cert_fingerprint(cert_pem_bytes)
        if uploaded_fp != db_cert.fingerprint:
            AuditLog.objects.create(
                actor=collaborator, target=collaborator,
                action='CERTIFICATE_VALIDATION_FAILED', details='fingerprint_mismatch',
            )
            return False

        AuditLog.objects.create(
            actor=collaborator, target=collaborator,
            action='CERTIFICATE_VALIDATED', details=db_cert.fingerprint[:16] + '…',
        )
        return True

    except Exception as exc:
        AuditLog.objects.create(
            actor=collaborator, target=collaborator,
            action='CERTIFICATE_VALIDATION_FAILED', details=f'exception:{str(exc)[:120]}',
        )
        return False


# ── Revocación ──────────────────────────────────────────────────────────────────

def revoke_certificate(certificate: UserCertificate, reason: str, revoked_by) -> None:
    """
    Revoca un certificado. Solo admin (nivel 1) puede revocar.
    """
    certificate.is_revoked = True
    certificate.revoked_at = timezone.now()
    certificate.revoked_by = revoked_by
    certificate.status = UserCertificate.STATUS_REVOKED
    certificate.revocation_reason = reason
    certificate.save()

    AuditLog.objects.create(
        actor=revoked_by,
        target=certificate.collaborator,
        action='CERTIFICATE_REVOKED',
        details=f'reason={reason} serial={certificate.serial_number}',
    )


# ── Descarga de clave privada ────────────────────────────────────────────────────

def get_coordinator_key_bytes(certificate: UserCertificate) -> bytes:
    """
    Retorna los bytes de la clave privada si están disponibles como atributo temporal.
    La clave privada NO se guarda en BD — solo está disponible justo después de la emisión.
    """
    pending_key = getattr(certificate, '_pending_private_key_pem', None)
    if pending_key:
        return pending_key
    raise ValueError(
        'La clave privada ya no está disponible. '
        'Solo se puede descargar inmediatamente después de emitir el certificado. '
        'Si se perdió, revoca el certificado y emite uno nuevo.'
    )


# ── Compatibilidad con código legacy ────────────────────────────────────────────

# Alias para código existente que usa estos nombres
validate_coordinator_cert_and_key = validate_cert_and_key
issue_coordinator_key_cert = issue_cert_and_key


def issue_encrypted_certificate(collaborator, issued_by):
    """
    OBSOLETO — los niveles 3 y 4 no reciben certificados.

    En la arquitectura correcta SOLO niveles 1 (admin) y 2 (coordinador) tienen
    certificados X.509. Los niveles 3 y 4 se autentican solo con usuario y contraseña.

    Raises PermissionError para impedir la emisión incorrecta.
    """
    level = getattr(collaborator, 'access_level', 4)
    raise PermissionError(
        f'El colaborador "{collaborator.username}" tiene nivel de acceso {level}. '
        'Solo los niveles 1 (admin) y 2 (coordinador) pueden recibir certificados digitales. '
        'Los niveles 3 y 4 se autentican únicamente con usuario y contraseña.'
    )


def validate_encrypted_certificate(collaborator, encrypted_str: str) -> bool:
    """
    OBSOLETO — validaba el formato de certificado cifrado AES-GCM propietario (legado).

    El nuevo sistema usa certificados X.509 firmados por la CA interna.
    Para validar un certificado X.509 actual, usa validate_cert_and_key().

    Retorna False siempre y registra en AuditLog el uso de formato obsoleto.
    """
    AuditLog.objects.create(
        actor=collaborator,
        target=collaborator,
        action='CERTIFICATE_VALIDATION_FAILED',
        details='formato_obsoleto: validate_encrypted_certificate fue llamado. Migrar a validate_cert_and_key.',
    )
    return False


def extract_cert_serial_number(certificate_data: str) -> str:
    """Extrae el número de serie X.509 de un certificado PEM."""
    if not certificate_data or not certificate_data.strip().startswith('-----BEGIN CERTIFICATE-----'):
        return ''
    try:
        from crypto_core.certificates import get_cert_metadata
        metadata = get_cert_metadata(certificate_data.encode('utf-8'))
        return metadata['serial_number']
    except Exception:
        return ''


# ── Funciones legacy eliminadas ─────────────────────────────────────────────────
# Las siguientes funciones han sido ELIMINADAS porque eran incorrectas:
#
# ✗ issue_encrypted_certificate   — usaba AES-GCM sobre JSON de usuario (no X.509 real)
# ✗ validate_encrypted_certificate — validaba un cifrado propietario, no una firma X.509
# ✗ encrypt_certificate / decrypt_certificate — cifrado de payload, no certificado real
# ✗ generate_coordinator_key_cert — generaba certs AUTO-FIRMADOS (sin CA)
# ✗ _encrypt_bytes / _decrypt_bytes — guardaba la clave privada en BD (prohibido)
# ✗ _get_encryption_key — derivaba clave de SHA-256 del SECRET_KEY (débil)
#
# Usa issue_cert_and_key / validate_cert_and_key en su lugar.
