"""
Servicios criptográficos para el módulo registros.

TODA la criptografía delega a crypto_core.
Este módulo mantiene la API existente para no romper las vistas/workflow actuales,
pero corrige los problemas críticos identificados en la auditoría:

PROBLEMAS CORREGIDOS:
  1. La firma ECDSA global ya no existe — se usa crypto_core.signatures para flujos finales.
  2. sign_action verifica que el firmante sea nivel 1 o 2 antes de firmar.
  3. El hash-chain existente se mantiene para trazabilidad, pero ya no es la única fuente de firma.
  4. Se agrega sign_final_flow() como nueva función principal para flujos finales.

PRESERVADO (compatibilidad):
  - sign_action / verify_action_signature / verify_action_chain / batch_sign_actions
    mantienen su API para no romper las vistas existentes, pero ahora verifican el nivel.
  - get_public_key_pem() sigue funcionando para mostrar la clave del servidor en el panel.
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from django.conf import settings
from django.utils import timezone

# ── Importaciones de crypto_core (única fuente de criptografía) ───────────────
from crypto_core.signatures import (
    FinalFlowAction,
    SignedLog,
    build_log_data,
    sign_final_flow_log as _core_sign_final_flow,
    verify_signed_log_from_db,
)
from crypto_core.hashing import hash_db_state_django

CURVE = ec.SECP256K1()
CURVE_NAME = 'secp256k1'

# Niveles de acceso que pueden firmar acciones con la clave del servidor
# NOTA: La firma con clave de servidor es para el hash-chain de trazabilidad,
#       NO para flujos finales. Los flujos finales usan crypto_core.signatures.
SIGNING_LEVELS = {1, 2}  # solo admin y coordinador


# ── Gestión de la clave ECDSA del servidor (para hash-chain legacy) ───────────

def _key_path() -> Path:
    configured = getattr(settings, 'ECC_PRIVATE_KEY_PATH', '')
    if configured:
        return Path(configured)
    return Path(settings.BASE_DIR) / 'ecc_signing_key.pem'


def _load_or_generate_private_key():
    path = _key_path()
    if path.exists():
        with open(path, 'rb') as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)
    private_key = ec.generate_private_key(CURVE)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, 'wb') as fh:
        fh.write(pem)
    os.chmod(path, 0o600)
    return private_key


def get_public_key_pem() -> str:
    return _load_or_generate_private_key().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')


def _sign_bytes(payload: bytes) -> Dict[str, str]:
    private_key = _load_or_generate_private_key()
    message_hash = hashlib.sha256(payload).hexdigest()
    der_sig = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    return {
        'message_hash': message_hash,
        'signature_r': str(r),
        'signature_s': str(s),
        'public_key': pub_pem,
        'curve_name': CURVE_NAME,
    }


def _verify_bytes(payload: bytes, message_hash: str, r: int, s: int, pub_pem: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(pub_pem.encode('utf-8'))
        der_sig = encode_dss_signature(r, s)
        public_key.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
        computed = hashlib.sha256(payload).hexdigest()
        return computed == message_hash
    except (InvalidSignature, Exception):
        return False


# ── MigrantRegistration signing ───────────────────────────────────────────────

def _canonical_payload(registration) -> bytes:
    data = {
        'id': registration.pk,
        'internal_id': registration.internal_id,
        'full_name': registration.full_name,
        'birth_date': str(registration.birth_date),
        'gender': registration.gender,
        'nationality': registration.nationality,
        'country_of_origin': registration.country_of_origin,
        'document_type': registration.document_type,
        'document_number': registration.document_number,
        'phone': registration.phone,
        'email': registration.email,
        'entry_date': str(registration.entry_date),
        'entry_point': registration.entry_point,
        'transit_countries': registration.transit_countries,
        'intended_destination': registration.intended_destination,
        'marital_status': registration.marital_status,
        'travels_alone': registration.travels_alone,
        'group_size': registration.group_size,
        'minors_in_group': registration.minors_in_group,
        'assistance_requested': registration.assistance_requested,
        'migration_reason': registration.migration_reason,
        'current_legal_status': registration.current_legal_status,
        'shelter_name': registration.shelter_name,
        'emergency_contact_name': registration.emergency_contact_name,
        'emergency_contact_phone': registration.emergency_contact_phone,
        'emergency_contact_relationship': registration.emergency_contact_relationship,
        'observations': registration.observations,
        'created_by_id': registration.created_by_id,
        'created_by_role': registration.created_by_role,
        'created_at': registration.created_at.isoformat(),
    }
    return json.dumps(data, sort_keys=True, ensure_ascii=False).encode('utf-8')


def sign_registration(registration) -> dict:
    payload = _canonical_payload(registration)
    return _sign_bytes(payload)


def verify_registration(registration, signature_obj) -> dict:
    payload = _canonical_payload(registration)
    computed_hash = hashlib.sha256(payload).hexdigest()
    is_valid = False
    error = None
    try:
        r = int(signature_obj.signature_r)
        s = int(signature_obj.signature_s)
        is_valid = _verify_bytes(payload, signature_obj.message_hash, r, s, signature_obj.public_key)
        if not is_valid:
            error = 'hash_mismatch_or_invalid_signature'
    except Exception as exc:
        error = str(exc)

    return {
        'is_valid': is_valid,
        'error': error,
        'curve': signature_obj.curve_name,
        'signed_at': signature_obj.signed_at,
        'signed_by': str(signature_obj.signed_by),
        'message_hash': computed_hash,
        'stored_hash': signature_obj.message_hash,
    }


# ── General ActionSignature con hash chain ────────────────────────────────────

def _get_last_chain_entry():
    from .models import ActionSignature
    return ActionSignature.objects.order_by('-chain_position', '-id').first()


def _build_action_payload(subject_type: str, subject_id: int, extra: dict, prev_hash: str) -> bytes:
    data = {
        'subject_type': subject_type,
        'subject_id': subject_id,
        'prev_chain_hash': prev_hash,
        **{k: v for k, v in sorted(extra.items())},
    }
    return json.dumps(data, sort_keys=True, ensure_ascii=False).encode('utf-8')


def sign_action(subject_type: str, subject_id: int, extra: dict, signer, batch=None):
    """
    Firma una acción genérica con el hash-chain del servidor.

    RESTRICCIÓN CORREGIDA: Solo nivel 1 (admin) y 2 (coordinador) pueden firmar.
    Un operativo o externo que intente firmar recibirá un PermissionError.
    """
    from .models import ActionSignature

    # CORRECCIÓN: verificar que el firmante tiene nivel de acceso permitido
    signer_level = getattr(signer, 'access_level', 4)
    if signer_level not in SIGNING_LEVELS:
        raise PermissionError(
            f'Solo los niveles 1 (admin) y 2 (coordinador) pueden firmar acciones. '
            f'Nivel actual: {signer_level}.'
        )

    last = _get_last_chain_entry()
    prev_hash = last.chain_hash() if last else ''
    chain_pos = (last.chain_position + 1) if last else 0

    payload = _build_action_payload(subject_type, subject_id, extra, prev_hash)
    sig_data = _sign_bytes(payload)

    return ActionSignature.objects.create(
        subject_type=subject_type,
        subject_id=subject_id,
        message_hash=sig_data['message_hash'],
        signature_r=sig_data['signature_r'],
        signature_s=sig_data['signature_s'],
        public_key=sig_data['public_key'],
        curve_name=sig_data['curve_name'],
        prev_chain_hash=prev_hash,
        chain_position=chain_pos,
        signed_by=signer,
        signed_by_role=signer.access_level,
        batch=batch,
    )


def verify_action_signature(action_sig) -> dict:
    extra = {}
    payload = _build_action_payload(
        action_sig.subject_type,
        action_sig.subject_id,
        extra,
        action_sig.prev_chain_hash,
    )
    r = int(action_sig.signature_r)
    s = int(action_sig.signature_s)
    is_valid = _verify_bytes(payload, action_sig.message_hash, r, s, action_sig.public_key)
    return {
        'is_valid': is_valid,
        'chain_position': action_sig.chain_position,
        'prev_chain_hash': action_sig.prev_chain_hash,
        'signed_by': str(action_sig.signed_by),
        'signed_at': action_sig.signed_at,
    }


def verify_action_chain(start_position: int = 0, count: int = 100) -> List[dict]:
    from .models import ActionSignature

    entries = list(
        ActionSignature.objects
        .filter(chain_position__gte=start_position)
        .order_by('chain_position', 'id')[:count]
    )
    results = []
    prev_hash = ''
    for sig in entries:
        sig_ok = verify_action_signature(sig)
        chain_ok = (sig.prev_chain_hash == prev_hash)
        results.append({
            'id': sig.pk,
            'chain_position': sig.chain_position,
            'subject': f'{sig.subject_type}:{sig.subject_id}',
            'signature_valid': sig_ok['is_valid'],
            'chain_intact': chain_ok,
            'signed_by': str(sig.signed_by),
            'signed_at': sig.signed_at,
        })
        prev_hash = sig.chain_hash()
    return results


def batch_sign_actions(items: List[dict], signer, ip_address: str = None):
    """
    Firma múltiples acciones en una sola llamada.

    RESTRICCIÓN CORREGIDA: Solo nivel 1 y 2 pueden usar firma masiva.
    """
    from .models import BatchSignSession

    signer_level = getattr(signer, 'access_level', 4)
    if signer_level not in SIGNING_LEVELS:
        raise PermissionError(
            f'Solo los niveles 1 (admin) y 2 (coordinador) pueden firmar en lote. '
            f'Nivel actual: {signer_level}.'
        )

    sigs = []
    batch = BatchSignSession.objects.create(
        signed_by=signer,
        ip_address=ip_address,
        item_count=len(items),
        batch_root_hash='pending',
    )

    for item in items:
        sig = sign_action(
            subject_type=item['subject_type'],
            subject_id=item['subject_id'],
            extra=item.get('extra', {}),
            signer=signer,
            batch=batch,
        )
        sigs.append(sig)

    sorted_hashes = sorted(s.message_hash for s in sigs)
    root_hash = hashlib.sha256('|'.join(sorted_hashes).encode('utf-8')).hexdigest()
    batch.batch_root_hash = root_hash
    batch.save(update_fields=['batch_root_hash'])

    return batch, sigs


# ── Flujos finales con certificado X.509 (NUEVA funcionalidad) ────────────────

def sign_final_flow(
    action: FinalFlowAction,
    performed_by,
    target_id: int,
    target_type: str,
    cert_pem: bytes,
    private_key_pem: bytes,
    details: dict = None,
) -> Optional['SignedFlowLog']:
    """
    Firma un flujo final con el certificado X.509 del admin/coordinador.

    Persiste el log firmado en la BD (tabla SignedFlowLog).
    Esta es la función correcta para flujos irreversibles.

    Args:
        action           — FinalFlowAction enum
        performed_by     — Collaborator que ejecuta la acción
        target_id        — ID del registro/usuario afectado
        target_type      — tipo del target ('migrant_registration', 'collaborator', etc.)
        cert_pem         — certificado X.509 del firmante (bytes PEM)
        private_key_pem  — clave privada del firmante (bytes PEM, nunca se guarda)
        details          — contexto adicional de la acción

    Returns:
        SignedFlowLog guardado en BD, o None si falla.

    Raises:
        PermissionError si el certificado no es válido o el usuario no tiene nivel correcto.
    """
    from iam.certificates import _get_ca_cert_pem, _get_revoked_serials
    from .models import SignedFlowLog

    signer_level = getattr(performed_by, 'access_level', 4)
    if signer_level not in SIGNING_LEVELS:
        raise PermissionError(
            f'Solo niveles 1 y 2 pueden firmar flujos finales. Nivel: {signer_level}.'
        )

    ca_cert_pem = _get_ca_cert_pem()
    revoked_serials = _get_revoked_serials()
    system_hash = hash_db_state_django()

    log_data = build_log_data(
        action=action,
        performed_by_user_id=performed_by.pk,
        performed_by_username=performed_by.username,
        target_id=target_id,
        target_type=target_type,
        details=details or {},
        system_hash=system_hash,
    )

    signed = _core_sign_final_flow(
        log_data=log_data,
        private_key_pem=private_key_pem,
        cert_pem=cert_pem,
        ca_cert_pem=ca_cert_pem,
        revoked_serials=revoked_serials,
    )

    db_log = SignedFlowLog.objects.create(
        action=action.value,
        log_data_json=json.dumps(log_data, sort_keys=True, separators=(',', ':'), ensure_ascii=False),
        signature_b64=signed.signature_b64,
        cert_fingerprint=signed.cert_fingerprint,
        signer_user_id=performed_by.pk,
        target_id=target_id,
        target_type=target_type,
        is_verified=True,
    )
    return db_log


def verify_final_flow_log(signed_flow_log) -> tuple:
    """
    Re-verifica un SignedFlowLog guardado en BD.

    Retorna (is_valid: bool, reason: str).
    """
    from iam.certificates import _get_ca_cert_pem, _get_revoked_serials
    from iam.models import UserCertificate

    ca_cert_pem = _get_ca_cert_pem()
    revoked_serials = _get_revoked_serials()

    # Obtener el PEM del certificado del firmante desde la BD
    try:
        signer_cert = UserCertificate.objects.get(
            collaborator_id=signed_flow_log.signer_user_id,
        )
        cert_pem = signer_cert.certificate_data.encode('utf-8')
    except UserCertificate.DoesNotExist:
        return False, 'signer_certificate_not_found'

    return verify_signed_log_from_db(
        log_data_json=signed_flow_log.log_data_json,
        signature_b64=signed_flow_log.signature_b64,
        cert_pem=cert_pem,
        ca_cert_pem=ca_cert_pem,
        revoked_serials=revoked_serials,
    )
