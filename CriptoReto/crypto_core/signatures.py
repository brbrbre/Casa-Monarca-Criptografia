"""
Firma digital de logs de flujos finales.

Un "flujo final" es una acción irreversible o crítica:
  - Aceptar/rechazar registro de usuario
  - Eliminar registro (soft delete con trazabilidad)
  - Procesar solicitudes ARCO
  - Autorizar documentos internos
  - Revocar acceso de un colaborador

SOLO admin (nivel 1) y coordinador (nivel 2) pueden firmar.
La firma es sobre el contenido del log, no sobre datos crudos de usuario.
"""

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone as dt_timezone
from enum import Enum
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

from .certificates import verify_certificate, get_cert_fingerprint

PRIVILEGED_ROLES = ('admin', 'coordinador')


class FinalFlowAction(Enum):
    ACCEPT_USER_REGISTRATION = 'accept_user_registration'
    REJECT_USER_REGISTRATION = 'reject_user_registration'
    DELETE_RECORD = 'delete_record'
    PROCESS_ARCO_ACCESS = 'process_arco_access'
    PROCESS_ARCO_RECTIFICATION = 'process_arco_rectification'
    PROCESS_ARCO_CANCELLATION = 'process_arco_cancellation'
    PROCESS_ARCO_OPPOSITION = 'process_arco_opposition'
    AUTHORIZE_DOCUMENT = 'authorize_document'
    REVOKE_USER_ACCESS = 'revoke_user_access'

    @classmethod
    def values(cls):
        return {m.value for m in cls}


@dataclass
class SignedLog:
    log_data: dict
    signature_b64: str
    cert_fingerprint: str
    cert_pem: bytes
    verified: bool = True
    error: Optional[str] = None


def _canonical_json(data: dict) -> bytes:
    """Serialización canónica: sort_keys=True, sin espacios, sin BOM."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _get_role_from_cert(cert_pem: bytes) -> str:
    """
    El role NO se guarda en el certificado X.509 estándar.
    Esta función es un hook para que la capa de aplicación pueda inyectarlo.
    Por defecto devuelve '' — la validación real ocurre en la capa de servicio Django.
    """
    return ''


def sign_final_flow_log(
    log_data: dict,
    private_key_pem: bytes,
    cert_pem: bytes,
    ca_cert_pem: bytes,
    revoked_serials: set = None,
) -> SignedLog:
    """
    Firma un log de flujo final con la clave privada del admin/coordinador.

    Args:
        log_data         — dict con la acción, quién la realiza, el target, etc.
        private_key_pem  — clave privada RSA del firmante (NO se guarda en servidor)
        cert_pem         — certificado X.509 del firmante
        ca_cert_pem      — certificado de la CA para verificar el cert del firmante
        revoked_serials  — seriales revocados en BD (para rechazar certs revocados)

    Raises:
        ValueError si la acción no es un flujo final válido
        PermissionError si el certificado no es válido o está revocado
    """
    action = log_data.get('action', '')
    if action not in FinalFlowAction.values():
        raise ValueError(
            f"Acción '{action}' no es un flujo final válido. "
            f"Acciones permitidas: {sorted(FinalFlowAction.values())}"
        )

    # Verificar certificado del firmante contra la CA
    cert_info = verify_certificate(cert_pem, ca_cert_pem, revoked_serials)
    if not cert_info['valid']:
        raise PermissionError(
            f"Certificado inválido o revocado: {cert_info['reason']}"
        )

    # Serializar log de forma canónica y firmar
    payload = _canonical_json(log_data)
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

    signature = private_key.sign(payload, padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH,
    ), hashes.SHA256())

    signature_b64 = base64.b64encode(signature).decode('ascii')
    cert_fingerprint = get_cert_fingerprint(cert_pem)

    return SignedLog(
        log_data=log_data,
        signature_b64=signature_b64,
        cert_fingerprint=cert_fingerprint,
        cert_pem=cert_pem,
        verified=True,
    )


def verify_signed_log(signed_log: SignedLog, ca_cert_pem: bytes, revoked_serials: set = None) -> bool:
    """
    Verifica la firma de un SignedLog contra la CA.

    Retorna True si la firma es válida, False con razón en signed_log.error.
    """
    try:
        cert_info = verify_certificate(signed_log.cert_pem, ca_cert_pem, revoked_serials)
        if not cert_info['valid']:
            signed_log.error = f'cert_invalid: {cert_info["reason"]}'
            signed_log.verified = False
            return False

        cert = load_pem_x509_certificate(signed_log.cert_pem)
        public_key = cert.public_key()

        payload = _canonical_json(signed_log.log_data)
        signature = base64.b64decode(signed_log.signature_b64)

        public_key.verify(
            signature,
            payload,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        signed_log.verified = True
        signed_log.error = None
        return True

    except InvalidSignature:
        signed_log.error = 'firma_invalida'
        signed_log.verified = False
        return False
    except Exception as exc:
        signed_log.error = f'error: {str(exc)[:120]}'
        signed_log.verified = False
        return False


def verify_signed_log_from_db(
    log_data_json: str,
    signature_b64: str,
    cert_pem: bytes,
    ca_cert_pem: bytes,
    revoked_serials: set = None,
) -> tuple:
    """
    Verifica un log firmado directamente desde los datos de la BD.

    Retorna (is_valid: bool, reason: str)
    """
    try:
        log_data = json.loads(log_data_json)
    except json.JSONDecodeError:
        return False, 'log_data_json_invalido'

    signed_log = SignedLog(
        log_data=log_data,
        signature_b64=signature_b64,
        cert_fingerprint=get_cert_fingerprint(cert_pem) if cert_pem else '',
        cert_pem=cert_pem,
    )
    is_valid = verify_signed_log(signed_log, ca_cert_pem, revoked_serials)
    return is_valid, signed_log.error or 'ok'


def build_log_data(
    action: FinalFlowAction,
    performed_by_user_id: int,
    performed_by_username: str,
    target_id: int,
    target_type: str,
    details: dict = None,
    system_hash: str = '',
) -> dict:
    """
    Construye el dict de log_data con el formato canónico requerido.
    """
    return {
        'action': action.value,
        'timestamp': datetime.now(dt_timezone.utc).isoformat(),
        'performed_by_user_id': performed_by_user_id,
        'performed_by_username': performed_by_username,
        'target_id': target_id,
        'target_type': target_type,
        'details': details or {},
        'system_hash': system_hash,
    }
