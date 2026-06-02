"""
Hashing SHA-256 para verificación de integridad.

NO confundir con contraseñas — eso es bcrypt/Django's make_password.
Estos hashes son para documentos y snapshots de BD.
"""

import hashlib
import json
from typing import Optional


def hash_document(content: bytes) -> str:
    """SHA-256 del contenido de un documento. Retorna hex string."""
    return hashlib.sha256(content).hexdigest()


def verify_document_integrity(content: bytes, expected_hash: str) -> bool:
    """Verifica que el contenido produce el hash esperado."""
    return hashlib.sha256(content).hexdigest() == expected_hash.lower()


def hash_string(text: str) -> str:
    """SHA-256 de un string UTF-8. Para hashing de campos individuales."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def hash_db_state(tables_data: dict) -> str:
    """
    SHA-256 de un snapshot canónico de las tablas críticas de la BD.

    Args:
        tables_data — dict con nombre_tabla → lista de dicts con los registros
                      (ordenados por PK para determinismo)

    Ejemplo de uso con Django ORM:
        from registros.models import MigrantRegistration
        from iam.models import UserCertificate
        tables = {
            'migrant_registrations': list(
                MigrantRegistration.objects
                .filter(is_deleted=False)
                .values('id', 'internal_id', 'created_at')
                .order_by('id')
            ),
            'certificates': list(
                UserCertificate.objects.values('id', 'fingerprint', 'status').order_by('id')
            ),
        }
        db_hash = hash_db_state(tables)
    """
    canonical = json.dumps(
        {k: sorted(v, key=lambda x: x.get('id', 0)) for k, v in sorted(tables_data.items())},
        sort_keys=True,
        separators=(',', ':'),
        ensure_ascii=False,
        default=str,
    )
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def hash_db_state_django() -> str:
    """
    Calcula el hash de integridad del estado actual de la BD via Django ORM.
    Importa los modelos lazy para evitar AppRegistryNotReady.
    """
    from django.apps import apps

    critical_models = []

    try:
        MigrantReg = apps.get_model('registros', 'MigrantRegistration')
        critical_models.append((
            'migrant_registrations',
            MigrantReg.objects.filter(is_deleted=False)
                              .values('id', 'internal_id', 'created_at', 'updated_at')
                              .order_by('id'),
        ))
    except LookupError:
        pass

    try:
        UserCert = apps.get_model('iam', 'UserCertificate')
        critical_models.append((
            'certificates',
            UserCert.objects.values('id', 'fingerprint', 'status', 'issued_at')
                            .order_by('id'),
        ))
    except LookupError:
        pass

    try:
        ActionSig = apps.get_model('registros', 'ActionSignature')
        critical_models.append((
            'action_signatures',
            ActionSig.objects.values('id', 'message_hash', 'chain_position')
                             .order_by('id'),
        ))
    except LookupError:
        pass

    tables_data = {name: list(qs) for name, qs in critical_models}
    return hash_db_state(tables_data)


def hash_signed_log_entry(log_data: dict, signature_b64: str) -> str:
    """Hash canónico de un log firmado (para encadenamiento)."""
    entry = {
        'log_data': log_data,
        'signature_b64': signature_b64,
    }
    canonical = json.dumps(entry, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
