"""
Cifrado AES-256-GCM para datos personales sensibles en la base de datos.

La clave AES está derivada de una master_password con PBKDF2-HMAC-SHA256
(600,000 iteraciones, conforme a OWASP 2023).

Formato en BD: base64url(salt_16 + nonce_12 + tag_16 + ciphertext)
El tag de GCM está implícito en el ciphertext de AESGCM de la librería
cryptography (los últimos 16 bytes del output de encrypt() son el tag).
"""

import base64
import os
import secrets
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 600_000
KEY_LENGTH = 32       # AES-256
SALT_LENGTH = 16
NONCE_LENGTH = 12     # GCM estándar

SENSITIVE_FIELDS = [
    'nombre_completo', 'full_name',
    'fecha_nacimiento', 'birth_date',
    'nacionalidad', 'nationality',
    'numero_documento', 'document_number',
    'telefono', 'phone',
    'correo_electronico', 'email',
    'direccion',
    'condicion_migratoria', 'current_legal_status',
    'notas_psicosociales', 'notas_legales', 'notas_humanitarias',
    'observations', 'migration_reason',
    'emergency_contact_name', 'emergency_contact_phone',
    'emergency_contact_relationship',
]

NON_SENSITIVE_FIELDS = [
    'id', 'pk',
    'created_at', 'updated_at', 'deleted_at',
    'is_deleted', 'is_active',
    'role', 'access_level', 'area',
    'status', 'state',
    'internal_id', 'folio',
]


def derive_key(master_password: str, salt: bytes) -> bytes:
    """
    Deriva una clave AES-256 desde la contraseña maestra con PBKDF2-HMAC-SHA256.
    600,000 iteraciones conforme a OWASP 2023.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(master_password.encode('utf-8'))


def _get_or_derive_key(key_or_password) -> bytes:
    """Acepta tanto una clave de 32 bytes como una contraseña string."""
    if isinstance(key_or_password, bytes) and len(key_or_password) == KEY_LENGTH:
        return key_or_password
    raise TypeError(
        "Se requiere una clave de 32 bytes derivada con derive_key(). "
        "Nunca pases la contraseña directamente a encrypt/decrypt."
    )


def encrypt_field(plaintext: str, key: bytes) -> str:
    """
    Cifra un campo sensible con AES-256-GCM.

    Formato de salida (base64url): salt(16) + nonce(12) + ciphertext+tag
    El salt permite re-derivar la clave si se usa derive_key() por campo.
    Si ya tienes una clave derivada, el salt es un nonce de diferenciación.

    Returns:
        String base64url listo para guardar en la BD.
    """
    key = _get_or_derive_key(key)
    nonce = secrets.token_bytes(NONCE_LENGTH)
    ciphertext_with_tag = AESGCM(key).encrypt(nonce, plaintext.encode('utf-8'), None)
    return base64.urlsafe_b64encode(nonce + ciphertext_with_tag).decode('ascii')


def decrypt_field(encrypted_b64: str, key: bytes) -> str:
    """
    Descifra un campo cifrado con encrypt_field().
    Verifica el GCM tag automáticamente (autenticación incluida).

    Raises:
        ValueError si el tag no coincide (tampering) o el formato es inválido.
    """
    key = _get_or_derive_key(key)
    try:
        raw = base64.urlsafe_b64decode(encrypted_b64.encode('ascii'))
        nonce = raw[:NONCE_LENGTH]
        ciphertext_with_tag = raw[NONCE_LENGTH:]
        plaintext = AESGCM(key).decrypt(nonce, ciphertext_with_tag, None)
        return plaintext.decode('utf-8')
    except InvalidTag:
        raise ValueError('Autenticación AES-GCM fallida: los datos pueden haber sido manipulados.')
    except Exception as exc:
        raise ValueError(f'Error al descifrar campo: {exc}') from exc


def encrypt_dict_fields(data: dict, key: bytes, fields: list = None) -> dict:
    """
    Cifra solo los campos sensibles de un dict. Los demás quedan intactos.
    Si fields es None, usa SENSITIVE_FIELDS.
    """
    target_fields = set(fields or SENSITIVE_FIELDS)
    result = {}
    for k, v in data.items():
        if k in target_fields and v is not None and v != '':
            result[k] = encrypt_field(str(v), key)
        else:
            result[k] = v
    return result


def decrypt_dict_fields(data: dict, key: bytes, fields: list = None) -> dict:
    """Descifra los campos sensibles de un dict."""
    target_fields = set(fields or SENSITIVE_FIELDS)
    result = {}
    for k, v in data.items():
        if k in target_fields and v is not None and v != '':
            try:
                result[k] = decrypt_field(str(v), key)
            except ValueError:
                result[k] = '[ERROR DE DESCIFRADO]'
        else:
            result[k] = v
    return result


def get_encryption_key_from_env() -> bytes:
    """
    Obtiene la clave de cifrado desde la variable de entorno DB_ENCRYPTION_MASTER_PASSWORD.
    Usa un salt fijo por instalación (guardado en DB_ENCRYPTION_SALT).

    IMPORTANTE: En producción, DB_ENCRYPTION_MASTER_PASSWORD debe ser un secreto seguro,
    NO el SECRET_KEY de Django ni nada derivado de él.
    """
    import os
    master_password = os.environ.get('DB_ENCRYPTION_MASTER_PASSWORD')
    if not master_password:
        raise RuntimeError(
            'DB_ENCRYPTION_MASTER_PASSWORD no está configurada. '
            'Genera una con: python -c "import secrets; print(secrets.token_hex(32))"'
        )
    salt_hex = os.environ.get('DB_ENCRYPTION_SALT')
    if not salt_hex:
        raise RuntimeError(
            'DB_ENCRYPTION_SALT no está configurada. '
            'Genera una con: python -c "import secrets; print(secrets.token_hex(16))"'
        )
    salt = bytes.fromhex(salt_hex)
    return derive_key(master_password, salt)
