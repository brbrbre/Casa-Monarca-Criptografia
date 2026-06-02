"""
Gestión de certificados X.509 para Casa Monarca.

Emite y gestiona certificados SOLO para admin (nivel 1) y coordinador (nivel 2).
Los operativos (nivel 3) y externos (nivel 4) NO reciben certificados.

La clave privada del usuario NUNCA se guarda en la BD.
"""

import hashlib
from datetime import datetime, timezone as dt_timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
)
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

PRIVILEGED_ROLES = ('admin', 'coordinador')
CERT_VALID_DAYS_DEFAULT = 365


def emit_certificate(
    user_id: int,
    username: str,
    role: str,
    area: str,
    ca_cert,
    ca_key,
    valid_days: int = CERT_VALID_DAYS_DEFAULT,
) -> tuple:
    """
    Emite un certificado X.509 firmado por la CA interna.

    Solo roles 'admin' y 'coordinador' pueden recibir certificados.

    Retorna:
        (cert_pem: bytes, private_key_pem: bytes)

    La clave privada NO se guarda en la BD — el llamador debe entregarla al usuario.

    Raises:
        ValueError si el rol no es admin o coordinador.
    """
    if role not in PRIVILEGED_ROLES:
        raise ValueError(
            f"Solo los roles {PRIVILEGED_ROLES} pueden recibir certificados. "
            f"Rol '{role}' no permitido."
        )

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    now = datetime.now(dt_timezone.utc)
    expires = now + timedelta(days=valid_days)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'MX'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Monterrey'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Casa Monarca'),
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
        .add_extension(
            x509.SubjectAlternativeName([
                x509.OtherName(
                    x509.ObjectIdentifier('1.2.840.113549.1.9.1'),
                    b'\x16' + len(str(user_id)).to_bytes(1, 'big') + str(user_id).encode(),
                ),
            ]),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(Encoding.PEM)
    private_key_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    return cert_pem, private_key_pem


def get_cert_metadata(cert_pem: bytes) -> dict:
    """
    Extrae metadatos del certificado PEM para guardar en la BD.

    Retorna:
        {serial_number, fingerprint_sha256, issued_at, expires_at, subject}
    """
    cert = load_pem_x509_certificate(cert_pem)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    subject = {attr.oid.dotted_string: attr.value for attr in cert.subject}
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    serial_attr = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)
    return {
        'serial_number': format(cert.serial_number, 'x').upper(),
        'fingerprint_sha256': fingerprint,
        'issued_at': cert.not_valid_before_utc,
        'expires_at': cert.not_valid_after_utc,
        'common_name': cn[0].value if cn else '',
        'user_id_from_cert': serial_attr[0].value if serial_attr else '',
    }


def verify_certificate(cert_pem: bytes, ca_cert_pem: bytes, revoked_serials: set = None) -> dict:
    """
    Verifica un certificado X.509 contra la CA interna.

    Args:
        cert_pem          — certificado a verificar (PEM bytes)
        ca_cert_pem       — certificado de la CA (PEM bytes)
        revoked_serials   — conjunto de serial_numbers (hex strings) revocados en BD

    Retorna:
        {valid: bool, reason: str, subject: dict, expires: datetime, role: str, user_id: str}
    """
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import padding

    result = {'valid': False, 'reason': '', 'subject': {}, 'expires': None, 'role': '', 'user_id': ''}

    try:
        cert = load_pem_x509_certificate(cert_pem)
        ca_cert = load_pem_x509_certificate(ca_cert_pem)

        # Verificar firma de la CA — soporta tanto RSA como ECDSA
        try:
            ca_public_key = ca_cert.public_key()
            from cryptography.hazmat.primitives.asymmetric import ec as _ec
            if isinstance(ca_public_key, _ec.EllipticCurvePublicKey):
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    _ec.ECDSA(cert.signature_hash_algorithm),
                )
            else:
                ca_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
        except (InvalidSignature, Exception):
            result['reason'] = 'firma_ca_invalida'
            return result

        # Verificar vigencia
        now = datetime.now(dt_timezone.utc)
        if now < cert.not_valid_before_utc:
            result['reason'] = 'certificado_aun_no_valido'
            return result
        if now > cert.not_valid_after_utc:
            result['reason'] = 'certificado_expirado'
            return result

        # Verificar revocación
        serial_hex = format(cert.serial_number, 'x').upper()
        if revoked_serials and serial_hex in revoked_serials:
            result['reason'] = 'certificado_revocado'
            return result

        # Extraer subject
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        ou_attrs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATIONAL_UNIT_NAME)
        serial_attrs = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)

        username = cn_attrs[0].value if cn_attrs else ''
        area = ou_attrs[0].value if ou_attrs else ''
        user_id = serial_attrs[0].value if serial_attrs else ''

        # El role se determina por lo que está guardado en la BD (no en el cert)
        # Aquí devolvemos los datos del subject para que la capa de servicio valide
        result.update({
            'valid': True,
            'reason': 'ok',
            'subject': {
                'CN': username,
                'OU': area,
                'serialNumber': user_id,
            },
            'expires': cert.not_valid_after_utc,
            'user_id': user_id,
            'serial_number': serial_hex,
        })
        return result

    except Exception as exc:
        result['reason'] = f'error: {str(exc)[:120]}'
        return result


def get_cert_fingerprint(cert_pem: bytes) -> str:
    """SHA-256 fingerprint del certificado PEM, en hex."""
    cert = load_pem_x509_certificate(cert_pem)
    return cert.fingerprint(hashes.SHA256()).hex()


def check_key_matches_cert(cert_pem: bytes, private_key_pem: bytes) -> bool:
    """Verifica que la clave privada corresponda al certificado."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    try:
        cert = load_pem_x509_certificate(cert_pem)
        key = load_pem_private_key(private_key_pem, password=None)
        cert_pub = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        key_pub = key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        return cert_pub == key_pub
    except Exception:
        return False
