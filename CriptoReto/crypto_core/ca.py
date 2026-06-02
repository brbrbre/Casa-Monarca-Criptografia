"""
CA interna de Casa Monarca.

Emite certificados X.509 SOLO para admin y coordinador.
La clave privada de la CA se guarda cifrada con AES-256-GCM derivada
de la contraseña maestra del admin con PBKDF2-HMAC-SHA256.
"""

import os
import secrets
from datetime import datetime, timezone as dt_timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.x509.oid import NameOID

# Separador para el formato cifrado: <salt_hex>:<nonce_b64>:<ciphertext_b64>
_SEP = ':'

CA_VALID_YEARS = 5
PBKDF2_ITERATIONS = 600_000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode('utf-8'))


def _encrypt_pem(pem_bytes: bytes, password: str) -> str:
    """Cifra bytes PEM con AES-256-GCM + PBKDF2. Devuelve string para archivo."""
    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, pem_bytes, None)
    return (
        salt.hex() + _SEP +
        nonce.hex() + _SEP +
        ciphertext.hex()
    )


def _decrypt_pem(encrypted_str: str, password: str) -> bytes:
    """Descifra el formato producido por _encrypt_pem."""
    try:
        salt_hex, nonce_hex, ct_hex = encrypted_str.strip().split(_SEP)
        salt = bytes.fromhex(salt_hex)
        nonce = bytes.fromhex(nonce_hex)
        ciphertext = bytes.fromhex(ct_hex)
        key = _derive_key(password, salt)
        return AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError('No se pudo descifrar la clave de la CA. Contraseña incorrecta o archivo dañado.') from exc


def generate_ca_keypair(ca_password: str) -> tuple:
    """
    Genera el par de claves de la CA interna.

    Retorna:
        ca_cert_pem (bytes)       — certificado PEM, público, distribuible
        ca_key_encrypted (str)    — clave privada cifrada con ca_password
    """
    private_key = ec.generate_private_key(ec.SECP256R1())

    now = datetime.now(dt_timezone.utc)
    expires = now + timedelta(days=CA_VALID_YEARS * 365)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'MX'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Monterrey'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Casa Monarca'),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Autoridad Certificadora'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'Casa Monarca Root CA'),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(expires)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    ca_cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ca_key_encrypted = _encrypt_pem(key_pem, ca_password)
    return ca_cert_pem, ca_key_encrypted


def load_ca(ca_cert_pem: bytes, ca_key_encrypted: str, ca_password: str) -> tuple:
    """
    Carga la CA desde disco.

    Retorna:
        (ca_cert, ca_private_key) — objetos cryptography listos para firmar
    """
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    ca_cert = load_pem_x509_certificate(ca_cert_pem)
    key_pem = _decrypt_pem(ca_key_encrypted, ca_password)
    ca_key = load_pem_private_key(key_pem, password=None)
    return ca_cert, ca_key


def get_ca_fingerprint(ca_cert_pem: bytes) -> str:
    """Retorna el fingerprint SHA-256 del certificado de la CA en formato hex:hex."""
    from cryptography.x509 import load_pem_x509_certificate
    cert = load_pem_x509_certificate(ca_cert_pem)
    raw = cert.fingerprint(hashes.SHA256())
    return ':'.join(f'{b:02X}' for b in raw)
