"""
SDK module (f): Secret key protection with public-key cryptography.

Protects symmetric secrets (AES keys, database master passwords, backup
credentials) using asymmetric cryptography so that:
  - Confidentiality: Only the holder of a private key can recover the secret.
  - Integrity:       SHA-256 MAC detects tampering with the protected bundle.
  - Authenticity:    The wrapping key pair identifies the intended recipient.

Algorithm choices:
  - Key pair:     RSA-4096 with OAEP-SHA256 for key wrapping.
                  RSA-4096 chosen over EC because OAEP key transport requires
                  RSA; EC keys are used for signing (identity module), not
                  for encryption in TLS or key wrapping.
  - Secret MAC:   HMAC-SHA256 over the plaintext secret for integrity check
                  before wrapping (detect corruption before encryption).
  - Storage:      JSON bundle — portable and database-friendly.

Typical use cases:
  - Wrapping the database encryption master key so it can be stored safely.
  - Protecting backup credentials tied to a specific admin's key pair.
  - Escrow-style key recovery: wrap the same secret with multiple public keys.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key,
    load_pem_public_key,
)
from cryptography.x509 import load_pem_x509_certificate

_RSA_KEY_SIZE = 4096


# ── Key pair generation ───────────────────────────────────────────────────────

def generate_key_pair() -> tuple[bytes, bytes]:
    """Generate an RSA-4096 key pair for key wrapping operations.

    The private key is returned unencrypted in PEM format.  Callers are
    responsible for protecting it (e.g., via OS keychain or encrypted storage).

    Returns:
        A tuple ``(public_key_pem, private_key_pem)`` as PEM bytes.

    Raises:
        RuntimeError: On key generation failure (should not occur in practice).

    Example:
        >>> pub_pem, priv_pem = generate_key_pair()
        >>> with open("admin_pub.pem", "wb") as f: f.write(pub_pem)
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=_RSA_KEY_SIZE)
    pub_pem = private_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    priv_pem = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    return pub_pem, priv_pem


# ── Key wrapping ──────────────────────────────────────────────────────────────

def wrap_key(secret_key_bytes: bytes, recipient_public_key_pem: bytes) -> dict:
    """Wrap a symmetric key with a recipient's RSA public key.

    Uses RSA-OAEP-SHA256 to encrypt *secret_key_bytes* so only the holder of
    the corresponding private key can recover it.  Suitable for AES-256 keys
    (32 bytes) but works for any secret up to ``(key_size / 8) - 66`` bytes.

    Args:
        secret_key_bytes: Symmetric key or secret to protect (bytes).
        recipient_public_key_pem: RSA public key in PEM format.  Can be a
            bare public key or extracted from an X.509 certificate.

    Returns:
        A JSON-serializable dict with:
          - ``wrapped_key_b64`` (str): OAEP-encrypted key (base64).
          - ``secret_hash`` (str): SHA-256 of plaintext for integrity check.
          - ``wrapped_at`` (str): ISO-8601 timestamp.

    Raises:
        ValueError: If *recipient_public_key_pem* is not a valid RSA public key.
        ValueError: If *secret_key_bytes* is empty.

    Example:
        >>> aes_key = os.urandom(32)
        >>> bundle = wrap_key(aes_key, pub_pem)
    """
    if not secret_key_bytes:
        raise ValueError("secret_key_bytes must not be empty.")

    pub_key = load_pem_public_key(recipient_public_key_pem)
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise ValueError("recipient_public_key_pem must be an RSA public key.")

    wrapped = pub_key.encrypt(
        secret_key_bytes,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {
        "wrapped_key_b64": base64.b64encode(wrapped).decode("ascii"),
        "secret_hash": hashlib.sha256(secret_key_bytes).hexdigest(),
        "wrapped_at": datetime.now(timezone.utc).isoformat(),
    }


def unwrap_key(wrapped_bundle: dict, private_key_pem: bytes) -> bytes:
    """Recover a symmetric key from a bundle created by :func:`wrap_key`.

    Args:
        wrapped_bundle: Dict as returned by :func:`wrap_key`.
        private_key_pem: Recipient's RSA private key (PEM bytes, unencrypted).

    Returns:
        Original symmetric key bytes.

    Raises:
        ValueError: If decryption fails (wrong key or corrupted data).
        ValueError: If the recovered key's hash does not match the stored hash
            (tampered bundle detected).

    Example:
        >>> recovered = unwrap_key(bundle, priv_pem)
        >>> assert recovered == original_aes_key
    """
    try:
        private_key = load_pem_private_key(private_key_pem, password=None)
        secret = private_key.decrypt(
            base64.b64decode(wrapped_bundle["wrapped_key_b64"]),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
    except Exception as exc:
        raise ValueError(f"Key unwrapping failed: {exc}") from exc

    actual_hash = hashlib.sha256(secret).hexdigest()
    expected_hash = wrapped_bundle.get("secret_hash", "")
    if expected_hash and not hmac.compare_digest(actual_hash, expected_hash):
        raise ValueError("Integrity check failed: recovered key hash does not match bundle.")
    return secret


# ── High-level secret protection ─────────────────────────────────────────────

def protect_secret(
    secret: bytes,
    recipient_public_key_pem: bytes,
    label: str = "",
) -> dict:
    """Protect an arbitrary secret with both encryption and integrity hashing.

    Combines OAEP key wrapping with a human-readable label and timestamp,
    producing a self-describing bundle suitable for long-term storage.

    Args:
        secret: Secret bytes to protect (e.g., a password, an AES key).
        recipient_public_key_pem: RSA public key PEM for the intended recipient.
        label: Optional descriptive label (e.g., ``"db_master_key_v2"``).

    Returns:
        A JSON-serializable dict (superset of :func:`wrap_key` output) with
        an additional ``"label"`` field.

    Raises:
        ValueError: If *secret* is empty.

    Example:
        >>> bundle = protect_secret(aes_key, pub_pem, label="db_master_key")
        >>> with open("db_master_key.json", "w") as f: json.dump(bundle, f)
    """
    bundle = wrap_key(secret, recipient_public_key_pem)
    bundle["label"] = label
    return bundle


def recover_secret(protected_bundle: dict, private_key_pem: bytes) -> bytes:
    """Recover a secret from a bundle created by :func:`protect_secret`.

    Args:
        protected_bundle: Dict as returned by :func:`protect_secret`.
        private_key_pem: Recipient's RSA-4096 private key (PEM bytes, unencrypted).

    Returns:
        Original secret bytes.

    Raises:
        ValueError: If decryption or integrity check fails.

    Example:
        >>> aes_key = recover_secret(bundle, priv_pem)
    """
    return unwrap_key(protected_bundle, private_key_pem)


def extract_public_key_from_cert(cert_pem: bytes) -> bytes:
    """Extract the RSA public key from an X.509 certificate as PEM bytes.

    Allows using a collaborator's certificate (e.g., from the identity module)
    directly as the recipient for key wrapping, without a separate key file.

    Args:
        cert_pem: X.509 certificate in PEM format (bytes).

    Returns:
        Public key in PEM format (bytes).

    Raises:
        ValueError: If the certificate does not contain an RSA public key.

    Example:
        >>> pub_pem = extract_public_key_from_cert(admin_cert_pem)
        >>> bundle = protect_secret(aes_key, pub_pem, label="admin_escrow")
    """
    cert = load_pem_x509_certificate(cert_pem)
    pub_key = cert.public_key()
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise ValueError("Certificate must contain an RSA public key for key wrapping.")
    return pub_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
