"""
SDK module (b): Document signing, verification, and encryption.

Provides document-level cryptographic operations aligned with the four
security properties required by the reto:

  - Integrity:       SHA-256 hash of content included in signature payload.
  - Authenticity:    Signature verified against the signer's X.509 certificate.
  - Confidentiality: AES-256-GCM hybrid encryption for document confidentiality.
  - Non-repudiation: Signature tied to certificate issued by the internal CA.

Algorithm choices:
  - Signing:    RSA-PSS with SHA-256 (compatible with RSA-2048 user certificates).
  - Encryption: Hybrid scheme — AES-256-GCM for content, RSA-OAEP to wrap the AES key.
                This allows encrypting for a specific recipient using only their certificate.
"""

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID

from .identity import verify_certificate


def _cert_fingerprint(cert_pem: bytes) -> str:
    cert = load_pem_x509_certificate(cert_pem)
    return cert.fingerprint(hashes.SHA256()).hex()


def _canonical_payload(content: bytes) -> bytes:
    """Deterministic payload: content hash + timestamp rounded to second."""
    return json.dumps(
        {"sha256": hashlib.sha256(content).hexdigest()},
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")


# ── Signing ───────────────────────────────────────────────────────────────────

def sign_document(
    content: bytes,
    private_key_pem: bytes,
    cert_pem: bytes,
) -> dict:
    """Sign a document with an RSA private key and attach the signer's certificate.

    The signature covers the SHA-256 hash of *content* to decouple the
    signature from the raw bytes (useful for large files).

    Args:
        content: Raw document bytes to sign.
        private_key_pem: Signer's RSA private key in PEM format (unencrypted).
        cert_pem: Signer's X.509 certificate in PEM format.  Included in the
            bundle so verifiers can validate the chain without a lookup.

    Returns:
        A dict (JSON-serializable) with:
          - ``signature_b64`` (str): Base64-encoded RSA-PSS signature.
          - ``payload_hash`` (str): SHA-256 hex of the signed payload.
          - ``content_hash`` (str): SHA-256 hex of the raw content.
          - ``cert_pem_b64`` (str): Base64-encoded signer certificate.
          - ``cert_fingerprint`` (str): SHA-256 fingerprint of the certificate.
          - ``signed_at`` (str): ISO-8601 timestamp.

    Raises:
        ValueError: If *private_key_pem* cannot be loaded.
        TypeError: If *content* is not bytes.

    Example:
        >>> bundle = sign_document(b"Sensitive record", key_pem, cert_pem)
        >>> import json
        >>> with open("record.sig", "w") as f: json.dump(bundle, f)
    """
    if not isinstance(content, bytes):
        raise TypeError("content must be bytes.")

    payload = _canonical_payload(content)
    private_key = load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "content_hash": hashlib.sha256(content).hexdigest(),
        "cert_pem_b64": base64.b64encode(cert_pem).decode("ascii"),
        "cert_fingerprint": _cert_fingerprint(cert_pem),
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }


def verify_document(
    content: bytes,
    signature_bundle: dict,
    ca_cert_pem: bytes,
    revoked_serials: Optional[set] = None,
) -> dict:
    """Verify a document signature bundle against the CA.

    Reconstructs the canonical payload from *content* and verifies the RSA-PSS
    signature using the certificate embedded in *signature_bundle*.

    Args:
        content: Original document bytes.
        signature_bundle: Dict as returned by :func:`sign_document`.
        ca_cert_pem: CA certificate PEM bytes used to validate the signer's cert.
        revoked_serials: Optional set of revoked certificate serial numbers.

    Returns:
        A dict with:
          - ``valid`` (bool): True if signature and certificate are valid.
          - ``reason`` (str): ``"ok"`` or a short failure description.
          - ``signer_cn`` (str): Common name from the signer's certificate.
          - ``signed_at`` (str): Timestamp from the bundle.
          - ``content_hash_match`` (bool): Whether content hash matches bundle.

    Example:
        >>> result = verify_document(b"Sensitive record", bundle, ca_cert_pem)
        >>> assert result["valid"]
    """
    result: dict = {"valid": False, "reason": "", "signer_cn": "", "signed_at": "",
                    "content_hash_match": False}
    try:
        cert_pem = base64.b64decode(signature_bundle["cert_pem_b64"])
        cert_info = verify_certificate(cert_pem, ca_cert_pem, revoked_serials)
        if not cert_info["valid"]:
            result["reason"] = f"cert_{cert_info['reason']}"
            return result

        content_hash = hashlib.sha256(content).hexdigest()
        result["content_hash_match"] = (content_hash == signature_bundle.get("content_hash"))

        payload = _canonical_payload(content)
        signature = base64.b64decode(signature_bundle["signature_b64"])
        cert = load_pem_x509_certificate(cert_pem)
        cert.public_key().verify(
            signature, payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        result.update({
            "valid": True,
            "reason": "ok",
            "signer_cn": cert_info["common_name"],
            "signed_at": signature_bundle.get("signed_at", ""),
        })
    except InvalidSignature:
        result["reason"] = "invalid_signature"
    except Exception as exc:
        result["reason"] = f"error: {str(exc)[:120]}"
    return result


# ── Encryption ────────────────────────────────────────────────────────────────

def encrypt_document(content: bytes, recipient_cert_pem: bytes) -> dict:
    """Encrypt a document for a specific recipient using hybrid encryption.

    Uses a fresh AES-256-GCM key for the document (confidentiality + integrity),
    and wraps that key with the recipient's RSA public key via OAEP (key transport).
    Only the holder of the corresponding private key can decrypt.

    Args:
        content: Document bytes to encrypt.
        recipient_cert_pem: Recipient's X.509 certificate.  The RSA public key
            embedded in the certificate is used for key wrapping.

    Returns:
        A JSON-serializable dict with:
          - ``wrapped_key_b64`` (str): RSA-OAEP encrypted AES key (base64).
          - ``nonce_b64`` (str): AES-GCM nonce (base64).
          - ``ciphertext_b64`` (str): Encrypted document (base64).
          - ``recipient_fingerprint`` (str): SHA-256 fingerprint of recipient cert.

    Raises:
        ValueError: If the recipient's certificate does not contain an RSA key.

    Example:
        >>> enc = encrypt_document(b"PII data", recipient_cert_pem)
        >>> plain = decrypt_document(enc, recipient_key_pem)
    """
    cert = load_pem_x509_certificate(recipient_cert_pem)
    pub_key = cert.public_key()
    if not isinstance(pub_key, rsa.RSAPublicKey):
        raise ValueError("Recipient certificate must contain an RSA public key.")

    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, content, None)

    wrapped_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return {
        "wrapped_key_b64": base64.b64encode(wrapped_key).decode("ascii"),
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("ascii"),
        "recipient_fingerprint": _cert_fingerprint(recipient_cert_pem),
    }


def decrypt_document(encrypted_bundle: dict, private_key_pem: bytes) -> bytes:
    """Decrypt a document encrypted with :func:`encrypt_document`.

    Args:
        encrypted_bundle: Dict as returned by :func:`encrypt_document`.
        private_key_pem: Recipient's RSA private key in PEM format (unencrypted).

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError: If decryption fails (wrong key, corrupted data, or tag mismatch).

    Example:
        >>> plain = decrypt_document(enc_bundle, key_pem)
    """
    try:
        private_key = load_pem_private_key(private_key_pem, password=None)
        aes_key = private_key.decrypt(
            base64.b64decode(encrypted_bundle["wrapped_key_b64"]),
            padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        nonce = base64.b64decode(encrypted_bundle["nonce_b64"])
        ciphertext = base64.b64decode(encrypted_bundle["ciphertext_b64"])
        return AESGCM(aes_key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ValueError(f"Decryption failed: {exc}") from exc


def hash_document(content: bytes) -> str:
    """Return the SHA-256 hash of a document as a hex string.

    Args:
        content: Document bytes.

    Returns:
        Lowercase hex SHA-256 digest.

    Example:
        >>> h = hash_document(b"Hello, world!")
    """
    return hashlib.sha256(content).hexdigest()
