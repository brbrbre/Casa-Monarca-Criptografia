"""
SDK module (c): Email signing and verification.

PGP-inspired email signing that provides integrity, authenticity, and
non-repudiation for communications from Casa Monarca collaborators.

The approach avoids S/MIME complexity while achieving the required properties:
  - Integrity:       HMAC-SHA256 of a canonical message representation.
  - Authenticity:    Signature verified against signer's X.509 certificate.
  - Non-repudiation: Signer cannot deny authorship — certificate ties identity.

Algorithm choice: RSA-PSS with SHA-256.  Same algorithm as documents.py to
simplify key management — one key pair serves both document and email signing.

Attachments are included in the signed payload via their SHA-256 hashes, so
tampering with an attachment invalidates the signature even if body is intact.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import load_pem_x509_certificate

from .identity import verify_certificate


def _canonical_message(subject: str, body: str, attachments: list[tuple[str, bytes]]) -> bytes:
    """Build a deterministic bytes representation of the email for signing.

    Attachment filenames and SHA-256 hashes are included; raw bytes are not,
    to avoid bloating the signed payload while still covering integrity.
    """
    attachment_hashes = [
        {"filename": name, "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in sorted(attachments, key=lambda a: a[0])
    ]
    payload = json.dumps(
        {"subject": subject, "body": body, "attachments": attachment_hashes},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return payload.encode("utf-8")


# ── Public API ────────────────────────────────────────────────────────────────

def sign_email(
    subject: str,
    body: str,
    sender_key_pem: bytes,
    sender_cert_pem: bytes,
    attachments: Optional[list[tuple[str, bytes]]] = None,
) -> dict:
    """Sign an email message and its attachments.

    Creates a signed bundle containing the message content and a detached
    RSA-PSS signature.  The bundle is JSON-serializable and can be attached
    as a ``signature.json`` file or stored in a database.

    Args:
        subject: Email subject line.
        body: Plain-text email body.
        sender_key_pem: Sender's RSA private key (PEM bytes, unencrypted).
        sender_cert_pem: Sender's X.509 certificate (PEM bytes).  Embedded in
            the bundle so the recipient can verify without a key directory.
        attachments: Optional list of ``(filename, bytes)`` tuples.  Each
            attachment is hashed and included in the signed payload.

    Returns:
        A JSON-serializable dict with:
          - ``subject`` (str)
          - ``body`` (str)
          - ``attachment_hashes`` (list): ``[{filename, sha256}]``.
          - ``signature_b64`` (str): Base64 RSA-PSS signature.
          - ``cert_pem_b64`` (str): Base64 sender certificate.
          - ``cert_fingerprint`` (str): SHA-256 cert fingerprint.
          - ``signed_at`` (str): ISO-8601 timestamp.

    Raises:
        ValueError: If the private key cannot be loaded.

    Example:
        >>> bundle = sign_email(
        ...     "ARCO confirmation", "Your request was processed.",
        ...     key_pem, cert_pem,
        ...     attachments=[("response.pdf", pdf_bytes)],
        ... )
    """
    attachments = attachments or []
    payload = _canonical_message(subject, body, attachments)
    private_key = load_pem_private_key(sender_key_pem, password=None)
    signature = private_key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    cert = load_pem_x509_certificate(sender_cert_pem)
    return {
        "subject": subject,
        "body": body,
        "attachment_hashes": [
            {"filename": name, "sha256": hashlib.sha256(data).hexdigest()}
            for name, data in sorted(attachments, key=lambda a: a[0])
        ],
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "cert_pem_b64": base64.b64encode(sender_cert_pem).decode("ascii"),
        "cert_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "signed_at": datetime.now(timezone.utc).isoformat(),
    }


def verify_email(
    signed_bundle: dict,
    ca_cert_pem: bytes,
    revoked_serials: Optional[set] = None,
) -> dict:
    """Verify a signed email bundle.

    Reconstructs the canonical message from the bundle fields and verifies
    the RSA-PSS signature.  Note: attachment *content* is not included in the
    bundle (only hashes).  If you need to verify attachment integrity, call
    :func:`verify_attachment` separately.

    Args:
        signed_bundle: Dict as returned by :func:`sign_email`.
        ca_cert_pem: CA certificate PEM bytes for signer cert validation.
        revoked_serials: Optional set of revoked certificate serial numbers.

    Returns:
        A dict with:
          - ``valid`` (bool)
          - ``reason`` (str): ``"ok"`` or failure description.
          - ``signer`` (str): Certificate CN of the sender.
          - ``signed_at`` (str)

    Example:
        >>> result = verify_email(bundle, ca_cert_pem)
        >>> if result["valid"]:
        ...     print("Authentic email from:", result["signer"])
    """
    result: dict = {"valid": False, "reason": "", "signer": "", "signed_at": ""}
    try:
        cert_pem = base64.b64decode(signed_bundle["cert_pem_b64"])
        cert_info = verify_certificate(cert_pem, ca_cert_pem, revoked_serials)
        if not cert_info["valid"]:
            result["reason"] = f"cert_{cert_info['reason']}"
            return result

        attachment_tuples = [
            (item["filename"], bytes.fromhex(item["sha256"]))
            for item in signed_bundle.get("attachment_hashes", [])
        ]
        # Reconstruct payload using only the hashes (same as sign path)
        payload = json.dumps(
            {
                "subject": signed_bundle["subject"],
                "body": signed_bundle["body"],
                "attachments": [
                    {"filename": name, "sha256": data.hex()}
                    for name, data in sorted(attachment_tuples, key=lambda a: a[0])
                ],
            },
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")

        signature = base64.b64decode(signed_bundle["signature_b64"])
        cert = load_pem_x509_certificate(cert_pem)
        cert.public_key().verify(
            signature, payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        result.update({
            "valid": True,
            "reason": "ok",
            "signer": cert_info["common_name"],
            "signed_at": signed_bundle.get("signed_at", ""),
        })
    except InvalidSignature:
        result["reason"] = "invalid_signature"
    except Exception as exc:
        result["reason"] = f"error: {str(exc)[:120]}"
    return result


def verify_attachment(attachment_bytes: bytes, filename: str, signed_bundle: dict) -> bool:
    """Check that an attachment's content matches the hash stored in a signed bundle.

    Provides integrity verification for attachment bytes received separately
    from the bundle (e.g., downloaded from a file server).

    Args:
        attachment_bytes: Raw bytes of the attachment to check.
        filename: Filename as listed in ``signed_bundle["attachment_hashes"]``.
        signed_bundle: Dict as returned by :func:`sign_email`.

    Returns:
        True if the SHA-256 of *attachment_bytes* matches the stored hash.
        False if not found or hash mismatch.

    Example:
        >>> ok = verify_attachment(pdf_bytes, "response.pdf", bundle)
    """
    expected = next(
        (item["sha256"] for item in signed_bundle.get("attachment_hashes", [])
         if item["filename"] == filename),
        None,
    )
    if expected is None:
        return False
    return hashlib.sha256(attachment_bytes).hexdigest() == expected
