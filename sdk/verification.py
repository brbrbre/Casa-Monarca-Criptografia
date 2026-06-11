"""
SDK module (e): External public-key document verification.

Enables third parties — government agencies, partner organizations, legal
teams — to verify the authenticity of Casa Monarca documents without access
to the internal system or database.  Only the CA certificate (public,
distributable) is needed.

Security properties provided:
  - Integrity:    Detects any modification to the document after signing.
  - Authenticity: Confirms the document was signed by a Casa Monarca collaborator.

No confidentiality is provided here by design — verification is a public
operation.  Verifiers need only:
  1. The CA certificate (``ca.crt`` — publicly distributable).
  2. The signed bundle (JSON file accompanying the document).
  3. The original document bytes.
"""

import base64
import hashlib
from datetime import datetime, timezone
from typing import Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import load_pem_x509_certificate

from .identity import verify_certificate, get_cert_metadata


def verify_cert_against_ca(
    cert_pem: bytes,
    ca_cert_pem: bytes,
    revoked_serials: Optional[set] = None,
) -> dict:
    """Verify an X.509 certificate against the Casa Monarca CA.

    Intended for external parties that receive a collaborator certificate and
    want to confirm it was genuinely issued by the organization.

    Args:
        cert_pem: Certificate to verify (PEM bytes).
        ca_cert_pem: Casa Monarca CA certificate (PEM bytes).
        revoked_serials: Optional set of revoked serial numbers in uppercase hex.

    Returns:
        A dict with:
          - ``valid`` (bool)
          - ``reason`` (str): ``"ok"`` or short failure code.
          - ``subject_cn`` (str): Common name of the certificate holder.
          - ``issued_to_area`` (str): Organizational unit.
          - ``expires_at`` (datetime or None): Certificate expiry (UTC).
          - ``serial_number`` (str): Certificate serial number (hex).
          - ``fingerprint_sha256`` (str): SHA-256 cert fingerprint.

    Example:
        >>> result = verify_cert_against_ca(cert_pem, ca_cert_pem)
        >>> print("Valid:", result["valid"], "Holder:", result["subject_cn"])
    """
    base = verify_certificate(cert_pem, ca_cert_pem, revoked_serials)
    meta = get_cert_metadata(cert_pem) if base["valid"] else {}
    return {
        "valid": base["valid"],
        "reason": base["reason"],
        "subject_cn": base.get("common_name", ""),
        "issued_to_area": base.get("area", ""),
        "expires_at": base.get("expires_at"),
        "serial_number": base.get("serial_number", ""),
        "fingerprint_sha256": meta.get("fingerprint_sha256", ""),
    }


def verify_document_bundle(
    document_bytes: bytes,
    signature_bundle: dict,
    ca_cert_pem: bytes,
    revoked_serials: Optional[set] = None,
) -> dict:
    """Verify a signed document bundle produced by ``sdk.documents.sign_document``.

    Suitable for use by external parties who receive a document plus its
    ``signature.json`` sidecar file.

    Args:
        document_bytes: Original document bytes.
        signature_bundle: Dict from ``sdk.documents.sign_document``.
        ca_cert_pem: Casa Monarca CA certificate (PEM bytes).
        revoked_serials: Optional set of revoked serial numbers.

    Returns:
        A dict with:
          - ``valid`` (bool)
          - ``reason`` (str)
          - ``signer_cn`` (str): Common name of the signer.
          - ``signer_area`` (str): Organizational unit of the signer.
          - ``signed_at`` (str): ISO-8601 timestamp from the bundle.
          - ``content_hash_match`` (bool): Whether document hash matches bundle.

    Example:
        >>> result = verify_document_bundle(doc_bytes, bundle, ca_cert_pem)
        >>> if result["valid"]:
        ...     print(f"Authentic. Signed by {result['signer_cn']} on {result['signed_at']}")
    """
    result: dict = {
        "valid": False, "reason": "", "signer_cn": "", "signer_area": "",
        "signed_at": "", "content_hash_match": False,
    }
    try:
        cert_pem = base64.b64decode(signature_bundle["cert_pem_b64"])
        cert_info = verify_certificate(cert_pem, ca_cert_pem, revoked_serials)
        if not cert_info["valid"]:
            result["reason"] = f"cert_{cert_info['reason']}"
            return result

        stored_hash = signature_bundle.get("content_hash", "")
        actual_hash = hashlib.sha256(document_bytes).hexdigest()
        result["content_hash_match"] = (actual_hash == stored_hash)

        import json
        payload = json.dumps(
            {"sha256": actual_hash},
            sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")

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
            "signer_area": cert_info["area"],
            "signed_at": signature_bundle.get("signed_at", ""),
        })
    except InvalidSignature:
        result["reason"] = "invalid_signature"
    except Exception as exc:
        result["reason"] = f"error: {str(exc)[:120]}"
    return result


def verify_form_bundle(
    signature_bundle: dict,
    ca_cert_pem: bytes,
    revoked_serials: Optional[set] = None,
) -> dict:
    """Verify a signed form bundle produced by ``sdk.forms.create_signed_form``.

    Delegates to the forms module for canonical payload reconstruction.

    Args:
        signature_bundle: Dict from ``sdk.forms.create_signed_form``.
        ca_cert_pem: Casa Monarca CA certificate (PEM bytes).
        revoked_serials: Optional set of revoked serial numbers.

    Returns:
        Same structure as ``sdk.forms.verify_signed_form``.

    Example:
        >>> result = verify_form_bundle(form_bundle, ca_cert_pem)
        >>> assert result["valid"]
    """
    from .forms import verify_signed_form
    return verify_signed_form(signature_bundle, ca_cert_pem, revoked_serials)


def get_ca_info(ca_cert_pem: bytes) -> dict:
    """Extract human-readable metadata from the CA certificate.

    Useful for displaying trust anchor information to external verifiers.

    Args:
        ca_cert_pem: CA certificate PEM bytes.

    Returns:
        A dict with: ``cn``, ``organization``, ``country``, ``expires_at``,
        ``fingerprint_sha256``.

    Example:
        >>> info = get_ca_info(ca_cert_pem)
        >>> print(info["cn"], "expires:", info["expires_at"])
    """
    from cryptography.x509.oid import NameOID
    cert = load_pem_x509_certificate(ca_cert_pem)
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    org = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    country = cert.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)
    return {
        "cn": cn[0].value if cn else "",
        "organization": org[0].value if org else "",
        "country": country[0].value if country else "",
        "expires_at": cert.not_valid_after_utc,
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }
