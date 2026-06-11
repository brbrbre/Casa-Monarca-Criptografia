"""
SDK module (d): Signed form handling.

Implements digitally signed forms analogous to Mexico's SAT e.firma:
a collaborator "signs" a form by producing an RSA-PSS signature over its
canonical JSON representation.  The signed form bundle is self-contained
and verifiable by any party holding the CA certificate.

Security properties provided:
  - Integrity:       Any modification to form data invalidates the signature.
  - Authenticity:    Signer's X.509 certificate is embedded in the bundle.
  - Non-repudiation: The signer cannot deny having authorized the form.
  - Availability:    Bundles are JSON — storable, transmittable, archivable.

Typical form types in the Casa Monarca context:
  - ``"registro_migrante"``    — initial registration consent
  - ``"arco_acceso"``          — ARCO access request authorization
  - ``"arco_rectificacion"``   — ARCO rectification authorization
  - ``"arco_cancelacion"``     — ARCO cancellation (deletion) authorization
  - ``"arco_oposicion"``       — ARCO opposition authorization
  - ``"onboarding_aprobacion"``— collaborator onboarding approval
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

_SUPPORTED_FORM_TYPES = frozenset({
    "registro_migrante",
    "arco_acceso",
    "arco_rectificacion",
    "arco_cancelacion",
    "arco_oposicion",
    "onboarding_aprobacion",
    "documento_interno",
})


def _canonical_form_bytes(form_type: str, form_data: dict, signed_at: str) -> bytes:
    """Produce a deterministic byte representation of the form for signing."""
    payload = {"form_type": form_type, "form_data": form_data, "signed_at": signed_at}
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


# ── Public API ────────────────────────────────────────────────────────────────

def create_signed_form(
    form_type: str,
    form_data: dict,
    signer_key_pem: bytes,
    signer_cert_pem: bytes,
) -> dict:
    """Create a digitally signed form bundle.

    The entire *form_data* dict is included in the signed payload.  Any
    post-hoc modification — including whitespace or field reordering — will
    invalidate the signature because the payload is canonicalized with
    ``sort_keys=True`` before signing.

    Args:
        form_type: A string identifying the form category.  Should be one of
            the supported types listed in this module's docstring, but any
            non-empty string is accepted to allow extensibility.
        form_data: Dict containing the form fields and values.  Must be
            JSON-serializable.  Nested dicts and lists are supported.
        signer_key_pem: Signer's RSA private key (PEM bytes, unencrypted).
        signer_cert_pem: Signer's X.509 certificate (PEM bytes).

    Returns:
        A JSON-serializable dict with:
          - ``form_type`` (str)
          - ``form_data`` (dict)
          - ``signature_b64`` (str): Base64 RSA-PSS signature.
          - ``payload_hash`` (str): SHA-256 hex of the canonical payload.
          - ``cert_pem_b64`` (str): Base64 signer certificate.
          - ``cert_fingerprint`` (str): SHA-256 cert fingerprint.
          - ``signed_at`` (str): ISO-8601 timestamp.

    Raises:
        ValueError: If *form_type* is empty or *form_data* is not serializable.
        ValueError: If the private key cannot be loaded.

    Example:
        >>> form = create_signed_form(
        ...     "arco_acceso",
        ...     {"migrant_id": 42, "requested_by": "brisma_alvarez"},
        ...     key_pem, cert_pem,
        ... )
    """
    if not form_type:
        raise ValueError("form_type must not be empty.")

    signed_at = datetime.now(timezone.utc).isoformat()
    payload = _canonical_form_bytes(form_type, form_data, signed_at)
    private_key = load_pem_private_key(signer_key_pem, password=None)
    signature = private_key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    cert = load_pem_x509_certificate(signer_cert_pem)
    return {
        "form_type": form_type,
        "form_data": form_data,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "payload_hash": hashlib.sha256(payload).hexdigest(),
        "cert_pem_b64": base64.b64encode(signer_cert_pem).decode("ascii"),
        "cert_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "signed_at": signed_at,
    }


def verify_signed_form(
    signed_bundle: dict,
    ca_cert_pem: bytes,
    revoked_serials: Optional[set] = None,
) -> dict:
    """Verify the digital signature on a signed form bundle.

    Reconstructs the canonical payload from the bundle's own fields and
    verifies the RSA-PSS signature against the embedded certificate.

    Args:
        signed_bundle: Dict as returned by :func:`create_signed_form`.
        ca_cert_pem: CA certificate PEM bytes for chain validation.
        revoked_serials: Optional set of revoked serial numbers.

    Returns:
        A dict with:
          - ``valid`` (bool)
          - ``reason`` (str): ``"ok"`` or failure description.
          - ``form_type`` (str)
          - ``signer_cn`` (str): Common name from the signer's certificate.
          - ``signer_area`` (str): Organizational unit.
          - ``signed_at`` (str)

    Example:
        >>> result = verify_signed_form(form_bundle, ca_cert_pem)
        >>> assert result["valid"], result["reason"]
    """
    result: dict = {
        "valid": False, "reason": "", "form_type": signed_bundle.get("form_type", ""),
        "signer_cn": "", "signer_area": "", "signed_at": "",
    }
    try:
        cert_pem = base64.b64decode(signed_bundle["cert_pem_b64"])
        cert_info = verify_certificate(cert_pem, ca_cert_pem, revoked_serials)
        if not cert_info["valid"]:
            result["reason"] = f"cert_{cert_info['reason']}"
            return result

        payload = _canonical_form_bytes(
            signed_bundle["form_type"],
            signed_bundle["form_data"],
            signed_bundle["signed_at"],
        )
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
            "form_type": signed_bundle["form_type"],
            "signer_cn": cert_info["common_name"],
            "signer_area": cert_info["area"],
            "signed_at": signed_bundle["signed_at"],
        })
    except InvalidSignature:
        result["reason"] = "invalid_signature"
    except Exception as exc:
        result["reason"] = f"error: {str(exc)[:120]}"
    return result


def get_form_data(signed_bundle: dict) -> dict:
    """Extract the form data from a signed bundle without verifying the signature.

    Useful for display purposes.  Always call :func:`verify_signed_form` before
    acting on the data in a security-sensitive context.

    Args:
        signed_bundle: Dict as returned by :func:`create_signed_form`.

    Returns:
        A copy of the ``form_data`` dict from the bundle.

    Example:
        >>> data = get_form_data(bundle)
        >>> print(data["migrant_id"])
    """
    return dict(signed_bundle.get("form_data", {}))
