"""
ECC digital-signature service for migrant registrations.

Algorithm : ECDSA over secp256k1
Hash      : SHA-256
Storage   : signature_r / signature_s stored as decimal integers (strings)
Key file  : settings.ECC_PRIVATE_KEY_PATH  (auto-generated on first use)
"""

import hashlib
import json
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from django.conf import settings

CURVE = ec.SECP256K1()
CURVE_NAME = 'secp256k1'


# ── Key management ────────────────────────────────────────────────────────────

def _key_path() -> Path:
    configured = getattr(settings, 'ECC_PRIVATE_KEY_PATH', '')
    if configured:
        return Path(configured)
    return Path(settings.BASE_DIR) / 'ecc_signing_key.pem'


def _load_or_generate_private_key():
    path = _key_path()
    if path.exists():
        with open(path, 'rb') as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)
    private_key = ec.generate_private_key(CURVE)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, 'wb') as fh:
        fh.write(pem)
    os.chmod(path, 0o600)
    return private_key


def get_public_key_pem() -> str:
    """Return the server's ECC public key in PEM format (safe to export)."""
    private_key = _load_or_generate_private_key()
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')


# ── Canonical payload ─────────────────────────────────────────────────────────

def _canonical_payload(registration) -> bytes:
    """
    Deterministic JSON serialisation of a MigrantRegistration.

    Keys are sorted; dates rendered as ISO strings.  Any change to a field
    value will produce a different hash, making tampering detectable.
    """
    data = {
        'id': registration.pk,
        'full_name': registration.full_name,
        'birth_date': str(registration.birth_date),
        'gender': registration.gender,
        'nationality': registration.nationality,
        'country_of_origin': registration.country_of_origin,
        'document_type': registration.document_type,
        'document_number': registration.document_number,
        'phone': registration.phone,
        'email': registration.email,
        'entry_date': str(registration.entry_date),
        'entry_point': registration.entry_point,
        'transit_countries': registration.transit_countries,
        'intended_destination': registration.intended_destination,
        'marital_status': registration.marital_status,
        'travels_alone': registration.travels_alone,
        'group_size': registration.group_size,
        'minors_in_group': registration.minors_in_group,
        'assistance_requested': registration.assistance_requested,
        'migration_reason': registration.migration_reason,
        'current_legal_status': registration.current_legal_status,
        'shelter_name': registration.shelter_name,
        'emergency_contact_name': registration.emergency_contact_name,
        'emergency_contact_phone': registration.emergency_contact_phone,
        'emergency_contact_relationship': registration.emergency_contact_relationship,
        'observations': registration.observations,
        'created_by_id': registration.created_by_id,
        'created_by_role': registration.created_by_role,
        'created_at': registration.created_at.isoformat(),
    }
    return json.dumps(data, sort_keys=True, ensure_ascii=False).encode('utf-8')


# ── Sign ──────────────────────────────────────────────────────────────────────

def sign_registration(registration) -> dict:
    """
    Sign *registration* with the server ECC key.

    Returns a dict ready to be unpacked into MigrantRegistrationSignature.
    """
    private_key = _load_or_generate_private_key()
    payload = _canonical_payload(registration)
    message_hash = hashlib.sha256(payload).hexdigest()

    # cryptography signs with DER-encoded (r, s); we decode to store individually
    der_signature = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_signature)

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')

    return {
        'message_hash': message_hash,
        'signature_r': str(r),
        'signature_s': str(s),
        'public_key': public_key_pem,
        'curve_name': CURVE_NAME,
    }


# ── Verify ────────────────────────────────────────────────────────────────────

def verify_registration(registration, signature_obj) -> dict:
    """
    Verify the ECDSA signature stored in *signature_obj* against *registration*.

    Returns a dict with:
        is_valid  – True only when both the ECDSA maths AND the stored hash match
        curve     – curve name used
        signed_at – datetime of signing
        signed_by – string representation of the signer
        message_hash – freshly computed hash of current data
        stored_hash  – hash recorded at signing time
    """
    payload = _canonical_payload(registration)
    computed_hash = hashlib.sha256(payload).hexdigest()

    is_valid = False
    error = None
    try:
        public_key = serialization.load_pem_public_key(
            signature_obj.public_key.encode('utf-8')
        )
        r = int(signature_obj.signature_r)
        s = int(signature_obj.signature_s)
        der_sig = encode_dss_signature(r, s)
        public_key.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
        # Cryptographic verification passed; also check the stored hash matches
        is_valid = (computed_hash == signature_obj.message_hash)
        if not is_valid:
            error = 'hash_mismatch'
    except InvalidSignature:
        error = 'invalid_signature'
    except Exception as exc:
        error = str(exc)

    return {
        'is_valid': is_valid,
        'error': error,
        'curve': signature_obj.curve_name,
        'signed_at': signature_obj.signed_at,
        'signed_by': str(signature_obj.signed_by),
        'message_hash': computed_hash,
        'stored_hash': signature_obj.message_hash,
    }
