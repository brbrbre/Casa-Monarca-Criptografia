"""
Cryptographic services for the registros module.

Covers:
  1. ECDSA signing / verification of MigrantRegistration payloads  (existing)
  2. General-purpose ActionSignature signing with hash-chained ledger
  3. Batch / parallel signing (single password confirmation → N signatures)
  4. Verification of the hash chain
"""

import hashlib
import json
import os
from pathlib import Path
from typing import Dict, List

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from django.conf import settings
from django.utils import timezone

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
    return _load_or_generate_private_key().public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')


def _sign_bytes(payload: bytes) -> Dict[str, str]:
    """Low-level: sign raw bytes, return (message_hash, r, s, public_key_pem)."""
    private_key = _load_or_generate_private_key()
    message_hash = hashlib.sha256(payload).hexdigest()
    der_sig = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der_sig)
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')
    return {
        'message_hash': message_hash,
        'signature_r': str(r),
        'signature_s': str(s),
        'public_key': pub_pem,
        'curve_name': CURVE_NAME,
    }


def _verify_bytes(payload: bytes, message_hash: str, r: int, s: int, pub_pem: str) -> bool:
    """Low-level: verify signature over raw bytes."""
    try:
        public_key = serialization.load_pem_public_key(pub_pem.encode('utf-8'))
        der_sig = encode_dss_signature(r, s)
        public_key.verify(der_sig, payload, ec.ECDSA(hashes.SHA256()))
        computed = hashlib.sha256(payload).hexdigest()
        return computed == message_hash
    except (InvalidSignature, Exception):
        return False


# ── MigrantRegistration signing (existing API, preserved) ────────────────────

def _canonical_payload(registration) -> bytes:
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


def sign_registration(registration) -> dict:
    payload = _canonical_payload(registration)
    return _sign_bytes(payload)


def verify_registration(registration, signature_obj) -> dict:
    payload = _canonical_payload(registration)
    computed_hash = hashlib.sha256(payload).hexdigest()
    is_valid = False
    error = None
    try:
        r = int(signature_obj.signature_r)
        s = int(signature_obj.signature_s)
        is_valid = _verify_bytes(payload, signature_obj.message_hash, r, s, signature_obj.public_key)
        if not is_valid:
            error = 'hash_mismatch_or_invalid_signature'
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


# ── General ActionSignature with hash chain ───────────────────────────────────

def _get_last_chain_entry():
    """Return the most recent ActionSignature (for chaining), or None."""
    from .models import ActionSignature
    return ActionSignature.objects.order_by('-chain_position', '-id').first()


def _build_action_payload(subject_type: str, subject_id: int, extra: dict, prev_hash: str) -> bytes:
    """
    Canonical payload for an ActionSignature.

    Including prev_hash in the signed payload means the ECDSA signature
    cryptographically commits to the entire history up to this point.
    """
    data = {
        'subject_type': subject_type,
        'subject_id': subject_id,
        'prev_chain_hash': prev_hash,
        **{k: v for k, v in sorted(extra.items())},
    }
    return json.dumps(data, sort_keys=True, ensure_ascii=False).encode('utf-8')


def sign_action(subject_type: str, subject_id: int, extra: dict, signer, batch=None):
    """
    Sign a generic action and persist an ActionSignature.

    Returns the created ActionSignature instance.
    """
    from .models import ActionSignature

    last = _get_last_chain_entry()
    prev_hash = last.chain_hash() if last else ''
    chain_pos = (last.chain_position + 1) if last else 0

    payload = _build_action_payload(subject_type, subject_id, extra, prev_hash)
    sig_data = _sign_bytes(payload)

    return ActionSignature.objects.create(
        subject_type=subject_type,
        subject_id=subject_id,
        message_hash=sig_data['message_hash'],
        signature_r=sig_data['signature_r'],
        signature_s=sig_data['signature_s'],
        public_key=sig_data['public_key'],
        curve_name=sig_data['curve_name'],
        prev_chain_hash=prev_hash,
        chain_position=chain_pos,
        signed_by=signer,
        signed_by_role=signer.access_level,
        batch=batch,
    )


def verify_action_signature(action_sig) -> dict:
    """Verify an ActionSignature against its stored hash and public key."""
    extra_keys = [
        'subject_type', 'subject_id', 'prev_chain_hash',
    ]
    extra = {}
    payload = _build_action_payload(
        action_sig.subject_type,
        action_sig.subject_id,
        extra,
        action_sig.prev_chain_hash,
    )
    r = int(action_sig.signature_r)
    s = int(action_sig.signature_s)
    is_valid = _verify_bytes(payload, action_sig.message_hash, r, s, action_sig.public_key)
    return {
        'is_valid': is_valid,
        'chain_position': action_sig.chain_position,
        'prev_chain_hash': action_sig.prev_chain_hash,
        'signed_by': str(action_sig.signed_by),
        'signed_at': action_sig.signed_at,
    }


# ── Hash chain verification ───────────────────────────────────────────────────

def verify_action_chain(start_position: int = 0, count: int = 100) -> List[dict]:
    """
    Walk the ActionSignature chain from start_position and verify each link.

    Returns a list of per-entry results.  Any 'chain_break' indicates tampering.
    """
    from .models import ActionSignature

    entries = list(
        ActionSignature.objects
        .filter(chain_position__gte=start_position)
        .order_by('chain_position', 'id')[:count]
    )
    results = []
    prev_hash = ''
    for sig in entries:
        sig_ok = verify_action_signature(sig)
        chain_ok = (sig.prev_chain_hash == prev_hash)
        results.append({
            'id': sig.pk,
            'chain_position': sig.chain_position,
            'subject': f'{sig.subject_type}:{sig.subject_id}',
            'signature_valid': sig_ok['is_valid'],
            'chain_intact': chain_ok,
            'signed_by': str(sig.signed_by),
            'signed_at': sig.signed_at,
        })
        prev_hash = sig.chain_hash()
    return results


# ── Batch / parallel signing ──────────────────────────────────────────────────

def batch_sign_actions(items: List[dict], signer, ip_address: str = None):
    """
    Sign multiple actions in a single call (one password confirmation).

    items: list of dicts with keys: subject_type, subject_id, extra
    signer: Collaborator instance (already password-verified by the caller)

    Returns:
        batch   – BatchSignSession instance
        sigs    – list of ActionSignature instances, one per item
    """
    from .models import BatchSignSession

    sigs = []
    batch_placeholder = None  # will be updated after creation

    # Create a temporary BatchSignSession so we have its PK for the root hash
    batch = BatchSignSession.objects.create(
        signed_by=signer,
        ip_address=ip_address,
        item_count=len(items),
        batch_root_hash='pending',  # computed below
    )

    for item in items:
        sig = sign_action(
            subject_type=item['subject_type'],
            subject_id=item['subject_id'],
            extra=item.get('extra', {}),
            signer=signer,
            batch=batch,
        )
        sigs.append(sig)

    # Compute root hash = SHA-256 of all individual hashes concatenated (sorted)
    sorted_hashes = sorted(s.message_hash for s in sigs)
    root_hash = hashlib.sha256('|'.join(sorted_hashes).encode('utf-8')).hexdigest()
    batch.batch_root_hash = root_hash
    batch.save(update_fields=['batch_root_hash'])

    return batch, sigs
