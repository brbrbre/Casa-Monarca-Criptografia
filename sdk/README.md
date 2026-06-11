# Casa Monarca SDK

Public Python SDK for the Casa Monarca PKI system.  
Covers all six subsystems of the MA2006B reto without Django dependencies.

---

## Installation

```bash
pip install cryptography>=41.0
```

The SDK is a local package — no PyPI distribution. Add the repo root to your Python path:

```bash
export PYTHONPATH=/path/to/Casa-Monarca-Criptografia:$PYTHONPATH
```

Or install editably from the repo root:

```bash
pip install -e .
```

---

## Modules

| Module | Subsystem | Description |
|---|---|---|
| `sdk.identity` | (a) | Certificate lifecycle: generate CA, issue, revoke, verify certificates |
| `sdk.documents` | (b) | Sign, verify, and encrypt arbitrary documents |
| `sdk.email_sign` | (c) | Sign email content and attachments; verify by recipient |
| `sdk.forms` | (d) | Create and verify digitally signed forms |
| `sdk.verification` | (e) | External public-key verification without system access |
| `sdk.key_manager` | (f) | Protect secret keys with public-key cryptography |

---

## Quick reference

### Import

```python
from sdk import identity, documents, email_sign, forms, verification, key_manager
```

### identity

```python
# Generate a CA
ca_cert_pem, ca_key_enc = identity.generate_ca("strong-ca-password")

# Issue a certificate
cert_pem, key_pem = identity.issue_certificate(
    user_id=1,
    username="mariel_alvarez",
    role="admin",
    area="Administracion",
    ca_cert_pem=ca_cert_pem,
    ca_key_encrypted=ca_key_enc,
    ca_password="strong-ca-password",
    valid_days=365,
)

# Verify a certificate
info = identity.verify_certificate(cert_pem, ca_cert_pem)
print(info["valid"], info["common_name"], info["expires_at"])

# Get certificate metadata
meta = identity.get_cert_metadata(cert_pem)
```

### documents

```python
# Sign
result = documents.sign_document(b"Document content", key_pem, cert_pem)
# result: {"signature_b64": ..., "cert_fingerprint": ..., "payload_hash": ...}

# Verify
v = documents.verify_document(b"Document content", result, ca_cert_pem)
print(v["valid"])  # True / False

# Encrypt
enc = documents.encrypt_document(b"Sensitive data", recipient_cert_pem)
plain = documents.decrypt_document(enc, recipient_key_pem)
```

### email_sign

```python
# Sign
signed = email_sign.sign_email(
    subject="Confirmacion ARCO",
    body="Su solicitud fue procesada.",
    sender_key_pem=key_pem,
    sender_cert_pem=cert_pem,
    attachments=[("respuesta.pdf", pdf_bytes)],
)

# Verify
result = email_sign.verify_email(signed, ca_cert_pem)
print(result["valid"], result["signer"])
```

### forms

```python
# Create signed form
form = forms.create_signed_form(
    form_type="registro_migrante",
    form_data={"nombre": "John Doe", "fecha": "2026-06-10"},
    signer_key_pem=key_pem,
    signer_cert_pem=cert_pem,
)

# Verify
v = forms.verify_signed_form(form, ca_cert_pem)
print(v["valid"], v["form_type"])
```

### verification

```python
# Verify a certificate from PEM bytes (no system access needed)
result = verification.verify_cert_against_ca(cert_pem, ca_cert_pem)

# Verify a document signature bundle
result = verification.verify_document_bundle(document_bytes, signature_bundle, ca_cert_pem)
print(result["valid"], result["signer_cn"])
```

### key_manager

```python
# Generate an asymmetric key pair for key wrapping
pub_pem, priv_pem = key_manager.generate_key_pair()

# Protect a secret key (AES-256 symmetric key) with a public key
wrapped = key_manager.wrap_key(secret_key_bytes, pub_pem)

# Recover the secret key
recovered = key_manager.unwrap_key(wrapped, priv_pem)

# Store a secret with integrity protection
bundle = key_manager.protect_secret(b"my secret", pub_pem, label="db_master_key")
secret = key_manager.recover_secret(bundle, priv_pem)
```

---

## End-to-end example

```python
from sdk import identity, documents

# 1. Generate a CA
ca_cert_pem, ca_key_enc = identity.generate_ca("ca-password-2026")

# 2. Issue a certificate for an admin
cert_pem, key_pem = identity.issue_certificate(
    user_id=42,
    username="mariel_alvarez",
    role="admin",
    area="Administracion",
    ca_cert_pem=ca_cert_pem,
    ca_key_encrypted=ca_key_enc,
    ca_password="ca-password-2026",
    valid_days=365,
)

# 3. Sign a sensitive document
content = b"Registro migrante ID-001 — 2026-06-10"
sig_bundle = documents.sign_document(content, key_pem, cert_pem)

# 4. Verify the signature (can be done by any party with the CA cert)
result = documents.verify_document(content, sig_bundle, ca_cert_pem)
assert result["valid"], result["reason"]
print("Signature verified:", result["signer_cn"])
```

---

## Test vectors location

Test vectors for all cryptographic operations are located in `CriptoReto/tests/test_crypto_integration.py`.
