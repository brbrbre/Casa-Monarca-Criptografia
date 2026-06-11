"""
Casa Monarca Cryptography SDK.

Public API covering the six PKI subsystems of the MA2006B reto:

    (a) identity      — Certificate lifecycle management
    (b) documents     — Document signing, verification, and encryption
    (c) email_sign    — Email content and attachment signing
    (d) forms         — Signed form creation and verification
    (e) verification  — External public-key document verification
    (f) key_manager   — Secret key protection with public-key cryptography

All modules depend solely on the `cryptography` library (pyca/cryptography).
No Django ORM dependency — this SDK is usable standalone.

Example:
    from sdk import identity, documents

    ca_cert_pem, ca_key_enc = identity.generate_ca("strong-password")
    cert_pem, key_pem = identity.issue_certificate(
        user_id=1, username="mariel", role="admin", area="Administracion",
        ca_cert_pem=ca_cert_pem, ca_key_encrypted=ca_key_enc,
        ca_password="strong-password",
    )
    signed = documents.sign_document(b"Sensitive content", key_pem, cert_pem)
    result = documents.verify_document(b"Sensitive content", signed, ca_cert_pem)
    print(result["valid"])  # True
"""

__version__ = "1.0.0"
__all__ = ["identity", "documents", "email_sign", "forms", "verification", "key_manager"]
