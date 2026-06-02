"""
Pruebas de integración criptográfica — Casa Monarca.

Ejecutar:
    cd CriptoReto && python -m pytest tests/test_crypto_integration.py -v
    # o con Django test runner:
    python manage.py test tests.test_crypto_integration

Estas pruebas verifican que la capa crypto_core funciona correctamente
y que las reglas de negocio criptográficas se cumplen.
"""

import base64
import json
import os
import tempfile
import pytest

# Configurar django antes de importar modelos
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'casamonarca.settings')

# ── Pruebas puras de crypto_core (sin Django) ─────────────────────────────────

class TestCAGeneration:
    """Pruebas de la CA interna."""

    def test_generate_ca_keypair_creates_valid_cert(self):
        from crypto_core.ca import generate_ca_keypair, load_ca, get_ca_fingerprint
        cert_pem, key_enc = generate_ca_keypair('test_password_123')

        assert cert_pem.startswith(b'-----BEGIN CERTIFICATE-----')
        assert isinstance(key_enc, str)
        assert ':' in key_enc

        ca_cert, ca_key = load_ca(cert_pem, key_enc, 'test_password_123')
        fingerprint = get_ca_fingerprint(cert_pem)
        assert len(fingerprint) > 30
        assert ':' in fingerprint

    def test_wrong_ca_password_raises(self):
        from crypto_core.ca import generate_ca_keypair, load_ca
        cert_pem, key_enc = generate_ca_keypair('correct_password')
        with pytest.raises(ValueError, match='Contraseña incorrecta|descifrar'):
            load_ca(cert_pem, key_enc, 'wrong_password')


class TestCertificateEmission:
    """Pruebas de emisión de certificados X.509."""

    @pytest.fixture
    def ca_material(self):
        from crypto_core.ca import generate_ca_keypair, load_ca
        cert_pem, key_enc = generate_ca_keypair('ca_pass_test')
        ca_cert, ca_key = load_ca(cert_pem, key_enc, 'ca_pass_test')
        return ca_cert, ca_key, cert_pem

    def test_emit_certificate_admin_succeeds(self, ca_material):
        from crypto_core.certificates import emit_certificate, get_cert_metadata
        ca_cert, ca_key, _ = ca_material
        cert_pem, key_pem = emit_certificate(1, 'admin_test', 'admin', 'TI', ca_cert, ca_key)
        assert cert_pem.startswith(b'-----BEGIN CERTIFICATE-----')
        assert key_pem.startswith(b'-----BEGIN PRIVATE KEY-----')
        meta = get_cert_metadata(cert_pem)
        assert meta['common_name'] == 'admin_test'
        assert meta['user_id_from_cert'] == '1'

    def test_emit_certificate_coordinador_succeeds(self, ca_material):
        from crypto_core.certificates import emit_certificate
        ca_cert, ca_key, _ = ca_material
        cert_pem, key_pem = emit_certificate(2, 'coord_test', 'coordinador', 'Legal', ca_cert, ca_key)
        assert cert_pem.startswith(b'-----BEGIN CERTIFICATE-----')

    def test_certificate_only_for_privileged_roles(self, ca_material):
        """Verificar que operativo y externo no pueden obtener certificados."""
        from crypto_core.certificates import emit_certificate
        ca_cert, ca_key, _ = ca_material
        with pytest.raises(ValueError, match='role|rol|permitido'):
            emit_certificate(3, 'oper_test', 'operativo', 'Humanitaria', ca_cert, ca_key)

    def test_certificate_externo_raises(self, ca_material):
        from crypto_core.certificates import emit_certificate
        ca_cert, ca_key, _ = ca_material
        with pytest.raises(ValueError, match='role|rol|permitido'):
            emit_certificate(4, 'ext_test', 'externo', 'Comunicación', ca_cert, ca_key)

    def test_certificate_signed_by_ca(self, ca_material):
        """El certificado emitido debe verificarse contra la CA."""
        from crypto_core.certificates import emit_certificate, verify_certificate
        ca_cert, ca_key, ca_cert_pem = ca_material
        cert_pem, _ = emit_certificate(1, 'admin2', 'admin', 'TI', ca_cert, ca_key)
        result = verify_certificate(cert_pem, ca_cert_pem)
        assert result['valid'] is True
        assert result['reason'] == 'ok'

    def test_self_signed_cert_fails_ca_verification(self, ca_material):
        """Un certificado auto-firmado no debe pasar la verificación de la CA."""
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        from datetime import datetime, timezone, timedelta
        from crypto_core.certificates import verify_certificate

        _, _, ca_cert_pem = ca_material

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fake')])
        fake_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .sign(private_key, hashes.SHA256())
        )
        fake_cert_pem = fake_cert.public_bytes(serialization.Encoding.PEM)
        result = verify_certificate(fake_cert_pem, ca_cert_pem)
        assert result['valid'] is False
        assert 'firma' in result['reason'] or 'invalid' in result['reason'].lower()

    def test_revoked_cert_fails_verification(self, ca_material):
        """Un certificado revocado no debe pasar la verificación."""
        from crypto_core.certificates import emit_certificate, verify_certificate, get_cert_metadata
        ca_cert, ca_key, ca_cert_pem = ca_material
        cert_pem, _ = emit_certificate(1, 'admin_rev', 'admin', 'TI', ca_cert, ca_key)
        meta = get_cert_metadata(cert_pem)
        serial = meta['serial_number']

        result = verify_certificate(cert_pem, ca_cert_pem, revoked_serials={serial})
        assert result['valid'] is False
        assert 'revocado' in result['reason']

    def test_key_matches_cert(self, ca_material):
        from crypto_core.certificates import emit_certificate, check_key_matches_cert
        ca_cert, ca_key, _ = ca_material
        cert_pem, key_pem = emit_certificate(1, 'admin3', 'admin', 'TI', ca_cert, ca_key)
        assert check_key_matches_cert(cert_pem, key_pem) is True

    def test_wrong_key_does_not_match_cert(self, ca_material):
        from crypto_core.certificates import emit_certificate, check_key_matches_cert
        ca_cert, ca_key, _ = ca_material
        cert_pem, _ = emit_certificate(1, 'admin4', 'admin', 'TI', ca_cert, ca_key)
        _, other_key_pem = emit_certificate(2, 'coord4', 'coordinador', 'Legal', ca_cert, ca_key)
        assert check_key_matches_cert(cert_pem, other_key_pem) is False


class TestSignatures:
    """Pruebas de firma de flujos finales."""

    @pytest.fixture
    def ca_and_cert(self):
        from crypto_core.ca import generate_ca_keypair, load_ca
        from crypto_core.certificates import emit_certificate
        cert_pem_ca, key_enc = generate_ca_keypair('ca_sig_test')
        ca_cert, ca_key = load_ca(cert_pem_ca, key_enc, 'ca_sig_test')
        cert_pem, private_key_pem = emit_certificate(1, 'admin_sig', 'admin', 'TI', ca_cert, ca_key)
        return cert_pem_ca, cert_pem, private_key_pem

    def test_signed_log_is_verifiable(self, ca_and_cert):
        """Un log firmado por admin puede verificarse con la CA pública."""
        from crypto_core.signatures import (
            FinalFlowAction, sign_final_flow_log, verify_signed_log, build_log_data,
        )
        ca_cert_pem, cert_pem, key_pem = ca_and_cert
        log_data = build_log_data(
            action=FinalFlowAction.ACCEPT_USER_REGISTRATION,
            performed_by_user_id=1,
            performed_by_username='admin_sig',
            target_id=10,
            target_type='migrant_registration',
            details={'previous_status': 'pendiente', 'new_status': 'activo'},
        )
        signed = sign_final_flow_log(log_data, key_pem, cert_pem, ca_cert_pem)
        assert signed.verified is True
        assert signed.signature_b64
        assert len(signed.cert_fingerprint) == 64

        is_valid = verify_signed_log(signed, ca_cert_pem)
        assert is_valid is True

    def test_sign_log_requires_valid_cert(self, ca_and_cert):
        """No se puede firmar con un certificado revocado."""
        from crypto_core.certificates import get_cert_metadata
        from crypto_core.signatures import (
            FinalFlowAction, sign_final_flow_log, build_log_data,
        )
        ca_cert_pem, cert_pem, key_pem = ca_and_cert
        meta = get_cert_metadata(cert_pem)
        serial = meta['serial_number']

        log_data = build_log_data(
            action=FinalFlowAction.DELETE_RECORD,
            performed_by_user_id=1,
            performed_by_username='admin_sig',
            target_id=5,
            target_type='migrant_registration',
        )
        with pytest.raises(PermissionError, match='revocado|invalid'):
            sign_final_flow_log(log_data, key_pem, cert_pem, ca_cert_pem,
                                revoked_serials={serial})

    def test_invalid_action_raises(self, ca_and_cert):
        """Una acción que no es flujo final debe rechazarse."""
        from crypto_core.signatures import sign_final_flow_log
        ca_cert_pem, cert_pem, key_pem = ca_and_cert
        bad_log = {
            'action': 'login',  # no es flujo final
            'timestamp': '2026-01-01T00:00:00Z',
            'performed_by_user_id': 1,
            'performed_by_username': 'admin',
            'target_id': 1,
            'target_type': 'session',
            'details': {},
            'system_hash': '',
        }
        with pytest.raises(ValueError, match='flujo final|válido'):
            sign_final_flow_log(bad_log, key_pem, cert_pem, ca_cert_pem)

    def test_tampered_log_fails_verification(self, ca_and_cert):
        """Modificar el log_data después de firmar debe invalidar la firma."""
        from crypto_core.signatures import (
            FinalFlowAction, SignedLog, sign_final_flow_log, verify_signed_log, build_log_data,
        )
        ca_cert_pem, cert_pem, key_pem = ca_and_cert
        log_data = build_log_data(
            action=FinalFlowAction.AUTHORIZE_DOCUMENT,
            performed_by_user_id=1,
            performed_by_username='admin_sig',
            target_id=7,
            target_type='document',
        )
        signed = sign_final_flow_log(log_data, key_pem, cert_pem, ca_cert_pem)

        tampered = SignedLog(
            log_data={**signed.log_data, 'target_id': 999},
            signature_b64=signed.signature_b64,
            cert_fingerprint=signed.cert_fingerprint,
            cert_pem=cert_pem,
        )
        assert verify_signed_log(tampered, ca_cert_pem) is False
        assert tampered.error and 'firma' in tampered.error


class TestEncryption:
    """Pruebas del cifrado AES-256-GCM."""

    @pytest.fixture
    def key(self):
        from crypto_core.encryption import derive_key
        import secrets
        salt = secrets.token_bytes(16)
        return derive_key('test_master_password_123', salt)

    def test_encrypt_decrypt_roundtrip(self, key):
        from crypto_core.encryption import encrypt_field, decrypt_field
        plaintext = 'Juan García López'
        encrypted = encrypt_field(plaintext, key)
        assert encrypted != plaintext
        assert '-----' not in encrypted
        decrypted = decrypt_field(encrypted, key)
        assert decrypted == plaintext

    def test_encrypted_value_looks_random(self, key):
        """Dos cifrados del mismo texto deben producir ciphertexts distintos."""
        from crypto_core.encryption import encrypt_field
        enc1 = encrypt_field('mismo texto', key)
        enc2 = encrypt_field('mismo texto', key)
        assert enc1 != enc2

    def test_tampered_ciphertext_raises(self, key):
        """Modificar el ciphertext debe fallar la verificación GCM."""
        from crypto_core.encryption import encrypt_field, decrypt_field
        encrypted = encrypt_field('dato sensible', key)
        # Modificar último byte del base64
        raw = base64.urlsafe_b64decode(encrypted)
        tampered = bytearray(raw)
        tampered[-1] ^= 0xFF
        tampered_b64 = base64.urlsafe_b64encode(bytes(tampered)).decode()
        with pytest.raises(ValueError, match='manipulados|GCM|descifrar'):
            decrypt_field(tampered_b64, key)

    def test_sensitive_fields_are_encrypted_in_model_dict(self, key):
        """nombre_completo nunca aparece en plaintext en el dict cifrado."""
        from crypto_core.encryption import encrypt_dict_fields, SENSITIVE_FIELDS
        data = {
            'full_name': 'María López',
            'birth_date': '1990-05-15',
            'nationality': 'Hondureña',
            'area': 'humanitaria',  # no sensible
            'status': 'activo',     # no sensible
        }
        encrypted = encrypt_dict_fields(data, key)
        assert encrypted['full_name'] != 'María López'
        assert encrypted['area'] == 'humanitaria'
        assert encrypted['status'] == 'activo'

    def test_wrong_key_fails_decryption(self):
        """Una clave diferente no puede descifrar."""
        from crypto_core.encryption import derive_key, encrypt_field, decrypt_field
        import secrets
        key1 = derive_key('password_uno', secrets.token_bytes(16))
        key2 = derive_key('password_dos', secrets.token_bytes(16))
        encrypted = encrypt_field('secret', key1)
        with pytest.raises(ValueError):
            decrypt_field(encrypted, key2)

    def test_pbkdf2_produces_32_byte_key(self):
        from crypto_core.encryption import derive_key
        key = derive_key('any_password', b'\x00' * 16)
        assert len(key) == 32

    def test_raw_password_rejected(self, key):
        """Pasar una contraseña string directamente a encrypt_field debe fallar."""
        from crypto_core.encryption import encrypt_field
        with pytest.raises(TypeError, match='32 bytes|derive_key'):
            encrypt_field('data', 'plaintext_password')


class TestHashing:
    """Pruebas de integridad SHA-256."""

    def test_hash_document_is_64_hex_chars(self):
        from crypto_core.hashing import hash_document
        result = hash_document(b'test content')
        assert len(result) == 64
        int(result, 16)

    def test_verify_document_integrity_pass(self):
        from crypto_core.hashing import hash_document, verify_document_integrity
        content = b'documento importante'
        h = hash_document(content)
        assert verify_document_integrity(content, h) is True

    def test_verify_document_integrity_fail(self):
        from crypto_core.hashing import hash_document, verify_document_integrity
        content = b'documento original'
        h = hash_document(content)
        assert verify_document_integrity(b'documento modificado', h) is False

    def test_hash_db_state_deterministic(self):
        from crypto_core.hashing import hash_db_state
        tables = {
            'users': [{'id': 1, 'username': 'admin'}, {'id': 2, 'username': 'coord'}],
            'certs': [{'id': 1, 'fingerprint': 'abc123', 'status': 'ACTIVE'}],
        }
        h1 = hash_db_state(tables)
        h2 = hash_db_state(tables)
        assert h1 == h2
        assert len(h1) == 64

    def test_hash_db_state_detects_change(self):
        from crypto_core.hashing import hash_db_state
        t1 = {'users': [{'id': 1, 'status': 'activo'}]}
        t2 = {'users': [{'id': 1, 'status': 'revocado'}]}
        assert hash_db_state(t1) != hash_db_state(t2)


class TestAuthTokens:
    """Pruebas de JWT — requiere JWT_SECRET_KEY en entorno."""

    @pytest.fixture(autouse=True)
    def set_jwt_secret(self, monkeypatch):
        monkeypatch.setenv('JWT_SECRET_KEY', 'test_jwt_secret_key_for_tests_only_32c')

    def _try_jwt(self):
        try:
            import jwt
            return jwt
        except ImportError:
            pytest.skip('PyJWT no instalado — instala con: pip install PyJWT')

    def test_jwt_does_not_include_private_key(self):
        """El JWT no debe contener ninguna clave criptográfica."""
        pyjwt = self._try_jwt()
        from crypto_core.auth_tokens import generate_token, verify_token
        token = generate_token(
            user_id=1, username='admin', role='admin',
            area='TI', has_certificate=True,
        )
        payload = verify_token(token)
        assert 'private_key' not in payload
        assert 'cert_pem' not in payload
        assert 'ca_key' not in payload
        assert 'password' not in payload

    def test_jwt_contains_expected_claims(self):
        pyjwt = self._try_jwt()
        from crypto_core.auth_tokens import generate_token, verify_token
        token = generate_token(
            user_id=42, username='coord_legal', role='coordinador',
            area='Legal', has_certificate=True,
        )
        payload = verify_token(token)
        assert payload['sub'] == '42'
        assert payload['username'] == 'coord_legal'
        assert payload['role'] == 'coordinador'
        assert payload['has_certificate'] is True

    def test_private_key_claim_raises(self):
        pyjwt = self._try_jwt()
        from crypto_core.auth_tokens import generate_token
        with pytest.raises(ValueError, match='private_key|claim'):
            generate_token(
                user_id=1, username='admin', role='admin',
                area='TI', has_certificate=True,
                extra_claims={'private_key': 'secret'},
            )

    def test_expired_token_raises(self):
        pyjwt = self._try_jwt()
        import jwt
        from crypto_core.auth_tokens import verify_token
        # Generar token ya expirado
        expired_payload = {
            'sub': '1', 'username': 'admin', 'role': 'admin',
            'exp': 1,  # timestamp en el pasado (Unix epoch + 1s)
            'iat': 0,
        }
        token = jwt.encode(expired_payload, 'test_jwt_secret_key_for_tests_only_32c', algorithm='HS256')
        with pytest.raises(jwt.ExpiredSignatureError):
            verify_token(token)


class TestOperativoCannotSign:
    """Verifica que un operativo no puede firmar flujos finales."""

    def test_operativo_cannot_sign_final_flows(self):
        """Un operativo no puede firmar porque no puede tener certificado."""
        from crypto_core.certificates import emit_certificate
        from crypto_core.ca import generate_ca_keypair, load_ca

        cert_pem_ca, key_enc = generate_ca_keypair('ca_op_test')
        ca_cert, ca_key = load_ca(cert_pem_ca, key_enc, 'ca_op_test')

        with pytest.raises(ValueError, match='role|rol|permitido|operativo'):
            emit_certificate(3, 'oper_1', 'operativo', 'Humanitaria', ca_cert, ca_key)

    def test_signing_level_check_in_services(self):
        """sign_action debe rechazar nivel 3/4."""
        from unittest.mock import MagicMock
        import sys
        # Solo probar la lógica de nivel, sin BD
        signer = MagicMock()
        signer.access_level = 3

        # Importar la función y verificar que lanza la excepción antes de tocar la BD
        import importlib
        # Cargamos el módulo con importación lazy del modelo
        from registros import services
        original_sign_bytes = services._sign_bytes
        services._sign_bytes = MagicMock(return_value={})

        try:
            with pytest.raises(PermissionError, match='nivel|Nivel|coordinador|admin'):
                services.sign_action('registration', 1, {}, signer)
        finally:
            services._sign_bytes = original_sign_bytes
