"""
Tests for the registros module.

Covers:
  - ECDSA signature generation
  - Signature verification (valid data)
  - Tamper detection (data modified after signing)
  - Role-based permissions (create, list, edit, delete)
  - ARCO permissions, creation, execution with ECDSA signature, cancellation Admin-only
"""

import io

from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse

from iam.models import Area, Collaborator
from .models import ArcoRequest, MigrantRegistration, MigrantRegistrationSignature, Ticket
from .services import sign_registration, verify_registration


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_user(username, access_level, area=None):
    user = Collaborator.objects.create_user(
        username=username,
        email=f'{username}@casatest.local',
        password='Test1234!',
        access_level=access_level,
        onboarding_status='approved',
        first_name='Test',
        last_name=username.capitalize(),
    )
    user.certificate_delivered_at = user.created_at
    user.area = area
    user.save(update_fields=['certificate_delivered_at', 'area'])
    return user


def _login(client, user):
    """Log in and, for Level-2 coordinators, inject the required cert_validated flag."""
    client.force_login(user)
    if user.access_level == 2:
        session = client.session
        session['cert_validated'] = True
        session.save()


def _make_registration(creator):
    return MigrantRegistration.objects.create(
        full_name='Juana Ramírez López',
        birth_date='1992-06-15',
        gender='femenino',
        nationality='Hondureña',
        country_of_origin='Honduras',
        document_type='pasaporte',
        document_number='HN987654',
        phone='5551234567',
        email='juana@example.com',
        entry_date='2024-03-01',
        entry_point='Tapachula, Chiapas',
        transit_countries='Guatemala',
        intended_destination='Ciudad de México',
        marital_status='soltero',
        travels_alone=True,
        group_size=1,
        minors_in_group=0,
        assistance_requested='legal,alimentaria',
        migration_reason='Escapar de violencia doméstica y buscar refugio.',
        current_legal_status='solicitante_asilo',
        shelter_name='Albergue Casa Monarca',
        emergency_contact_name='Pedro Ramírez',
        emergency_contact_phone='5559876543',
        emergency_contact_relationship='hermano',
        data_consent=True,
        created_by=creator,
        created_by_role=creator.access_level,
    )


# ── Cryptography tests ────────────────────────────────────────────────────────

class SignatureGenerationTest(TestCase):
    def setUp(self):
        self.area = Area.objects.create(slug='test-area', name='Test Area')
        self.user = _make_user('operativo1', 3, area=self.area)
        self.registration = _make_registration(self.user)

    def test_sign_returns_required_keys(self):
        result = sign_registration(self.registration)
        for key in ('message_hash', 'signature_r', 'signature_s', 'public_key', 'curve_name'):
            self.assertIn(key, result, f'Missing key: {key}')

    def test_curve_is_secp256k1(self):
        result = sign_registration(self.registration)
        self.assertEqual(result['curve_name'], 'secp256k1')

    def test_hash_is_64_hex_chars(self):
        result = sign_registration(self.registration)
        self.assertEqual(len(result['message_hash']), 64)
        int(result['message_hash'], 16)  # must be valid hex

    def test_r_and_s_are_positive_integers(self):
        result = sign_registration(self.registration)
        self.assertGreater(int(result['signature_r']), 0)
        self.assertGreater(int(result['signature_s']), 0)


class SignatureVerificationTest(TestCase):
    def setUp(self):
        self.area = Area.objects.create(slug='test-area-v', name='Test Area V')
        self.user = _make_user('coord1', 2, area=self.area)
        self.registration = _make_registration(self.user)
        sig_data = sign_registration(self.registration)
        self.sig = MigrantRegistrationSignature.objects.create(
            registration=self.registration,
            signed_by=self.user,
            signed_by_role=self.user.access_level,
            **sig_data,
        )

    def test_valid_signature_passes(self):
        result = verify_registration(self.registration, self.sig)
        self.assertTrue(result['is_valid'])
        self.assertIsNone(result['error'])

    def test_hash_matches(self):
        result = verify_registration(self.registration, self.sig)
        self.assertEqual(result['message_hash'], result['stored_hash'])


class TamperDetectionTest(TestCase):
    """Modifying any field after signing must invalidate the signature."""

    def setUp(self):
        self.area = Area.objects.create(slug='test-area-t', name='Test Area T')
        self.user = _make_user('admin1', 1, area=self.area)
        self.registration = _make_registration(self.user)
        sig_data = sign_registration(self.registration)
        self.sig = MigrantRegistrationSignature.objects.create(
            registration=self.registration,
            signed_by=self.user,
            signed_by_role=self.user.access_level,
            **sig_data,
        )

    def _tamper_and_verify(self, field, new_value):
        setattr(self.registration, field, new_value)
        self.registration.save(update_fields=[field])
        result = verify_registration(self.registration, self.sig)
        self.assertFalse(result['is_valid'], f'Tamper on "{field}" was NOT detected')

    def test_tamper_full_name(self):
        self._tamper_and_verify('full_name', 'NOMBRE ALTERADO')

    def test_tamper_nationality(self):
        self._tamper_and_verify('nationality', 'Nación Modificada')

    def test_tamper_migration_reason(self):
        self._tamper_and_verify('migration_reason', 'Razón falsificada por atacante.')

    def test_tamper_document_number(self):
        self._tamper_and_verify('document_number', 'FAKE0000')

    def test_hash_mismatch_detected(self):
        """Stored hash no longer matches recomputed hash after tampering."""
        self.registration.full_name = 'Atacante Malicioso'
        self.registration.save(update_fields=['full_name'])
        result = verify_registration(self.registration, self.sig)
        self.assertNotEqual(result['message_hash'], result['stored_hash'])


# ── Role / permission tests ───────────────────────────────────────────────────

class RolePermissionTest(TestCase):
    def setUp(self):
        self.area = Area.objects.create(slug='perm-area', name='Perm Area')
        self.admin     = _make_user('admin_r',   1, area=self.area)
        self.coord     = _make_user('coord_r',   2, area=self.area)
        self.operative = _make_user('oper_r',    3, area=self.area)
        self.external  = _make_user('externo_r', 4, area=self.area)
        self.registration = _make_registration(self.admin)

    # ── Create form accessible by all roles ───────────────────────────────────

    def _can_access_new(self, user):
        c = Client()
        _login(c, user)
        resp = c.get(reverse('registros:registro_new'))
        return resp.status_code == 200

    def test_admin_can_access_new(self):
        self.assertTrue(self._can_access_new(self.admin))

    def test_coord_can_access_new(self):
        self.assertTrue(self._can_access_new(self.coord))

    def test_operative_can_access_new(self):
        self.assertTrue(self._can_access_new(self.operative))

    def test_external_can_access_new(self):
        self.assertTrue(self._can_access_new(self.external))

    # ── List: Level 1–3 only ──────────────────────────────────────────────────

    def _list_status(self, user):
        c = Client()
        _login(c, user)
        return c.get(reverse('registros:registro_list')).status_code

    def test_admin_can_list(self):
        self.assertEqual(self._list_status(self.admin), 200)

    def test_coord_can_list(self):
        self.assertEqual(self._list_status(self.coord), 200)

    def test_operative_can_list(self):
        self.assertEqual(self._list_status(self.operative), 200)

    def test_external_cannot_list(self):
        status = self._list_status(self.external)
        self.assertNotEqual(status, 200)  # redirected away

    # ── Edit: Level 1–2 only ──────────────────────────────────────────────────

    def _edit_status(self, user):
        c = Client()
        _login(c, user)
        url = reverse('registros:registro_edit', kwargs={'pk': self.registration.pk})
        return c.get(url).status_code

    def test_admin_can_edit(self):
        self.assertEqual(self._edit_status(self.admin), 200)

    def test_coord_can_edit(self):
        self.assertEqual(self._edit_status(self.coord), 200)

    def test_operative_cannot_edit(self):
        self.assertNotEqual(self._edit_status(self.operative), 200)

    def test_external_cannot_edit(self):
        self.assertNotEqual(self._edit_status(self.external), 200)

    # ── Delete: Level 1 only ──────────────────────────────────────────────────

    def _delete_and_check(self, user):
        c = Client()
        _login(c, user)
        url = reverse('registros:registro_delete', kwargs={'pk': self.registration.pk})
        c.post(url)
        self.registration.refresh_from_db()
        return self.registration.is_deleted

    def test_admin_can_delete(self):
        self.assertTrue(self._delete_and_check(self.admin))

    def test_coord_cannot_delete(self):
        # Reset in case admin deleted in previous test
        self.registration.is_deleted = False
        self.registration.save()
        self.assertFalse(self._delete_and_check(self.coord))

    def test_operative_cannot_delete(self):
        self.registration.is_deleted = False
        self.registration.save()
        self.assertFalse(self._delete_and_check(self.operative))

    def test_external_cannot_delete(self):
        self.registration.is_deleted = False
        self.registration.save()
        self.assertFalse(self._delete_and_check(self.external))


# ── ARCO tests ────────────────────────────────────────────────────────────────

class ArcoPermissionTest(TestCase):
    """Level 4 (Voluntario) cannot access ARCO views at all."""

    def setUp(self):
        self.area = Area.objects.create(slug='arco-perm', name='ARCO Perm')
        self.admin     = _make_user('arco_admin',  1, area=self.area)
        self.coord     = _make_user('arco_coord',  2, area=self.area)
        self.operative = _make_user('arco_oper',   3, area=self.area)
        self.external  = _make_user('arco_ext',    4, area=self.area)
        self.registration = _make_registration(self.admin)

    def _arco_list_status(self, user):
        c = Client()
        _login(c, user)
        return c.get(reverse('registros:arco_list')).status_code

    def _arco_create_get_status(self, user):
        c = Client()
        _login(c, user)
        url = reverse('registros:arco_create', kwargs={'pk': self.registration.pk})
        return c.get(url).status_code

    def test_admin_can_list_arco(self):
        self.assertEqual(self._arco_list_status(self.admin), 200)

    def test_coord_can_list_arco(self):
        self.assertEqual(self._arco_list_status(self.coord), 200)

    def test_operative_can_list_arco(self):
        self.assertEqual(self._arco_list_status(self.operative), 200)

    def test_external_cannot_list_arco(self):
        """Level 4 must be redirected (not 200)."""
        self.assertNotEqual(self._arco_list_status(self.external), 200)

    def test_external_cannot_create_arco(self):
        self.assertNotEqual(self._arco_create_get_status(self.external), 200)

    def test_operative_can_create_arco(self):
        self.assertEqual(self._arco_create_get_status(self.operative), 200)


class ArcoCreateTest(TestCase):
    """Creating an ARCO case generates a case_id, a Ticket, and the correct initial state."""

    def setUp(self):
        self.area = Area.objects.create(slug='arco-create', name='ARCO Create')
        self.operative = _make_user('arco_create_oper', 3, area=self.area)
        self.coord     = _make_user('arco_create_coord', 2, area=self.area)
        self.registration = _make_registration(self.coord)

    def _post_arco(self, user, arco_type, description, pdf_file=None):
        c = Client()
        _login(c, user)
        url = reverse('registros:arco_create', kwargs={'pk': self.registration.pk})
        data = {'arco_type': arco_type, 'description': description}
        files = {}
        if pdf_file:
            files['attached_document'] = pdf_file
        return c.post(url, {**data, **files})

    def test_create_access_request_generates_case_id(self):
        self._post_arco(self.operative, 'access', 'Solicito conocer todos mis datos almacenados.')
        arco = ArcoRequest.objects.filter(arco_type='access').first()
        self.assertIsNotNone(arco)
        self.assertTrue(arco.case_id.startswith('ARCO-'))
        self.assertEqual(len(arco.case_id), 13)  # 'ARCO-' + 8 hex chars

    def test_create_request_generates_ticket(self):
        self._post_arco(self.operative, 'access', 'Solicito conocer todos mis datos almacenados.')
        arco = ArcoRequest.objects.filter(arco_type='access').first()
        self.assertIsNotNone(arco)
        self.assertIsNotNone(arco.ticket)
        ticket = Ticket.objects.get(pk=arco.ticket.pk)
        self.assertIn(arco.case_id, ticket.summary)

    def test_create_rectification_with_pdf(self):
        pdf_bytes = b'%PDF-1.4 fake pdf content for testing purposes'
        pdf = SimpleUploadedFile('evidencia.pdf', pdf_bytes, content_type='application/pdf')
        self._post_arco(self.operative, 'rectification',
                        'Solicito rectificar mi nombre completo, está mal escrito.', pdf_file=pdf)
        arco = ArcoRequest.objects.filter(arco_type='rectification').first()
        self.assertIsNotNone(arco)
        self.assertTrue(bool(arco.attached_document))

    def test_create_rectification_stores_pdf_only_for_rectification(self):
        pdf_bytes = b'%PDF-1.4 fake pdf'
        pdf = SimpleUploadedFile('doc.pdf', pdf_bytes, content_type='application/pdf')
        self._post_arco(self.operative, 'access',
                        'Solicito conocer mis datos con un archivo adjunto inesperado.', pdf_file=pdf)
        arco = ArcoRequest.objects.filter(arco_type='access').first()
        self.assertIsNotNone(arco)
        # PDF should NOT be stored for non-rectification types
        self.assertFalse(bool(arco.attached_document))

    def test_coord_creates_arco_directly_in_review(self):
        """Coordinador has direct authority → state goes to in_review, no workflow."""
        self._post_arco(self.coord, 'access', 'Solicito acceder a todos los datos almacenados.')
        arco = ArcoRequest.objects.filter(arco_type='access', requested_by=self.coord).first()
        self.assertIsNotNone(arco)
        self.assertEqual(arco.state, ArcoRequest.STATE_IN_REVIEW)
        self.assertIsNone(arco.workflow_request)

    def test_description_too_short_rejected(self):
        resp = self._post_arco(self.operative, 'access', 'Corto')
        self.assertEqual(resp.status_code, 200)  # form re-rendered
        self.assertFalse(ArcoRequest.objects.filter(description='Corto').exists())


class ArcoExecuteSignatureTest(TestCase):
    """Executing an ARCO case must produce an ActionSignature in the hash chain."""

    def setUp(self):
        self.area = Area.objects.create(slug='arco-exec', name='ARCO Exec')
        self.admin = _make_user('arco_exec_admin', 1, area=self.area)
        self.coord = _make_user('arco_exec_coord', 2, area=self.area)
        self.registration = _make_registration(self.admin)

        # Create a UserCertificate for coord so validate_coordinator_cert_and_key works
        from iam.certificates import issue_coordinator_key_cert, get_coordinator_key_bytes
        cert_obj = issue_coordinator_key_cert(self.coord, self.admin)
        cert_pem_bytes = cert_obj.certificate_data.encode('utf-8')
        key_der_bytes = get_coordinator_key_bytes(cert_obj)
        self._cert_pem = cert_pem_bytes
        self._key_der = key_der_bytes

        # Seed a UserCertificate for admin (encrypted)
        from iam.certificates import issue_encrypted_certificate
        issue_encrypted_certificate(self.admin, self.admin)

    def _make_arco(self, user, arco_type='access'):
        arco = ArcoRequest.objects.create(
            arco_type=arco_type,
            registration=self.registration,
            requested_by=user,
            state=ArcoRequest.STATE_SUBMITTED,
            description='Solicito todos los datos almacenados para verificación.',
        )
        return arco

    def test_execute_access_creates_action_signature(self):
        arco = self._make_arco(self.coord)
        c = Client()
        _login(c, self.coord)
        url = reverse('registros:arco_execute', kwargs={'pk': arco.pk})
        resp = c.post(url, {
            'password': 'Test1234!',
            'notes': 'Ejecutado en test',
            'cert_file': SimpleUploadedFile('test.cert', self._cert_pem, content_type='application/octet-stream'),
            'key_file': SimpleUploadedFile('test.key', self._key_der, content_type='application/octet-stream'),
        })
        arco.refresh_from_db()
        self.assertEqual(arco.state, ArcoRequest.STATE_EXECUTED)
        self.assertIsNotNone(arco.action_signature)
        self.assertEqual(arco.action_signature.subject_type, 'arco_request')
        self.assertEqual(arco.action_signature.subject_id, arco.pk)

    def test_execute_access_generates_pdf(self):
        arco = self._make_arco(self.coord)
        c = Client()
        _login(c, self.coord)
        url = reverse('registros:arco_execute', kwargs={'pk': arco.pk})
        c.post(url, {
            'password': 'Test1234!',
            'notes': '',
            'cert_file': SimpleUploadedFile('test.cert', self._cert_pem),
            'key_file': SimpleUploadedFile('test.key', self._key_der),
        })
        arco.refresh_from_db()
        self.assertTrue(bool(arco.generated_document))

    def test_execute_wrong_password_fails(self):
        arco = self._make_arco(self.coord)
        c = Client()
        _login(c, self.coord)
        url = reverse('registros:arco_execute', kwargs={'pk': arco.pk})
        c.post(url, {
            'password': 'WrongPassword!',
            'notes': '',
            'cert_file': SimpleUploadedFile('test.cert', self._cert_pem),
            'key_file': SimpleUploadedFile('test.key', self._key_der),
        })
        arco.refresh_from_db()
        self.assertNotEqual(arco.state, ArcoRequest.STATE_EXECUTED)

    def test_execute_missing_cert_fails(self):
        arco = self._make_arco(self.coord)
        c = Client()
        _login(c, self.coord)
        url = reverse('registros:arco_execute', kwargs={'pk': arco.pk})
        c.post(url, {'password': 'Test1234!', 'notes': ''})
        arco.refresh_from_db()
        self.assertNotEqual(arco.state, ArcoRequest.STATE_EXECUTED)


class ArcoCancellationAdminOnlyTest(TestCase):
    """Only Admin (level 1) can execute a Cancelación ARCO."""

    def setUp(self):
        self.area = Area.objects.create(slug='arco-cancel', name='ARCO Cancel')
        self.admin = _make_user('arco_cancel_admin', 1, area=self.area)
        self.coord = _make_user('arco_cancel_coord', 2, area=self.area)
        self.registration = _make_registration(self.admin)

        from iam.certificates import issue_coordinator_key_cert, get_coordinator_key_bytes
        cert_obj = issue_coordinator_key_cert(self.coord, self.admin)
        self._cert_pem = cert_obj.certificate_data.encode('utf-8')
        self._key_der = get_coordinator_key_bytes(cert_obj)

        from iam.certificates import issue_encrypted_certificate
        admin_cert = issue_encrypted_certificate(self.admin, self.admin)
        from iam.certificates import encrypt_certificate, generate_certificate_payload
        self._admin_cert_str = admin_cert.certificate_data

    def _make_cancellation_arco(self):
        return ArcoRequest.objects.create(
            arco_type='cancellation',
            registration=self.registration,
            requested_by=self.admin,
            state=ArcoRequest.STATE_SUBMITTED,
            description='Solicitud formal de cancelación de todos los datos personales.',
        )

    def test_coord_cannot_execute_cancellation(self):
        arco = self._make_cancellation_arco()
        c = Client()
        _login(c, self.coord)
        url = reverse('registros:arco_execute', kwargs={'pk': arco.pk})
        c.post(url, {
            'password': 'Test1234!',
            'notes': '',
            'cert_file': SimpleUploadedFile('test.cert', self._cert_pem),
            'key_file': SimpleUploadedFile('test.key', self._key_der),
        })
        arco.refresh_from_db()
        self.assertNotEqual(arco.state, ArcoRequest.STATE_EXECUTED)
        # Registration should NOT be deleted
        self.registration.refresh_from_db()
        self.assertFalse(self.registration.is_deleted)

    def test_admin_can_execute_cancellation(self):
        arco = self._make_cancellation_arco()
        c = Client()
        _login(c, self.admin)
        url = reverse('registros:arco_execute', kwargs={'pk': arco.pk})
        c.post(url, {
            'password': 'Test1234!',
            'notes': 'Eliminación solicitada por el titular.',
            'cert_file': SimpleUploadedFile(
                'admin.cert',
                self._admin_cert_str.encode('utf-8'),
                content_type='text/plain',
            ),
        })
        arco.refresh_from_db()
        self.assertEqual(arco.state, ArcoRequest.STATE_EXECUTED)
        self.registration.refresh_from_db()
        self.assertTrue(self.registration.is_deleted)
