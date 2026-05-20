"""
Tests for the registros module.

Covers:
  - ECDSA signature generation
  - Signature verification (valid data)
  - Tamper detection (data modified after signing)
  - Role-based permissions (create, list, edit, delete)
"""

from django.test import Client, TestCase
from django.urls import reverse

from iam.models import Area, Collaborator
from .models import MigrantRegistration, MigrantRegistrationSignature
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
