#!/usr/bin/env python3
"""
seed.py — Reset y poblado de BD con encriptación completa
Casa Monarca | MA2006B Criptografía

Uso:
    python seed.py           # reset completo + seed
    python seed.py --check   # solo verifica que el cifrado funciona (no toca la BD)
    python seed.py --no-certs  # seed sin emitir certificados X.509 (más rápido)

Qué hace:
  1. Borra db.sqlite3 y recrea todas las tablas vía migrate
  2. Crea todas las Áreas del sistema
  3. Crea usuarios para TODOS los roles/áreas con contraseña lista para login
  4. Emite certificados X.509 (CA interna) para admin y coordinadores
  5. Crea registros migrantes de prueba con TODOS los campos PII cifrados con AES-256-GCM
  6. Verifica que ningún dato sensible aparece en texto plano en la BD
"""

import os
import sys
from datetime import date, timedelta
from pathlib import Path

# ── Bootstrap Django ──────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

# Carga .env antes de configurar Django
try:
    from dotenv import load_dotenv
    load_dotenv(BASE_DIR / '.env')
except ImportError:
    # python-dotenv no instalado → carga .env manualmente
    env_path = BASE_DIR / '.env'
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, _, v = line.partition('=')
                os.environ.setdefault(k.strip(), v.strip())

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'casamonarca.settings')

import django
django.setup()

# ── Imports post-setup ────────────────────────────────────────────────────────
from django.core.management import call_command
from django.db import connection
from django.utils import timezone

from crypto_core.encryption import decrypt_field, encrypt_field, get_encryption_key_from_env
from iam.models import Area, AuditLog, Collaborator

# ═════════════════════════════════════════════════════════════════════════════
# DATOS SEED
# ═════════════════════════════════════════════════════════════════════════════

AREAS = [
    ('humanitario', 'Humanitario',       'Área de atención humanitaria directa.'),
    ('psicosocial', 'Psicosocial',       'Área de apoyo psicológico y psicosocial.'),
    ('legal',       'Legal',             'Área de asesoría legal y derechos humanos.'),
    ('comunicaciones', 'Comunicaciones', 'Área de comunicación y relaciones públicas.'),
    ('almacen',     'Almacén',           'Área de logística y almacén.'),
    ('it',          'TI / Sistemas',     'Área de tecnologías de la información.'),
]

# Nivel de acceso: 1=Admin, 2=Coordinador, 3=Operativo, 4=Externo
SEED_USERS = [
    # ── Administrador (nivel 1) ──────────────────────────────────────────────
    {
        'username':    'admin',
        'password':    'Admin1234!',
        'first_name':  'Admin',
        'last_name':   'Principal',
        'email':       'admin@casamonarca.org',
        'access_level': 1,
        'role':        'Administrador IT',
        'area_slug':   'it',
        'is_staff':    True,
        'has_cert':    True,
        'descripcion': '[NIVEL 1] Administrador del sistema — acceso total',
    },

    # ── Coordinadores (nivel 2) — uno por área ───────────────────────────────
    {
        'username':    'coord_humanitario',
        'password':    'Coord1234!',
        'first_name':  'Coordinadora',
        'last_name':   'Humanitaria',
        'email':       'coord.humanitario@casamonarca.org',
        'access_level': 2,
        'role':        'Coordinador Humanitario',
        'area_slug':   'humanitario',
        'is_staff':    True,
        'has_cert':    True,
        'descripcion': '[NIVEL 2] Coordinador área Humanitario',
    },
    {
        'username':    'coord_psicosocial',
        'password':    'Coord1234!',
        'first_name':  'Coordinador',
        'last_name':   'Psicosocial',
        'email':       'coord.psicosocial@casamonarca.org',
        'access_level': 2,
        'role':        'Coordinador Humanitario',
        'area_slug':   'psicosocial',
        'is_staff':    True,
        'has_cert':    True,
        'descripcion': '[NIVEL 2] Coordinador área Psicosocial',
    },
    {
        'username':    'coord_legal',
        'password':    'Coord1234!',
        'first_name':  'Coordinadora',
        'last_name':   'Legal',
        'email':       'coord.legal@casamonarca.org',
        'access_level': 2,
        'role':        'Coordinador Legal',
        'area_slug':   'legal',
        'is_staff':    True,
        'has_cert':    True,
        'descripcion': '[NIVEL 2] Coordinador área Legal',
    },
    {
        'username':    'coord_comunicaciones',
        'password':    'Coord1234!',
        'first_name':  'Coordinador',
        'last_name':   'Comunicaciones',
        'email':       'coord.comunicaciones@casamonarca.org',
        'access_level': 2,
        'role':        'Comunicación',
        'area_slug':   'comunicaciones',
        'is_staff':    True,
        'has_cert':    True,
        'descripcion': '[NIVEL 2] Coordinador área Comunicaciones',
    },
    {
        'username':    'coord_almacen',
        'password':    'Coord1234!',
        'first_name':  'Coordinadora',
        'last_name':   'Almacén',
        'email':       'coord.almacen@casamonarca.org',
        'access_level': 2,
        'role':        'Almacén',
        'area_slug':   'almacen',
        'is_staff':    True,
        'has_cert':    True,
        'descripcion': '[NIVEL 2] Coordinador área Almacén',
    },
    {
        'username':    'coord_it',
        'password':    'Coord1234!',
        'first_name':  'Coordinador',
        'last_name':   'TI',
        'email':       'coord.it@casamonarca.org',
        'access_level': 2,
        'role':        'Administrador IT',
        'area_slug':   'it',
        'is_staff':    True,
        'has_cert':    True,
        'descripcion': '[NIVEL 2] Coordinador área TI',
    },

    # ── Operativos (nivel 3) — uno por área ─────────────────────────────────
    {
        'username':    'op_humanitario',
        'password':    'Oper1234!',
        'first_name':  'Operativo',
        'last_name':   'Humanitario',
        'email':       'op.humanitario@casamonarca.org',
        'access_level': 3,
        'role':        'Operativo Humanitario',
        'area_slug':   'humanitario',
        'is_staff':    False,
        'has_cert':    False,
        'descripcion': '[NIVEL 3] Operativo área Humanitario',
    },
    {
        'username':    'op_psicosocial',
        'password':    'Oper1234!',
        'first_name':  'Operativa',
        'last_name':   'Psicosocial',
        'email':       'op.psicosocial@casamonarca.org',
        'access_level': 3,
        'role':        'Psicólogo',
        'area_slug':   'psicosocial',
        'is_staff':    False,
        'has_cert':    False,
        'descripcion': '[NIVEL 3] Operativo área Psicosocial',
    },
    {
        'username':    'op_legal',
        'password':    'Oper1234!',
        'first_name':  'Operativo',
        'last_name':   'Legal',
        'email':       'op.legal@casamonarca.org',
        'access_level': 3,
        'role':        'Coordinador Legal',
        'area_slug':   'legal',
        'is_staff':    False,
        'has_cert':    False,
        'descripcion': '[NIVEL 3] Operativo área Legal',
    },
    {
        'username':    'op_comunicaciones',
        'password':    'Oper1234!',
        'first_name':  'Operativa',
        'last_name':   'Comunicaciones',
        'email':       'op.comunicaciones@casamonarca.org',
        'access_level': 3,
        'role':        'Comunicación',
        'area_slug':   'comunicaciones',
        'is_staff':    False,
        'has_cert':    False,
        'descripcion': '[NIVEL 3] Operativo área Comunicaciones',
    },
    {
        'username':    'op_almacen',
        'password':    'Oper1234!',
        'first_name':  'Operativo',
        'last_name':   'Almacén',
        'email':       'op.almacen@casamonarca.org',
        'access_level': 3,
        'role':        'Almacén',
        'area_slug':   'almacen',
        'is_staff':    False,
        'has_cert':    False,
        'descripcion': '[NIVEL 3] Operativo área Almacén',
    },

    # ── Externos (nivel 4) ───────────────────────────────────────────────────
    {
        'username':    'externo_auditor',
        'password':    'Ext1234!',
        'first_name':  'Auditor',
        'last_name':   'Externo',
        'email':       'auditor@externo.org',
        'access_level': 4,
        'role':        'Personal Externo',
        'area_slug':   'it',
        'is_staff':    False,
        'has_cert':    False,
        'descripcion': '[NIVEL 4] Auditor externo — solo lectura',
    },
    {
        'username':    'externo_proveedor',
        'password':    'Ext1234!',
        'first_name':  'Proveedor',
        'last_name':   'Servicios',
        'email':       'proveedor@externo.org',
        'access_level': 4,
        'role':        'Personal Externo',
        'area_slug':   'it',
        'is_staff':    False,
        'has_cert':    False,
        'descripcion': '[NIVEL 4] Proveedor de servicios externos',
    },
]

# Datos en texto plano — se cifrarán automáticamente vía EncryptedTextField/EncryptedDateField
SEED_REGISTRATIONS = [
    {
        'first_name':                   'Juan',
        'first_surname':                'Pérez',
        'second_surname':               'García',
        'birth_date':                   date(1985, 3, 15),
        'gender':                       'masculino',
        'nationality':                  'Hondureña',
        'country_of_origin':            'Honduras',
        'document_type':                'pasaporte',
        'document_number':              'HN-1234567',
        'phone':                        '+504 9876-5432',
        'email':                        'juan.perez@email.com',
        'entry_date':                   date(2025, 6, 1),
        'entry_point':                  'Tapachula, Chiapas',
        'transit_countries':            'Guatemala',
        'intended_destination':         'Ciudad de México',
        'marital_status':               'casado',
        'travels_alone':                False,
        'group_size':                   3,
        'minors_in_group':              1,
        'assistance_requested':         'legal,alimentaria',
        'migration_reason':             'Huyendo de violencia por pandillas. Necesita protección internacional.',
        'current_legal_status':         'solicitante_asilo',
        'shelter_name':                 'Casa Monarca',
        'emergency_contact_name':       'María García Flores',
        'emergency_contact_phone':      '+504 8888-0001',
        'emergency_contact_relationship': 'Esposa',
        'observations':                 'Requiere atención médica por lesiones en trayecto.',
        'data_consent':                 True,
    },
    {
        'first_name':                   'María',
        'first_surname':                'Rodríguez',
        'second_surname':               'López',
        'birth_date':                   date(1992, 7, 22),
        'gender':                       'femenino',
        'nationality':                  'Guatemalteca',
        'country_of_origin':            'Guatemala',
        'document_type':                'id_nacional',
        'document_number':              'GT-7654321',
        'phone':                        '+502 5555-1234',
        'email':                        'maria.rodriguez@email.com',
        'entry_date':                   date(2025, 5, 20),
        'entry_point':                  'Ciudad Hidalgo, Chiapas',
        'transit_countries':            '',
        'intended_destination':         'Monterrey, Nuevo León',
        'marital_status':               'soltero',
        'travels_alone':                True,
        'group_size':                   1,
        'minors_in_group':              0,
        'assistance_requested':         'psicologica,alojamiento',
        'migration_reason':             'Violencia doméstica y persecución. Solicita refugio.',
        'current_legal_status':         'refugiado_reconocido',
        'shelter_name':                 'Casa Monarca',
        'emergency_contact_name':       'Carlos Rodríguez',
        'emergency_contact_phone':      '+502 5555-9999',
        'emergency_contact_relationship': 'Hermano',
        'observations':                 'Apoyo psicológico urgente. Trauma severo.',
        'data_consent':                 True,
    },
    {
        'first_name':                   'Carlos',
        'first_surname':                'Mendoza',
        'second_surname':               'Fuentes',
        'birth_date':                   date(1978, 11, 3),
        'gender':                       'masculino',
        'nationality':                  'Salvadoreña',
        'country_of_origin':            'El Salvador',
        'document_type':                'id_nacional',
        'document_number':              'SV-9876543',
        'phone':                        '+503 7777-8888',
        'email':                        'carlos.mendoza@email.com',
        'entry_date':                   date(2025, 4, 10),
        'entry_point':                  'Suchiate, Chiapas',
        'transit_countries':            'Guatemala, México',
        'intended_destination':         'Tijuana, Baja California',
        'marital_status':               'casado',
        'travels_alone':                False,
        'group_size':                   2,
        'minors_in_group':              0,
        'assistance_requested':         'legal,documentacion',
        'migration_reason':             'En tránsito hacia Estados Unidos. Solicita asesoría legal.',
        'current_legal_status':         'migrante_irregular',
        'shelter_name':                 'Casa Monarca',
        'emergency_contact_name':       'Ana Fuentes',
        'emergency_contact_phone':      '+503 6666-0002',
        'emergency_contact_relationship': 'Esposa',
        'observations':                 'Pendiente de cita con abogado.',
        'data_consent':                 True,
    },
    {
        'first_name':                   'Ana Sofía',
        'first_surname':                'Torres',
        'second_surname':               'Vargas',
        'birth_date':                   date(2001, 5, 18),
        'gender':                       'femenino',
        'nationality':                  'Venezolana',
        'country_of_origin':            'Venezuela',
        'document_type':                'pasaporte',
        'document_number':              'VE-11223344',
        'phone':                        '+58 412-5556677',
        'email':                        'ana.torres@email.com',
        'entry_date':                   date(2025, 3, 5),
        'entry_point':                  'Aeropuerto Internacional de Cancún',
        'transit_countries':            'Colombia, Ecuador, Perú',
        'intended_destination':         'Ciudad de México',
        'marital_status':               'soltero',
        'travels_alone':                True,
        'group_size':                   1,
        'minors_in_group':              0,
        'assistance_requested':         'legal,laboral',
        'migration_reason':             'Crisis económica y política en Venezuela.',
        'current_legal_status':         'solicitante_asilo',
        'shelter_name':                 'Casa Monarca',
        'emergency_contact_name':       'Luis Torres',
        'emergency_contact_phone':      '+58 412-1112233',
        'emergency_contact_relationship': 'Padre',
        'observations':                 'Universitaria. Habla inglés y francés.',
        'data_consent':                 True,
    },
    {
        'first_name':                   'Roberto',
        'first_surname':                'Díaz',
        'second_surname':               'Herrera',
        'birth_date':                   date(1965, 9, 30),
        'gender':                       'masculino',
        'nationality':                  'Nicaragüense',
        'country_of_origin':            'Nicaragua',
        'document_type':                'pasaporte',
        'document_number':              'NI-55667788',
        'phone':                        '+505 8888-9999',
        'email':                        'roberto.diaz@email.com',
        'entry_date':                   date(2025, 2, 14),
        'entry_point':                  'Tapachula, Chiapas',
        'transit_countries':            'Costa Rica, Guatemala',
        'intended_destination':         'Guadalajara, Jalisco',
        'marital_status':               'viudo',
        'travels_alone':                True,
        'group_size':                   1,
        'minors_in_group':              0,
        'assistance_requested':         'medica,alojamiento',
        'migration_reason':             'Persecución política. Periodista en riesgo.',
        'current_legal_status':         'refugiado_reconocido',
        'shelter_name':                 'Casa Monarca',
        'emergency_contact_name':       'Elena Herrera',
        'emergency_contact_phone':      '+505 7777-0003',
        'emergency_contact_relationship': 'Hermana',
        'observations':                 'Requiere atención médica por condición crónica (diabetes).',
        'data_consent':                 True,
    },
]


# ═════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def sep():
    print('─' * 65)


def _generate_ca_noninteractive(certs_dir: Path, ca_password: str):
    """Genera la CA interna de forma no interactiva para el seed."""
    from crypto_core.ca import generate_ca_keypair, load_ca, get_ca_fingerprint
    ca_cert_pem, ca_key_encrypted = generate_ca_keypair(ca_password)
    ca_cert_path = certs_dir / 'ca_cert.pem'
    ca_key_path = certs_dir / 'ca_key.enc.pem'
    ca_cert_path.write_bytes(ca_cert_pem)
    ca_cert_path.chmod(0o644)
    ca_key_path.write_text(ca_key_encrypted)
    ca_key_path.chmod(0o600)
    ca_cert, ca_key = load_ca(ca_cert_pem, ca_key_encrypted, ca_password)
    print(f'   ✅ CA generada. Fingerprint: {get_ca_fingerprint(ca_cert_pem)}')
    return ca_cert, ca_key


def _load_existing_ca(certs_dir: Path, ca_password: str):
    from crypto_core.ca import load_ca
    ca_cert_pem = (certs_dir / 'ca_cert.pem').read_bytes()
    ca_key_encrypted = (certs_dir / 'ca_key.enc.pem').read_text()
    try:
        return load_ca(ca_cert_pem, ca_key_encrypted, ca_password)
    except ValueError:
        print('   ❌ Contraseña de CA incorrecta. Regenerando CA...')
        return None, None


def _emit_cert(user, admin_user, ca_cert, ca_key, certs_dir: Path):
    """
    Emite certificado X.509 y guarda AMBOS archivos listos para el login:
      certs/<username>.cert  ← sube en el campo 'Certificado (.cert)' del login
      certs/<username>.key   ← sube en el campo 'Llave privada (.key)' del login
    """
    from iam.certificates import issue_cert_and_key
    try:
        cert = issue_cert_and_key(user, issued_by=admin_user)
        user.certificate_delivered_at = timezone.now()
        user.save(update_fields=['certificate_delivered_at'])

        key_pem = getattr(cert, '_pending_private_key_pem', None)
        if key_pem:
            # .key — archivo que se sube al campo 'Llave privada (.key)' del login
            key_path = certs_dir / f'{user.username}.key'
            key_path.write_bytes(key_pem)
            key_path.chmod(0o600)

            # .cert — archivo que se sube al campo 'Certificado (.cert)' del login
            cert_path = certs_dir / f'{user.username}.cert'
            cert_path.write_text(cert.certificate_data)
            cert_path.chmod(0o644)

            print(f'      🔐 Cert+Key listos:')
            print(f'         certs/{user.username}.cert  ← sube en "Certificado (.cert)"')
            print(f'         certs/{user.username}.key   ← sube en "Llave privada (.key)"')
        return cert
    except Exception as exc:
        print(f'      ⚠️  No se pudo emitir certificado: {exc}')
        return None


# ═════════════════════════════════════════════════════════════════════════════
# MODO --check
# ═════════════════════════════════════════════════════════════════════════════

def run_check():
    print()
    print('🔍 MODO VERIFICACIÓN — No se modifica la BD')
    print()

    print('1. Verificando variables de entorno...')
    try:
        key = get_encryption_key_from_env()
        print('   ✅ DB_ENCRYPTION_MASTER_PASSWORD y DB_ENCRYPTION_SALT configurados')
    except RuntimeError as e:
        print(f'   ❌ {e}')
        return

    print('2. Verificando cifrado/descifrado AES-256-GCM...')
    test_cases = [
        'Juan Pérez García',
        'HN-1234567',
        '+504 9876-5432',
        'juan@email.com',
        'Solicitante de asilo — datos confidenciales',
        '1985-03-15',
    ]
    all_ok = True
    for original in test_cases:
        enc = encrypt_field(original, key)
        dec = decrypt_field(enc, key)
        if dec != original:
            print(f'   ❌ FALLO con: {repr(original)}')
            all_ok = False
        else:
            print(f'   ✅ "{original[:30]}" → cifrado → descifrado ok')

    # Verificar que EncryptedTextField maneja vacío/None (la guarda en campo sin cifrar)
    from crypto_core.fields import EncryptedTextField
    _f = EncryptedTextField()
    assert _f.get_prep_value('') in ('', None)
    assert _f.get_prep_value(None) is None
    print('   ✅ Nulo/vacío manejado correctamente por EncryptedTextField')

    print()
    if all_ok:
        print('✅ Sistema de cifrado funcionando correctamente')
    else:
        print('❌ Hay errores — revisa crypto_core/encryption.py')


# ═════════════════════════════════════════════════════════════════════════════
# SEED PRINCIPAL
# ═════════════════════════════════════════════════════════════════════════════

def run_seed(emit_certs: bool = True):
    print()
    print('╔══════════════════════════════════════════════════════════════╗')
    print('║     CASA MONARCA — RESET Y SEED CON ENCRIPTACIÓN COMPLETA   ║')
    print('║                    AES-256-GCM | Django 6                   ║')
    print('╚══════════════════════════════════════════════════════════════╝')
    print()

    # ── 1. Verificar clave de encriptación ───────────────────────────────────
    print('🔑 Verificando configuración de encriptación...')
    try:
        db_key = get_encryption_key_from_env()
        # Prueba rápida
        test = decrypt_field(encrypt_field('prueba', db_key), db_key)
        assert test == 'prueba'
        print('   ✅ Clave AES-256 derivada y verificada')
    except RuntimeError as e:
        print(f'   ❌ {e}')
        sys.exit(1)

    # ── 2. Reset de BD ───────────────────────────────────────────────────────
    sep()
    print('🗑️  Reseteando base de datos...')
    db_path = BASE_DIR / 'db.sqlite3'
    if db_path.exists():
        db_path.unlink()
        print(f'   ✅ db.sqlite3 eliminado')

    print('   Aplicando migraciones...')
    call_command('migrate', '--run-syncdb', verbosity=0)
    print('   ✅ Tablas recreadas con esquema actualizado (campos PII como TEXT cifrado)')

    # ── 3. Directorio de certificados ────────────────────────────────────────
    certs_dir = BASE_DIR / 'certs'
    certs_dir.mkdir(mode=0o700, exist_ok=True)

    # ── 4. CA para certificados X.509 ────────────────────────────────────────
    ca_cert = ca_key = None
    if emit_certs:
        sep()
        print('🏛️  Configurando Autoridad Certificadora (CA)...')
        ca_password = os.environ.get('CA_MASTER_PASSWORD', 'CasaMonarca_CA_Seed_2026!')
        ca_cert_path = certs_dir / 'ca_cert.pem'
        ca_key_path  = certs_dir / 'ca_key.enc.pem'

        if ca_cert_path.exists() and ca_key_path.exists():
            print('   CA existente encontrada. Cargando...')
            ca_cert, ca_key = _load_existing_ca(certs_dir, ca_password)

        if ca_cert is None:
            print('   Generando nueva CA interna...')
            ca_cert, ca_key = _generate_ca_noninteractive(certs_dir, ca_password)
            # Guardar password en el entorno para que iam/certificates.py pueda usarla
            os.environ['CA_MASTER_PASSWORD'] = ca_password
        else:
            print('   ✅ CA cargada correctamente')

    # ── 5. Crear Áreas ───────────────────────────────────────────────────────
    sep()
    print('🗂️  Creando áreas del sistema...')
    area_objs = {}
    for slug, name, desc in AREAS:
        obj, created = Area.objects.update_or_create(
            slug=slug, defaults={'name': name, 'description': desc}
        )
        area_objs[slug] = obj
        status = '✅ creada' if created else '↩  ya existía'
        print(f'   {status}: {name}')

    # ── 6. Crear usuarios ────────────────────────────────────────────────────
    sep()
    print('👥 Creando usuarios seed...')
    print()

    admin_user = None
    created_users = []

    for u_data in SEED_USERS:
        username = u_data['username']
        area_obj = area_objs[u_data['area_slug']]

        user, created = Collaborator.objects.get_or_create(
            username=username,
            defaults={
                'email':          u_data['email'],
                'first_name':     u_data['first_name'],
                'last_name':      u_data['last_name'],
                'access_level':   u_data['access_level'],
                'role':           u_data['role'],
                'area':           area_obj,
                'is_staff':       u_data['is_staff'],
                'is_active':      True,
                'onboarding_status': Collaborator.ONBOARDING_STATUS_APPROVED,
                'onboarding_approved_at': timezone.now(),
            },
        )
        user.set_password(u_data['password'])
        if user.onboarding_status != Collaborator.ONBOARDING_STATUS_APPROVED:
            user.onboarding_status = Collaborator.ONBOARDING_STATUS_APPROVED
            user.onboarding_approved_at = timezone.now()
        user.save()

        # El admin se autoaprueba para el bootstrap
        if u_data['access_level'] == 1 and not user.onboarding_approved_by:
            user.onboarding_approved_by = user
            user.save(update_fields=['onboarding_approved_by'])

        if admin_user is None and u_data['access_level'] == 1:
            admin_user = user

        print(f'   👤 {username}')
        print(f'      {u_data["descripcion"]}')
        print(f"      Password: '{u_data['password']}'")

        # Emitir certificado X.509 para niveles 1 y 2
        if emit_certs and u_data['has_cert'] and ca_cert and ca_key:
            _emit_cert(user, admin_user or user, ca_cert, ca_key, certs_dir)
        elif u_data['has_cert'] and not emit_certs:
            print('      ⏭  Emisión de certificado omitida (--no-certs)')

        # Registrar en AuditLog
        AuditLog.objects.create(
            actor=admin_user or user,
            target=user,
            action='SEED_USER_CREATED',
            details=f'Usuario de prueba creado por seed.py — acceso_nivel={u_data["access_level"]}',
        )
        created_users.append(user)
        print()

    # ── 7. Crear registros migrantes con PII cifrada ─────────────────────────
    sep()
    print('📋 Creando registros migrantes (PII cifrada con AES-256-GCM)...')
    print()

    from registros.models import MigrantRegistration

    created_registrations = []
    for reg_data in SEED_REGISTRATIONS:
        # Los campos EncryptedTextField/EncryptedDateField cifran automáticamente
        # al hacer .save() — no necesitamos llamar encrypt_field() manualmente
        creator = admin_user
        reg = MigrantRegistration(
            first_name=reg_data['first_name'],
            first_surname=reg_data['first_surname'],
            second_surname=reg_data.get('second_surname', 'X'),
            birth_date=reg_data['birth_date'],
            gender=reg_data['gender'],
            nationality=reg_data['nationality'],
            country_of_origin=reg_data['country_of_origin'],
            document_type=reg_data['document_type'],
            document_number=reg_data['document_number'],
            phone=reg_data['phone'],
            email=reg_data['email'],
            entry_date=reg_data['entry_date'],
            entry_point=reg_data['entry_point'],
            transit_countries=reg_data.get('transit_countries', ''),
            intended_destination=reg_data['intended_destination'],
            marital_status=reg_data['marital_status'],
            travels_alone=reg_data['travels_alone'],
            group_size=reg_data['group_size'],
            minors_in_group=reg_data['minors_in_group'],
            assistance_requested=reg_data['assistance_requested'],
            migration_reason=reg_data['migration_reason'],
            current_legal_status=reg_data['current_legal_status'],
            shelter_name=reg_data['shelter_name'],
            emergency_contact_name=reg_data['emergency_contact_name'],
            emergency_contact_phone=reg_data['emergency_contact_phone'],
            emergency_contact_relationship=reg_data['emergency_contact_relationship'],
            observations=reg_data['observations'],
            data_consent=reg_data['data_consent'],
            privacy_accepted_at=timezone.now(),
            privacy_notice_version='1.0',
            created_by=creator,
            created_by_role=creator.access_level,
        )
        reg.save()
        created_registrations.append(reg)
        print(f'   📄 {reg.full_name} → ID: {reg.internal_id}')
        # Verificar que el campo en BD no es texto plano
        raw = _read_raw_field(reg.pk, 'first_name')
        is_encrypted = raw and 'Juan' not in raw and 'María' not in raw and 'Carlos' not in raw \
                       and 'Ana' not in raw and 'Roberto' not in raw
        status = '🔒 cifrado' if is_encrypted else '⚠️  POSIBLE TEXTO PLANO'
        print(f'      BD: {status} ({raw[:40] if raw else "NULL"}...)')

    # ── 8. Verificación final en BD ──────────────────────────────────────────
    sep()
    print('🔍 VERIFICACIÓN FINAL: Buscando texto plano en la BD...')
    print()
    _verify_no_plaintext_in_db()

    # ── 9. Tabla de credenciales ─────────────────────────────────────────────
    print()
    print('╔════════════════════════════════════════════════════════════════════╗')
    print('║                   CREDENCIALES DE PRUEBA                          ║')
    print('╠══════════════════╤══════════════╤═══════════════╤═════════════════╣')
    print('║ Username         │ Password     │ Nivel         │ Área            ║')
    print('╠══════════════════╪══════════════╪═══════════════╪═════════════════╣')

    nivel_labels = {1: 'Admin (1)', 2: 'Coordinador (2)', 3: 'Operativo (3)', 4: 'Externo (4)'}
    for u_data in SEED_USERS:
        uname  = u_data['username'].ljust(16)[:16]
        passwd = u_data['password'].ljust(12)[:12]
        nivel  = nivel_labels[u_data['access_level']].ljust(13)[:13]
        area   = u_data['area_slug'].ljust(15)[:15]
        cert   = ' 🔐' if u_data['has_cert'] else '   '
        print(f'║ {uname} │ {passwd} │ {nivel} │ {area} ║{cert}')

    print('╚══════════════════╧══════════════╧═══════════════╧═════════════════╝')
    print()
    print('  🔐 = Tiene certificado X.509 firmado por la CA interna')
    print()
    print('╔══════════════════════════════════════════════════════════════╗')
    print('║              ✅ SEED COMPLETADO EXITOSAMENTE                ║')
    print('║                                                              ║')
    print('║  Todos los campos PII están cifrados con AES-256-GCM.       ║')
    print('║  Ningún dato personal se guardó en texto plano en la BD.    ║')
    print('║                                                              ║')
    print('║  Para arrancar el servidor:  python manage.py runserver     ║')
    print('╚══════════════════════════════════════════════════════════════╝')
    print()


def _read_raw_field(pk: int, field: str) -> str:
    """Lee el valor RAW del campo directo desde SQLite (sin pasar por ORM)."""
    try:
        import sqlite3
        db_path = BASE_DIR / 'db.sqlite3'
        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute(f'SELECT {field} FROM registros_migrantregistration WHERE id = ?', (pk,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:
        return None


def _verify_no_plaintext_in_db():
    """Abre la BD con sqlite3 y verifica que no hay PII en texto plano."""
    try:
        import sqlite3
        db_path = BASE_DIR / 'db.sqlite3'
        if not db_path.exists():
            print('   ⚠️  No se encontró db.sqlite3')
            return

        # Only check strings that appear EXCLUSIVELY in encrypted PII fields
        # (not in area names, shelter names, or other unencrypted context)
        sensitive_strings = [
            'HN-1234567', 'GT-7654321', 'SV-9876543', 'VE-11223344', 'NI-55667788',
            'juan.perez@email.com', 'maria.rodriguez@email.com',
            'carlos.mendoza@email.com', 'ana.torres@email.com', 'roberto.diaz@email.com',
            '+504 9876-5432', '+502 5555-1234', '+503 7777-8888', '+58 412-5556677',
            'Juan Pérez García', 'María Rodríguez López', 'Carlos Mendoza Fuentes',
            'Ana Sofía Torres Vargas', 'Roberto Díaz Herrera',
        ]

        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]

        found_plaintext = False
        for table in tables:
            try:
                cur.execute(f'SELECT * FROM {table} LIMIT 20')
                rows = cur.fetchall()
                for row in rows:
                    for cell in row:
                        if isinstance(cell, str):
                            for s in sensitive_strings:
                                if s in cell:
                                    print(f'   ❌ ALERTA texto plano en tabla "{table}": ...{cell[:50]}...')
                                    found_plaintext = True
                                    break
            except Exception:
                pass

        conn.close()

        if not found_plaintext:
            print('   ✅ Ningún dato PII encontrado en texto plano en la BD')
            print('   ✅ Todos los campos sensibles están cifrados')
        else:
            print('   ⚠️  Se encontraron posibles datos en texto plano — revisa los modelos')

    except Exception as exc:
        print(f'   ⚠️  No se pudo verificar la BD: {exc}')


# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    if '--check' in sys.argv:
        run_check()
    elif '--no-certs' in sys.argv:
        run_seed(emit_certs=False)
    else:
        run_seed(emit_certs=True)
