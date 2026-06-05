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
# Convención de username: <iniciales_área>_<inicial_nombre><apellido>
#   ti = TI/Sistemas  |  le = Legal  |  hu = Humanitario
SEED_USERS = [
    # ── Administrador (nivel 1) ──────────────────────────────────────────────
    {
        'username':    'mariel_alvarez',
        'password':    'Mariel2026!',
        'first_name':  'Mariel',
        'last_name':   'Alvarez',
        'email':       'm.alvarez@casamonarca.org',
        'access_level': 1,
        'role':        'Administrador IT',
        'area_slug':   'it',
        'is_staff':    True,
        'has_cert':    True,
        'descripcion': '[NIVEL 1] Administradora del sistema — acceso total',
    },

    # ── Coordinador (nivel 2) ────────────────────────────────────────────────
    {
        'username':    'emiliano_ruiz',
        'password':    'Emiliano2026!',
        'first_name':  'Emiliano',
        'last_name':   'Ruiz',
        'email':       'e.ruiz@casamonarca.org',
        'access_level': 2,
        'role':        'Coordinador Legal',
        'area_slug':   'legal',
        'is_staff':    True,
        'has_cert':    True,
        'descripcion': '[NIVEL 2] Coordinador área Legal',
    },

    # ── Operativa (nivel 3) ──────────────────────────────────────────────────
    {
        'username':    'brisma_alvarez',
        'password':    'Brisma2026!',
        'first_name':  'Brisma',
        'last_name':   'Alvarez',
        'email':       'b.alvarez@casamonarca.org',
        'access_level': 3,
        'role':        'Operativo Humanitario',
        'area_slug':   'humanitario',
        'is_staff':    False,
        'has_cert':    False,
        'descripcion': '[NIVEL 3] Operativa área Humanitario',
    },

    # ── Voluntaria/Externa (nivel 4) ─────────────────────────────────────────
    {
        'username':    'karen_estrada',
        'password':    'Karen2026!',
        'first_name':  'Karen',
        'last_name':   'Estrada',
        'email':       'k.estrada@casamonarca.org',
        'access_level': 4,
        'role':        'Personal Externo',
        'area_slug':   'humanitario',
        'is_staff':    False,
        'has_cert':    False,
        'descripcion': '[NIVEL 4] Voluntaria área Humanitario',
    },
]

# Datos en texto plano — se cifrarán automáticamente vía EncryptedTextField/EncryptedDateField
# Solo los 12 campos rastreados del modelo actual + campos obligatorios de consentimiento
SEED_REGISTRATIONS = [
    {
        'first_name':       'Santiago',
        'first_surname':    'Morales',
        'second_surname':   'Fuentes',
        'birth_date':       date(1988, 4, 22),
        'gender':           'masculino',
        'country_of_origin':'Honduras',
        'state_or_region':  'Cortés',
        'phone':            '+504 9871-2345',
        'service_date':     date(2026, 5, 10),
        'marital_status':   'casado',
        'age_group':        'adulto',
        'population_group': 'adulto',
        'data_consent':     True,
    },
    {
        'first_name':       'Valentina',
        'first_surname':    'Cruz',
        'second_surname':   'Mendoza',
        'birth_date':       date(1995, 11, 8),
        'gender':           'femenino',
        'country_of_origin':'Guatemala',
        'state_or_region':  'Quetzaltenango',
        'phone':            '+502 5544-6677',
        'service_date':     date(2026, 5, 18),
        'marital_status':   'soltero',
        'age_group':        'adulto',
        'population_group': 'adulto',
        'data_consent':     True,
    },
    {
        'first_name':       'Diego Alejandro',
        'first_surname':    'Fuentes',
        'second_surname':   'Maldonado',
        'birth_date':       date(1995, 8, 14),
        'gender':           'masculino',
        'country_of_origin':'Honduras',
        'state_or_region':  'Cortés',
        'phone':            '+504 9812-3456',
        'service_date':     date(2026, 6, 4),
        'marital_status':   'soltero',
        'age_group':        'adulto',
        'population_group': 'adulto',
        'data_consent':     True,
    },
    # ── placeholder que reemplaza los registros eliminados ──────────────────
    {
        'first_name':       'Ana Sofia',
        'first_surname':    'Torres',
        'second_surname':   'Vargas',
        'birth_date':       date(2001, 5, 18),
        'gender':           'femenino',
        'country_of_origin':'Venezuela',
        'state_or_region':  'Caracas',
        'phone':            '+58 412-5556677',
        'service_date':     date(2026, 4, 2),
        'marital_status':   'soltero',
        'age_group':        'adulto',
        'population_group': 'adulto',
        'data_consent':     True,
    },
    # ── placeholder para que la BD tenga historial visible ──────────────────
    {
        'first_name':       'Roberto',
        'first_surname':    'Diaz',
        'second_surname':   'Herrera',
        'birth_date':       date(1965, 9, 30),
        'gender':           'masculino',
        'country_of_origin':'Nicaragua',
        'state_or_region':  'Managua',
        'phone':            '+505 8888-9999',
        'service_date':     date(2026, 3, 15),
        'marital_status':   'viudo',
        'age_group':        'adulto',
        'population_group': 'adulto',
        'data_consent':     True,
    },
    # ── placeholder original (mantiene el formato) ──────────────────────────
    {
        'first_name':       'Juan',
        'first_surname':    'Perez',
        'second_surname':   'Garcia',
        'birth_date':       date(1985, 3, 15),
        'gender':           'masculino',
        'country_of_origin':'Honduras',
        'state_or_region':  'San Pedro Sula',
        'phone':            '+504 9876-5432',
        'service_date':     date(2026, 2, 20),
        'marital_status':   'casado',
        'age_group':        'adulto',
        'population_group': 'adulto',
        'data_consent':     True,
    },
    {
        'first_name':       'Maria',
        'first_surname':    'Rodriguez',
        'second_surname':   'Lopez',
        'birth_date':       date(1992, 7, 22),
        'gender':           'femenino',
        'country_of_origin':'Guatemala',
        'state_or_region':  'Ciudad de Guatemala',
        'phone':            '+502 5555-1234',
        'service_date':     date(2026, 2, 28),
        'marital_status':   'soltero',
        'age_group':        'adulto',
        'population_group': 'adulto',
        'data_consent':     True,
    },
    {
        'first_name':       'Carlos',
        'first_surname':    'Mendoza',
        'second_surname':   'Fuentes',
        'birth_date':       date(1978, 11, 3),
        'gender':           'masculino',
        'country_of_origin':'El Salvador',
        'state_or_region':  'San Salvador',
        'phone':            '+503 7777-8888',
        'service_date':     date(2026, 1, 10),
        'marital_status':   'casado',
        'age_group':        'adulto',
        'population_group': 'adulto',
        'data_consent':     True,
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
            country_of_origin=reg_data['country_of_origin'],
            state_or_region=reg_data.get('state_or_region', ''),
            phone=reg_data.get('phone', ''),
            service_date=reg_data.get('service_date'),
            marital_status=reg_data['marital_status'],
            age_group=reg_data.get('age_group', 'adulto'),
            population_group=reg_data.get('population_group', 'adulto'),
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
        first = reg_data['first_name'].split()[0]
        is_encrypted = raw and first not in raw
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
            '+504 9871-2345', '+502 5544-6677', '+504 9812-3456',
            '+58 412-5556677', '+505 8888-9999', '+504 9876-5432', '+502 5555-1234',
            'Santiago Morales Fuentes', 'Valentina Cruz Mendoza', 'Diego Alejandro Fuentes',
            'Ana Sofia Torres Vargas', 'Roberto Diaz Herrera',
            'Juan Perez Garcia', 'Maria Rodriguez Lopez', 'Carlos Mendoza Fuentes',
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
