#!/usr/bin/env python3
"""
Script de inicialización del sistema Casa Monarca.

Uso:
    python scripts/init_system.py           # primera vez
    python scripts/init_system.py --fresh   # reset completo (destruye BD)

Pasos:
  1. (Opcional) Borra y recrea la BD si --fresh
  2. Aplica migraciones Django
  3. Genera la CA interna de Casa Monarca
  4. Crea el usuario admin inicial
  5. Emite certificado X.509 para el admin, firmado por la CA
  6. Guarda la clave privada del admin localmente (con aviso)
"""

import getpass
import os
import sys
from pathlib import Path

# Añadir el directorio raíz al sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'casamonarca.settings')

import django
django.setup()


def _ensure_certs_dir() -> Path:
    certs_dir = BASE_DIR / 'certs'
    certs_dir.mkdir(mode=0o700, exist_ok=True)
    return certs_dir


def _print_header():
    print('\n' + '=' * 60)
    print('  Casa Monarca — Inicialización del Sistema Criptográfico')
    print('=' * 60)


def _print_separator():
    print('-' * 60)


def step_fresh_db():
    """Borra la BD SQLite si existe (solo en modo --fresh)."""
    db_path = BASE_DIR / 'db.sqlite3'
    if db_path.exists():
        confirm = input(f'\n⚠️  Se borrará la BD en {db_path}. ¿Confirmar? [s/N]: ').strip().lower()
        if confirm != 's':
            print('Cancelado.')
            sys.exit(0)
        db_path.unlink()
        print(f'✓ BD eliminada: {db_path}')


def step_migrate():
    """Aplica todas las migraciones Django."""
    print('\n[1/5] Aplicando migraciones Django...')
    from django.core.management import call_command
    call_command('migrate', '--run-syncdb', verbosity=0)
    print('✓ Migraciones aplicadas.')


def step_generate_ca(certs_dir: Path) -> tuple:
    """Genera la CA interna o la carga si ya existe."""
    print('\n[2/5] Configurando Autoridad Certificadora...')
    ca_cert_path = certs_dir / 'ca_cert.pem'
    ca_key_path = certs_dir / 'ca_key.enc.pem'

    if ca_cert_path.exists() and ca_key_path.exists():
        print('  CA ya existe. Cargando...')
        ca_password = getpass.getpass('  CA master password: ')
        ca_cert_pem = ca_cert_path.read_bytes()
        ca_key_encrypted = ca_key_path.read_text()
        from crypto_core.ca import load_ca, get_ca_fingerprint
        try:
            ca_cert, ca_key = load_ca(ca_cert_pem, ca_key_encrypted, ca_password)
            print(f'✓ CA cargada. Fingerprint: {get_ca_fingerprint(ca_cert_pem)}')
            return ca_cert, ca_key, ca_cert_pem, ca_password
        except ValueError:
            print('✗ Error: Contraseña de CA incorrecta o archivo dañado.')
            sys.exit(1)

    print('  Generando nueva CA interna de Casa Monarca...')
    print('  (Esta contraseña protege la clave raíz del sistema)')
    ca_password = getpass.getpass('  Nueva CA master password: ')
    ca_password_confirm = getpass.getpass('  Confirmar CA master password: ')
    if ca_password != ca_password_confirm:
        print('✗ Las contraseñas no coinciden.')
        sys.exit(1)
    if len(ca_password) < 12:
        print('✗ La contraseña de la CA debe tener al menos 12 caracteres.')
        sys.exit(1)

    from crypto_core.ca import generate_ca_keypair, load_ca, get_ca_fingerprint
    ca_cert_pem, ca_key_encrypted = generate_ca_keypair(ca_password)

    ca_cert_path.write_bytes(ca_cert_pem)
    ca_cert_path.chmod(0o644)
    ca_key_path.write_text(ca_key_encrypted)
    ca_key_path.chmod(0o600)

    ca_cert, ca_key = load_ca(ca_cert_pem, ca_key_encrypted, ca_password)
    fingerprint = get_ca_fingerprint(ca_cert_pem)
    print(f'✓ CA generada.')
    print(f'  Certificado: {ca_cert_path}')
    print(f'  Clave cifrada: {ca_key_path}')
    print(f'  Fingerprint: {fingerprint}')
    return ca_cert, ca_key, ca_cert_pem, ca_password


def step_create_admin(ca_cert, ca_key, ca_cert_pem: bytes, certs_dir: Path):
    """Crea el usuario admin inicial y emite su certificado."""
    print('\n[3/5] Creando usuario administrador...')

    from django.contrib.auth import get_user_model
    from django.db import transaction

    User = get_user_model()

    # Verificar si ya existe un admin
    existing_admins = User.objects.filter(access_level=1, is_deleted=False)
    if existing_admins.exists():
        print(f'  Ya existe(n) {existing_admins.count()} admin(s):')
        for a in existing_admins:
            print(f'    - {a.username}')
        create_new = input('  ¿Crear otro admin? [s/N]: ').strip().lower()
        if create_new != 's':
            print('  Usando admins existentes.')
            return

    username = input('  Admin username: ').strip()
    if not username:
        print('✗ Username vacío.')
        sys.exit(1)

    if User.objects.filter(username=username).exists():
        print(f'✗ Usuario "{username}" ya existe.')
        sys.exit(1)

    email = input('  Admin email: ').strip()
    first_name = input('  Nombre: ').strip()
    last_name = input('  Apellido: ').strip()

    password = getpass.getpass('  Admin password (mín. 10 chars): ')
    if len(password) < 10:
        print('✗ Contraseña muy corta.')
        sys.exit(1)
    password_confirm = getpass.getpass('  Confirmar password: ')
    if password != password_confirm:
        print('✗ Las contraseñas no coinciden.')
        sys.exit(1)

    # Obtener o crear área de TI
    from iam.models import Area
    area_obj, _ = Area.objects.get_or_create(
        slug='ti',
        defaults={'name': 'TI / Sistemas', 'description': 'Tecnologías de la Información'},
    )

    print('\n[4/5] Emitiendo certificado X.509 para el admin...')
    from crypto_core.certificates import emit_certificate, get_cert_metadata

    with transaction.atomic():
        # Crear usuario
        admin_user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name,
            access_level=1,
            role='Administrador IT',
            area=area_obj,
            onboarding_status=User.ONBOARDING_STATUS_APPROVED,
        )
        admin_user.is_staff = True
        admin_user.is_superuser = True
        admin_user.save()

        # Emitir certificado
        cert_pem, private_key_pem = emit_certificate(
            user_id=admin_user.pk,
            username=username,
            role='admin',
            area='TI / Sistemas',
            ca_cert=ca_cert,
            ca_key=ca_key,
            valid_days=365,
        )
        metadata = get_cert_metadata(cert_pem)

        # Guardar cert en BD (la clave privada NO se guarda)
        from iam.models import UserCertificate
        user_cert = UserCertificate.objects.create(
            collaborator=admin_user,
            certificate_data=cert_pem.decode('utf-8'),
            fingerprint=metadata['fingerprint_sha256'],
            expires_at=metadata['expires_at'],
            serial_number=metadata['serial_number'],
            issued_by=admin_user,
        )

    # Guardar clave privada localmente (con advertencia)
    key_path = certs_dir / f'admin_{username}_key.pem'
    key_path.write_bytes(private_key_pem)
    key_path.chmod(0o600)

    print(f'\n  ✓ Usuario admin creado: {username}')
    print(f'  ✓ Certificado guardado en BD (serial: {metadata["serial_number"]})')
    print(f'\n  ⚠️  CLAVE PRIVADA GENERADA: {key_path}')
    print(f'      Esta clave NO está guardada en la BD.')
    print(f'      El admin debe guardarla en un lugar seguro.')
    print(f'      Si se pierde, se debe revocar el certificado y emitir uno nuevo.')
    return admin_user, user_cert, metadata


def step_print_summary(ca_cert_pem: bytes, user_cert_metadata: dict):
    """Imprime el resumen final."""
    from crypto_core.ca import get_ca_fingerprint
    print('\n' + '=' * 60)
    print('  ✅ Sistema Casa Monarca inicializado correctamente')
    print('=' * 60)
    print(f'  CA Fingerprint  : {get_ca_fingerprint(ca_cert_pem)}')
    if user_cert_metadata:
        print(f'  Admin cert serial: {user_cert_metadata["serial_number"]}')
        print(f'  Admin cert expira: {user_cert_metadata["expires_at"].strftime("%Y-%m-%d")}')
    print(f'\n  Próximos pasos:')
    print(f'    1. Copia certs/admin_*_key.pem a un lugar seguro y bórralo del servidor')
    print(f'    2. Configura DB_ENCRYPTION_MASTER_PASSWORD en el entorno')
    print(f'    3. Configura DB_ENCRYPTION_SALT en el entorno')
    print(f'    4. Inicia el servidor: python manage.py runserver')
    print()


def main():
    fresh = '--fresh' in sys.argv
    _print_header()

    certs_dir = _ensure_certs_dir()

    if fresh:
        step_fresh_db()

    step_migrate()
    ca_cert, ca_key, ca_cert_pem, _ = step_generate_ca(certs_dir)
    result = step_create_admin(ca_cert, ca_key, ca_cert_pem, certs_dir)

    metadata = result[2] if result else None
    step_print_summary(ca_cert_pem, metadata)


if __name__ == '__main__':
    main()
