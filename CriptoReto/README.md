# Casa Monarca IAM

Aplicación Django para la gestión de identidades y acceso de Casa Monarca.

## Características implementadas

- Migración del HTML a plantillas Django.
- Autenticación con Django `username`/`password` y soporte opcional MFA con TOTP (`pyotp`).
- Autorización por nivel, área y rol.
- Modelo de usuario personalizado (`Collaborator`) con `area`, `access_level`, `role`, `is_revoked`, `is_deleted` y `mfa_enabled`.
- Auditoría de acciones administrativas y de login.
- Revocación, reactivación, edición y eliminación de colaboradores.
- Seed data de prueba con cuentas para administración, legal, humanitario, comunicaciones, almacén, psicosocial y externo.
- Configuración opcional de MySQL vía variables de entorno.

## Instalación

```bash
python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
```

## Base de datos

Por defecto usa SQLite para desarrollo. Para MySQL, sigue estos pasos:

1. Crea la base de datos y el usuario MySQL.

```bash
cd /Users/brismaalvarezvaldez/Documents/CriptoReto
mysql -u root -p < mysql_setup.sql
```

2. O ejecuta los comandos manualmente en MySQL:

```sql
CREATE DATABASE IF NOT EXISTS casamonarca CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'casamonarca_user'@'localhost' IDENTIFIED BY 'Cm2026MySQL!';
GRANT ALL PRIVILEGES ON casamonarca.* TO 'casamonarca_user'@'localhost';
FLUSH PRIVILEGES;
```

3. Define las variables de entorno antes de iniciar Django:

```bash
export MYSQL_DATABASE=casamonarca
export MYSQL_USER=casamonarca_user
export MYSQL_PASSWORD='Cm2026MySQL!'
export MYSQL_HOST=127.0.0.1
export MYSQL_PORT=3306
```

4. Confirma que el proyecto usa MySQL:

```bash
export DJANGO_SETTINGS_MODULE=casamonarca.settings
python - <<'PY'
from django.conf import settings
print(settings.DATABASES['default']['ENGINE'])
print(settings.DATABASES['default']['NAME'])
PY
```

Debería mostrar:

```text
django.db.backends.mysql
casamonarca
```

5. Ejecuta migraciones y carga datos de prueba:

```bash
python manage.py migrate
python manage.py seed_data
```

6. Inicia el servidor:

```bash
python manage.py runserver
```

## Ejecución

```bash
python manage.py runserver
```

## Usuarios de prueba

- `admin` / `Admin2026!` (Nivel 1)
- `legal_coordinator` / `Legal2026!`
- `humanitario_ops` / `Humanitario2026!`
- `external_comms` / `Comms2026!`
- `warehouse_manager` / `Almacen2026!`
- `psychologist` / `Psico2026!`
- `external_support` / `Soporte2026!`

## Notas

- El sistema no usa Keycloak ni step-ca.
- La autenticación y autorización se resuelven completamente dentro de Django.
- El comando `seed_data` crea los datos de prueba y deja registrado el actor administrador.
