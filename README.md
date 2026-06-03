<div align="center">

# 🦋 Casa Monarca — Plataforma de Criptografía y Gestión de Identidades

**Solución de seguridad criptográfica para organizaciones de apoyo migrante**

[![Python](https://img.shields.io/badge/Python-3.11-blue?logo=python&logoColor=white)](https://python.org)
[![Django](https://img.shields.io/badge/Django-5.x-092E20?logo=django&logoColor=white)](https://djangoproject.com)
[![Cryptography](https://img.shields.io/badge/Cryptography-ECDSA%20·%20X.509%20·%20AES--GCM-red)](https://cryptography.io)
[![License](https://img.shields.io/badge/License-Academic-orange)](.)

> Proyecto desarrollado para **MA2006B – Uso de Álgebras Modernas para Seguridad y Criptografía**  
> Tecnológico de Monterrey · Equipo 1 · Grupo 602

</div>

---

## 📖 Contexto

[Casa Monarca](https://www.casamonarca.org.mx/) es una organización sin fines de lucro que brinda apoyo a personas migrantes en Monterrey, México. Como parte de sus operaciones, maneja información altamente sensible: datos personales, documentos oficiales y registros de atención humanitaria.

El manejo inadecuado de esta información expone a la organización y a los migrantes a riesgos como:

- Falsificación y alteración de documentos
- Suplantación de identidad de colaboradores
- Acceso no autorizado a datos personales
- Incumplimiento de la **LFPDPPP** (Ley Federal de Protección de Datos Personales)

Este proyecto implementa una plataforma completa que aborda estos riesgos mediante criptografía de clave pública, control de acceso basado en roles y trazabilidad criptográfica de todas las acciones.

---

## ✨ Funcionalidades principales

### 🔐 Criptografía aplicada

| Componente | Implementación |
|---|---|
| Firma de registros | ECDSA con curva **secp256k1** |
| Certificados de identidad | **X.509** firmados por CA interna |
| Cifrado de datos sensibles | **AES-256-GCM** con campo transparente en BD |
| Cadena de integridad | Hash-chain SHA-256 en ledger de acciones |
| Tokens de sesión | **JWT** firmados (PyJWT) |
| Autenticación adicional | **TOTP** (pyotp) para acciones críticas |

### 👥 Gestión de identidades (IAM)

- Modelo de colaborador con **4 niveles de acceso** (Admin → Coordinador → Operativo → Voluntario)
- Ciclo de vida completo de **certificados X.509**: emisión, suspensión, reactivación, revocación y baja
- **Onboarding seguro**: nuevos usuarios requieren aprobación de Coordinador/Admin antes de operar
- Auditoría persistente de todas las acciones de identidad

### 📋 Gestión de registros migrantes

- Formulario de registro con **consentimiento informado** (digital, verbal o escrito por proxy)
- Campos PII cifrados en base de datos con `EncryptedTextField` / `EncryptedDateField`
- **Firma digital ECDSA** de cada registro al momento de creación
- Verificación de autenticidad de registros en cualquier momento
- Expediente por migrante con timeline completo de eventos (LFPDPPP Art. 30)

### ⚙️ Flujo de aprobación (Workflow)

- Solicitudes de acciones sensibles pasan por cadena de aprobación por niveles
- Cada paso de aprobación genera un `ApprovalStep` con **hash encadenado** anti-tampering
- **Firma masiva (batch)**: Coordinadores/Admins pueden firmar múltiples solicitudes en un solo paso de autenticación
- Estados: `submitted → pending_review → escalated → approved → executed`

### 🛡️ Derechos ARCO

Implementación completa de los derechos **Acceso · Rectificación · Cancelación · Oposición** según LFPDPPP:

- Panel dedicado con panel de notificaciones separado de las solicitudes generales
- **ArcoTicket**: modelo dedicado con flujo de autorización propio (Operativo → Coordinador → Admin)
- Cada ejecución requiere certificado digital del ejecutor
- Plazo legal de 20 días hábiles con seguimiento visual
- Generación de PDF de respuesta para solicitudes de Acceso

### 🔗 Cadena de auditoría criptográfica

- Todas las firmas de acciones se encadenan mediante `prev_chain_hash`
- Cualquier modificación retroactiva rompe la cadena — detectable en la vista de auditoría
- Vista de auditoría pública verificable para demostrar integridad

---

## 🏗️ Arquitectura del proyecto

```
Casa-Monarca-Criptografia/
└── CriptoReto/
    ├── casamonarca/          # Configuración Django + context processors
    ├── crypto_core/          # Módulo criptográfico central
    │   ├── ca.py             # Autoridad Certificadora interna
    │   ├── certificates.py   # Emisión y verificación X.509
    │   ├── signatures.py     # ECDSA secp256k1
    │   ├── encryption.py     # AES-256-GCM
    │   ├── fields.py         # EncryptedTextField / EncryptedDateField
    │   ├── hashing.py        # SHA-256 + hash-chain
    │   └── auth_tokens.py    # JWT
    ├── iam/                  # Gestión de identidades y acceso
    │   ├── models.py         # Collaborator, UserCertificate, AuditLog
    │   ├── views.py          # Login, onboarding, certificados, auditoría
    │   └── certificates.py   # Capa de servicio de certificados
    ├── registros/            # Registros migrantes + ARCO + Workflow
    │   ├── models.py         # MigrantRegistration, ArcoRequest, ArcoTicket,
    │   │                     # WorkflowRequest, Ticket, ActionSignature, …
    │   ├── views.py          # CRUD + ARCO + workflow + batch-sign
    │   ├── workflow.py       # Lógica de flujos de aprobación
    │   └── services.py       # sign_registration, verify, batch_sign_actions
    ├── templates/            # HTML con diseño Casa Monarca
    └── tests/                # Suite de pruebas (33+ tests)
```

---

## 🚀 Instalación y ejecución

### Requisitos previos

- Python 3.11+
- pip

### 1. Clonar y crear entorno virtual

```bash
git clone <url-del-repositorio>
cd Casa-Monarca-Criptografia/CriptoReto

python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\Activate.ps1    # Windows PowerShell
```

### 2. Instalar dependencias

```bash
pip install -r requirements.txt
```

### 3. Variables de entorno

Crea un archivo `.env` en `CriptoReto/` (o exporta en la terminal):

```bash
# Requerido para la CA interna
export CA_MASTER_PASSWORD="tu_password_seguro"

# Opcional: clave secreta Django (se genera automáticamente si no se define)
export DJANGO_SECRET_KEY="..."

# Opcional: usar MySQL en lugar de SQLite
export MYSQL_DATABASE=casamonarca
export MYSQL_USER=casamonarca_user
export MYSQL_PASSWORD=Cm2026MySQL!
export MYSQL_HOST=127.0.0.1
export MYSQL_PORT=3306
```

### 4. Migraciones y datos de prueba

```bash
python manage.py migrate
python manage.py shell < seed.py   # Carga usuarios y datos de prueba
```

### 5. Iniciar servidor

```bash
python manage.py runserver
```

Abre [http://127.0.0.1:8000](http://127.0.0.1:8000) en tu navegador.

---

## 👤 Usuarios de prueba

| Usuario | Contraseña | Nivel | Rol |
|---|---|---|---|
| `admin` | `Admin2026!` | 1 — Admin | Administración total |
| `legal_coordinator` | `Legal2026!` | 2 — Coordinador | Área Legal |
| `humanitario_ops` | `Humanitario2026!` | 3 — Operativo | Área Humanitaria |
| `external_comms` | `Comms2026!` | 3 — Operativo | Comunicaciones |
| `warehouse_manager` | `Almacen2026!` | 3 — Operativo | Almacén |
| `psychologist` | `Psico2026!` | 3 — Operativo | Psicosocial |
| `external_support` | `Soporte2026!` | 4 — Voluntario | Apoyo externo |

> Los usuarios de nivel 1 y 2 requieren cargar su certificado `.cert` y llave `.key` para ejecutar acciones firmadas. Los certificados de prueba se generan al correr el seed.

---

## 🧪 Pruebas

```bash
pytest tests/ -v
```

La suite cubre: generación de llaves ECDSA, firma y verificación, emisión de certificados X.509, cifrado AES-GCM, hash-chain, campos encriptados y flujos de workflow.

---

## 🛠️ Stack tecnológico

| Capa | Tecnología |
|---|---|
| Backend | Django 5.x (Python 3.11) |
| Criptografía | `cryptography` (X.509, AES-GCM), ECDSA secp256k1 |
| Autenticación | Django Auth + TOTP (`pyotp`) + JWT (`PyJWT`) |
| Base de datos | SQLite (dev) · MySQL (prod) |
| PDF | ReportLab |
| Frontend | HTML/CSS vanilla + Font Awesome (sin framework JS) |
| Testing | pytest + pytest-django |

---

## 👩‍💻 Equipo

| Nombre | Matrícula |
|---|---|
| Mariel Álvarez Salas | A01198828 |
| Brisma Alvarez Valdez | A00839238 |
| Emiliano Ruiz López | A01659693 |
| Ana Sofia Nagao Alvarez | A01285034 |
| Karen Aylen Estrada Ceferino | A00838403 |

**Equipo 1 · Grupo 602**  
MA2006B – Uso de Álgebras Modernas para Seguridad y Criptografía  
Tecnológico de Monterrey · 2026

---

<div align="center">

Desarrollado con propósito social para Casa Monarca 🦋

</div>
