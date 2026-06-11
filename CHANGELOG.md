# Changelog

Todos los cambios notables de este proyecto se documentan aquí.  
El formato sigue [Keep a Changelog](https://keepachangelog.com/es/1.0.0/).

---

## [1.0.0] — 2026-06-10 — Release Candidate

### Añadido

#### Subsistema (a) — Gestión de Identidades
- CA interna con par de claves EC SECP256R1, vigencia configurable (default 5 años)
- Clave privada de la CA cifrada en reposo con AES-256-GCM derivada de contraseña maestra
- Emisión de certificados X.509 (RSA-2048) para niveles 1 y 2 firmados por la CA
- Ciclo de vida completo de certificados: ACTIVE → SUSPENDED → REACTIVATED → REVOKED / INACTIVE
- Panel de gestión de certificados con historial de estados (`CertificateAuditLog`)
- Modelo `Collaborator` extendiendo `AbstractUser` con 4 niveles de acceso y RBAC
- Proceso de onboarding con aprobación multinivel y carga de identificación oficial
- Autenticación TOTP opcional (`pyotp`) para acciones críticas
- Registro de intentos de acceso (`LoginAttempt`) con bloqueo por umbral configurable
- Recuperación de contraseña mediante pregunta de seguridad (respuesta hasheada con bcrypt)
- JWT de sesión firmado con `PyJWT` (`auth_tokens.py`) con decoradores `@require_role`
- Fingerprint SHA-256 de certificados para identificación rápida

#### Subsistema (b) — Gestión de Documentos
- Firma digital ECDSA secp256k1 de cada registro migrante en su creación (`sign_registration`)
- Cifrado AES-256-GCM de todos los campos PII en base de datos (`EncryptedTextField`, `EncryptedDateField`)
- Hash-chain SHA-256 enlazado (`prev_chain_hash`) sobre todas las acciones del sistema
- Verificación de autenticidad de registros desde el expediente del migrante
- Soft-delete con trazabilidad criptográfica y campo `deleted_at`
- Firma de flujos finales con certificado X.509 (`sign_final_flow`, `FinalFlowAction`)
- Snapshot hash del estado de la BD para sellos de tiempo de contexto (`hash_db_state_django`)

#### Subsistema (d) — Formularios con Firma
- Consentimiento informado firmado digitalmente (operador nivel 3)
- Derechos ARCO completos: modelos `ArcoRequest` y `ArcoTicket`
- Flujo `ArcoTicket`: Operativo → Coordinador → Admin con firma en cada paso
- Seguimiento de plazo legal de 20 días hábiles (LFPDPPP Art. 32)
- Generación de PDF de respuesta para solicitudes de Acceso con ReportLab
- Workflow de aprobación multinivel con hash-chain en cada `ApprovalStep`
- Firma masiva (batch sign): múltiples acciones en una sola sesión de autenticación

#### Subsistema (e) — Verificación Externa
- Panel público de verificación de certificados X.509 (sin autenticación)
- Verificación de firmas ECDSA de registros desde interfaz web

#### Subsistema (f) — Gestión de Llaves
- PBKDF2-HMAC-SHA256 con 600,000 iteraciones para derivación de claves (OWASP 2023)
- Separación de contraseñas: `DB_ENCRYPTION_MASTER_PASSWORD` ≠ `CA_MASTER_PASSWORD`
- Salt persistente por instalación (`DB_ENCRYPTION_SALT`)
- Validación: la función `_get_or_derive_key()` impide pasar contraseñas en texto plano

#### Infraestructura y herramientas
- SDK público (`sdk/`) con 6 módulos que cubren los subsistemas a–f
- Demo PKI de extremo a extremo (`Demo.sh`) con función de limpieza de archivos generados
- Suite de pruebas con pytest + pytest-django (33+ tests)
- Seed de datos de prueba con 4 usuarios representando los 4 niveles de acceso
- Script de inicialización del sistema (`scripts/init_system.py`)
- Configuración MySQL (`mysql_setup.sql`) para despliegue en producción
- `credenciales.txt` de referencia para acceso a base de datos de desarrollo

### Cambiado

- Refactorización de `registros/services.py`: la firma con clave de servidor pasó a ser solo para el hash-chain de trazabilidad; los flujos finales usan `crypto_core.signatures` con certificado X.509
- Corrección de la restricción de firma: solo niveles 1 y 2 pueden firmar acciones (`SIGNING_LEVELS = {1, 2}`)
- Separación de responsabilidades: `crypto_core` es independiente de Django y puede usarse sin el ORM

### Corregido

- `sign_action` ahora lanza `PermissionError` cuando un operativo (nivel 3) o externo (nivel 4) intenta firmar
- `batch_sign_actions` aplica la misma restricción de nivel que `sign_action`
- `EncryptedDateField.formfield()` omite `max_length` para que `DateInput` funcione correctamente
- Manejo explícito de `InvalidTag` en `decrypt_field` para detectar tampering en campos cifrados

### Problemas conocidos

- `verify_action_signature` reconstruye el payload con `extra={}` en lugar de los datos originales (ver [TODO.md](TODO.md))
- `ecc_signing_key.pem` incluido en el repositorio como artefacto de desarrollo (nunca usar en producción)
- Dos migraciones `0004` en `registros/` resueltas por merge en `0005`
- MFA no forzado en el flujo de login (el campo `mfa_enabled` existe pero es opcional)

---

## [Sin versión previa]

Este es el primer release del proyecto. No hay versiones anteriores que documentar.

[1.0.0]: https://github.com/brbrbre/Casa-Monarca-Criptografia/releases/tag/v1.0.0
