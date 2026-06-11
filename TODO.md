# TODO — Casa Monarca Criptografía

Estado del proyecto al **2026-06-10 · v1.0.0-RC**.

---

## ✅ Implementado en v1.0.0

### Subsistema (a) — Gestión de Identidades (IAM)

- [x] CA interna con par de claves EC SECP256R1, vigencia configurable (default 5 años)
- [x] Clave privada de la CA cifrada en reposo (AES-256-GCM + PBKDF2-HMAC-SHA256)
- [x] Emisión de certificados X.509 para niveles 1 (admin) y 2 (coordinador)
- [x] Ciclo de vida completo: emisión → suspensión → reactivación → revocación → baja
- [x] Panel de gestión de certificados con historial de estados (`CertificateAuditLog`)
- [x] Modelo `Collaborator` con 4 niveles de acceso y RBAC
- [x] Proceso de onboarding con aprobación multinivel
- [x] Carga de identificación oficial durante onboarding
- [x] Registro de intentos de acceso (`LoginAttempt`) con bloqueo por umbral
- [x] Recuperación de contraseña mediante pregunta de seguridad (hash bcrypt)
- [x] Soporte TOTP (`pyotp`) para acciones críticas

### Subsistema (b) — Gestión de Documentos

- [x] Firma digital ECDSA secp256k1 de cada registro migrante en su creación
- [x] Cifrado AES-256-GCM de todos los campos PII en base de datos
- [x] Hash-chain SHA-256 enlazado (`prev_chain_hash`) sobre todas las acciones
- [x] Verificación de autenticidad de registros desde el expediente
- [x] `EncryptedTextField` / `EncryptedDateField` — cifrado transparente en Django ORM
- [x] Soft-delete con trazabilidad criptográfica

### Subsistema (d) — Formularios con Firma

- [x] Consentimiento informado firmado digitalmente (operador nivel 3)
- [x] Derechos ARCO completos: Acceso, Rectificación, Cancelación, Oposición
- [x] `ArcoTicket` con flujo de autorización: Operativo → Coordinador → Admin
- [x] Plazo legal de 20 días hábiles con seguimiento visual
- [x] Generación de PDF de respuesta para solicitudes de Acceso (ReportLab)
- [x] Workflow de aprobación con hash-chain en cada paso (`ApprovalStep`)
- [x] Firma masiva (batch): múltiples acciones en un solo paso de autenticación

### Subsistema (e) — Verificación Externa

- [x] Panel público de verificación de certificados X.509
- [x] Verificación de firmas de registros sin autenticación requerida

### Subsistema (f) — Gestión de Llaves de BD

- [x] PBKDF2-HMAC-SHA256 con 600,000 iteraciones (OWASP 2023)
- [x] Separación de `DB_ENCRYPTION_MASTER_PASSWORD` y `CA_MASTER_PASSWORD`
- [x] Salt persistente por instalación (`DB_ENCRYPTION_SALT`)

### Infraestructura general

- [x] SDK público (`sdk/`) con los 6 módulos del reto
- [x] Suite de pruebas automatizadas (pytest + pytest-django)
- [x] Demo PKI de extremo a extremo (`Demo.sh`)
- [x] Seed de datos de prueba con 4 usuarios y certificados

---

## 🔄 En progreso

### Subsistema (c) — Firma de Correos

- [ ] La lógica de firma está disponible en `sdk/email_sign.py`
- [ ] Falta integración con cliente de correo (SMTP + Django email backend)
- [ ] Falta interfaz de usuario dentro del panel web

### Auditoría tamper-evident

- [ ] `AuditLog` en `iam/models.py` registra acciones pero no está encadenado con hash
- [ ] Se requiere migrar al mismo esquema de hash-chain que `ActionSignature`

---

## 📋 Pendiente — Alta prioridad

### Seguridad y cumplimiento

- [ ] **MFA obligatorio para nivel 1 y 2** — TOTP existe en el modelo pero no se fuerza en login
- [ ] **Gestión de CRL (Certificate Revocation List)** — actualmente la revocación se maneja en BD; falta endpoint OCSP o distribución de CRL en formato estándar
- [ ] **Flujo ARCO completo para Cancelación y Oposición** — los modelos existen pero las vistas de ejecución están incompletas
- [ ] **Pruebas automatizadas para todos los flujos criptográficos** — agregar vectores de prueba para: derivación de clave PBKDF2, cifrado AES-GCM, hash-chain con 100+ entradas, verificación de firma con cert revocado

### Infraestructura

- [ ] **Rotación de clave maestra de BD** — proceso de re-cifrado de todos los campos PII cuando se rota `DB_ENCRYPTION_MASTER_PASSWORD`
- [ ] **Límite de intentos de descarga de `.key`** — actualmente `key_file_downloaded` es un flag booleano; debería tener un contador y expirar la descarga

---

## 📋 Pendiente — Prioridad media

### Interfaz de usuario

- [ ] **Diseño responsivo para móviles** — las vistas están optimizadas para escritorio
- [ ] **Notificaciones en tiempo real** — usar Django Channels o polling para alertas de nuevos registros ARCO
- [ ] **Dashboard de métricas** — contadores de registros activos, certificados próximos a vencer, solicitudes ARCO abiertas

### Integración con sistemas externos

- [ ] **Soporte para firma autógrafa digitalizada** — combinar firma digital con captura de firma manuscrita en tablet
- [ ] **Integración con sistemas de la Secretaría de Gobernación** — para validación de documentos migratorios oficiales
- [ ] **Exportación a formato PKCS#7** — para interoperabilidad con otros sistemas PKI

### Operaciones

- [ ] **Procedimiento de respaldo y recuperación de llaves** — documentar y automatizar el proceso de backup de la CA y las claves maestras
- [ ] **Configuración de despliegue con Docker** — Dockerfile + docker-compose para reproducibilidad
- [ ] **Configuración de servidor en producción** — guía para Nginx + Gunicorn + MySQL + certificados TLS

---

## 🔮 Futuro / Migración a blockchain

- [ ] **Estructuras de datos compatibles con blockchain** — el hash-chain actual puede migrarse a una cadena de bloques pública para mayor transparencia
- [ ] **Capa de compatibilidad con DID (Decentralized Identity)** — W3C DID spec para interoperabilidad con sistemas de identidad descentralizada
- [ ] **Escalabilidad multi-organización** — soporte para múltiples organizaciones bajo una CA raíz compartida
- [ ] **Sello de tiempo certificado (TSA)** — integración con una Autoridad de Sellado de Tiempo para probar cuándo se firmaron los documentos

---

## 🐛 Problemas conocidos

- **`verify_action_signature` ignora el campo `extra`** — en `registros/services.py`, la función `verify_action_signature` reconstruye el payload con `extra={}` en lugar de leer los datos originales del `ActionSignature`. Esto hace que la verificación de firma siempre falle para registros con metadatos adicionales.
- **`ecc_signing_key.pem` en repositorio** — la clave ECDSA del servidor (`CriptoReto/ecc_signing_key.pem`) está incluida en el repositorio. En producción, esta clave debe generarse en el servidor y nunca versionarse.
- **Campos de formularios ARCO sin validación de tamaño máximo** — los modelos `ArcoRequest` y `ArcoTicket` no tienen límite en el campo `details`, lo que puede permitir payloads excesivamente grandes.
- **`EncryptedTextField` no es compatible con búsquedas ORM** — documentado en el código, pero no hay manejo de error explícito cuando se intenta hacer `filter()` sobre un campo cifrado; el ORM devuelve resultados vacíos en silencio.
- **Migración `0004` tiene conflicto de nombre** — existen dos migraciones con nombre `0004` en `registros/` (`0004_add_internal_id.py` y `0004_migrantregistration_folio.py`), resuelto por `0005_merge_20260601_1540.py` pero puede causar confusión.
