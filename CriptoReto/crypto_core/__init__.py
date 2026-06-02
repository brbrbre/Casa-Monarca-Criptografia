"""
crypto_core — Capa criptográfica unificada de Casa Monarca.

Todo código criptográfico del sistema pasa por este paquete.
Ningún módulo externo a crypto_core debe importar `cryptography` directamente.

Módulos:
  ca            — Autoridad Certificadora interna
  certificates  — Emisión, revocación y verificación de certificados X.509
  signatures    — Firma digital de logs de flujos finales
  encryption    — Cifrado AES-256-GCM para datos sensibles en BD
  hashing       — SHA-256 para integridad de documentos y BD
  auth_tokens   — JWT para sesiones HTTP
"""
