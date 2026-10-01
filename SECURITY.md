# Security

Esto es una DEMO ACADEMICA. RENIEC-DEMO no es RENIEC oficial y no sustituye PKI, revocacion ni controles de identidad.

- Ed25519 es proporcionado por `cryptography`; no hay criptografia casera.
- SHA-256 se calcula sobre JSON canonico.
- La private key se mantiene en backend y se excluye de Git.
- IndexedDB puede ser inspeccionado por el usuario del dispositivo; no se usa para secretos.
- CORS, validacion de campos y limite de imagen estan configurados.
- Para produccion faltan HSM, autenticacion de operadores, rotacion de claves, auditoria inmutable y politica formal de revocacion.
