# RENIEC-DEMO Offline Authenticator

Prototipo academico reproducible para investigar autenticacion offline de credenciales digitales. No es un sistema oficial de RENIEC, no usa certificados oficiales ni datos reales.

## Arquitectura

- `backend/`: FastAPI, SQLite, Ed25519, SHA-256, QR con `qrcode`, LSB y shares 2-de-2.
- `frontend/`: React + Vite + TypeScript, PWA, Service Worker, Cache Storage e IndexedDB.
- `backend/tests/`: pruebas de hash, firma, emision, manipulacion, shares y esteganografia.

## Ejecucion

```powershell
cd backend
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

En otra terminal:

```powershell
cd frontend
npm install
npm run dev
```

Abrir `http://localhost:5173`. Swagger queda en `http://localhost:8000/docs`.

## Flujo de demo

1. En **Emitir**, usar los datos ficticios precargados y generar una credencial.
2. En **Verificar**, cargar el sobre JSON de la ultima emision y analizarlo. La firma se valida localmente con Web Crypto.
3. Desactivar la red del navegador: la PWA conserva el shell y la verificacion no ejecuta HTTP.
4. En **Sincronizacion**, volver a conectar y enviar los registros IndexedDB.
5. En **Laboratorio**, ejecutar los ataques A/B/C y descargar el JSON medido.
6. Para cinco credenciales demo, llamar `POST /api/demo/seed` desde Swagger.

## Claves y datos

La primera ejecucion crea `backend/data/ed25519-private.pem`. La private key no se serializa en respuestas y `data/` esta excluido de Git. Copiar `.env.example` a `.env` si se necesitan rutas u origenes distintos.

## Limitaciones experimentales

La propuesta implementa operaciones reales. El QR generado es real y el lector usa OpenCV. La criptografia visual es un esquema 2-de-2 de mascaras binarias XOR sobre imagenes; una share aislada no reconstruye el secreto. La esteganografia usa longitud + payload en bits LSB RGB. PSNR, MSE y SSIM de ataques de imagen no se fabrican: requieren una imagen atacada que se puede incorporar como siguiente fase experimental. El laboratorio actual mide los ataques de payload y tiempos del proceso, y marca como aplicabilidad los casos que necesitan imagen.

## Tests

```powershell
cd backend
python -m pytest -q
```

## Seguridad

Validacion Pydantic, limites de imagen, CORS configurable, errores HTTP, datos ficticios, claves fuera del frontend y logs sin nombres. Esta implementacion es de investigacion y no debe desplegarse como infraestructura de identidad.
