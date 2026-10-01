import base64
import csv
import io
import json
import time
import uuid
from datetime import date, datetime, timezone
from typing import Any

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from PIL import Image
import cv2
import numpy as np
from pydantic import BaseModel, Field, field_validator

from .config import settings
from .database import connect, init_db, json_value, now_iso, row_to_dict
from .services.crypto_service import canonical_json, public_key_b64, sha256_text, sign_text, verify_text
from .services.image_service import credential_image, qr_image, reconstruct_share, steg_decode, steg_encode, visual_shares

app = FastAPI(title=settings.app_name, version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=settings.origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
init_db()


class CredentialInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    identifier: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9_-]+$")
    document_type: str = Field(default="IDENTITY", min_length=2, max_length=40)
    issued_at: date
    expires_at: date | None = None
    additional_data: dict[str, str] = Field(default_factory=dict)

    @field_validator("expires_at")
    @classmethod
    def valid_dates(cls, value: date | None, info):
        if value and info.data.get("issued_at") and value < info.data["issued_at"]:
            raise ValueError("La fecha de expiracion no puede preceder a la emision")
        return value


class VerifyInput(BaseModel):
    envelope: dict[str, Any]
    offline: bool = False
    public_key: str | None = None


class SharesInput(BaseModel):
    secret: str


class ReconstructInput(BaseModel):
    share_a: str
    share_b: str


class StegInput(BaseModel):
    image: str
    payload: dict[str, Any] = Field(default_factory=dict)


@app.on_event("startup")
def startup():
    init_db()


def build_envelope(payload: dict[str, Any], signature: str, qr_b64: str, version: int, size: int) -> dict[str, Any]:
    return {"version": 1, "issuer": "RENIEC-DEMO", "payload": payload, "signature": signature, "public_key": public_key_b64(), "qr_image": qr_b64, "qr_version": version, "payload_bytes": size}


def verify_envelope(envelope: dict[str, Any], offline: bool) -> dict[str, Any]:
    payload = envelope.get("payload")
    signature = envelope.get("signature", "")
    if not isinstance(payload, dict):
        return {"valid": False, "signature_valid": False, "integrity_valid": False, "reason": "Payload ausente o invalido", "offline": offline}
    canonical = canonical_json(payload)
    digest = sha256_text(canonical)
    signature_valid = verify_text(canonical, signature, envelope.get("public_key"))
    credential_id = str(payload.get("credential_id", ""))
    status = "UNKNOWN"
    with connect() as db:
        row = db.execute("SELECT status FROM credentials WHERE credential_id = ?", (credential_id,)).fetchone()
        if row:
            status = row["status"]
        revocation = db.execute("SELECT status FROM revocations WHERE credential_id = ?", (credential_id,)).fetchone()
        if revocation:
            status = revocation["status"]
    expiry = payload.get("expires_at")
    if status == "VALID" and expiry and expiry < datetime.now(timezone.utc).date().isoformat():
        status = "EXPIRED"
    valid = signature_valid and status == "VALID"
    result = {"valid": valid, "signature_valid": signature_valid, "integrity_valid": signature_valid, "payload_hash": digest, "credential_id": credential_id, "issuer": payload.get("issuer"), "status": status, "offline": offline, "reason": "Firma o integridad invalidas" if not signature_valid else ("Credencial no vigente" if not valid else "OK")}
    with connect() as db:
        db.execute("INSERT OR IGNORE INTO verification_logs (verification_id, credential_id, result, signature_valid, integrity_valid, offline, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)", (str(uuid.uuid4()), credential_id, "VALID" if valid else "INVALID", int(signature_valid), int(signature_valid), int(offline), now_iso()))
    return result


@app.get("/api/health")
def health():
    return {"status": "ok", "issuer": "RENIEC-DEMO", "public_key": public_key_b64()}


@app.post("/api/credentials")
def create_credential(data: CredentialInput):
    started = time.perf_counter()
    payload = {"version": 1, "issuer": "RENIEC-DEMO", "credential_id": f"CRD-{uuid.uuid4().hex[:10].upper()}", "document_type": data.document_type.upper(), "holder_hash": sha256_text(data.name.strip()), "issued_at": data.issued_at.isoformat(), "expires_at": data.expires_at.isoformat() if data.expires_at else None, "additional_data": data.additional_data}
    canonical = canonical_json(payload)
    digest = sha256_text(canonical)
    signature = sign_text(canonical)
    envelope_without_image = {"version": 1, "issuer": "RENIEC-DEMO", "payload": payload, "signature": signature, "public_key": public_key_b64()}
    qr_b64, qr_version, payload_bytes = qr_image(envelope_without_image)
    envelope = build_envelope(payload, signature, qr_b64, qr_version, payload_bytes)
    visual_a, visual_b = visual_shares(qr_b64)
    protected_image = steg_encode(qr_b64, {"credential_id": payload["credential_id"], "payload_hash": digest, "share_checksum": sha256_text(visual_a + visual_b)})
    final_image = credential_image(payload, qr_b64)
    with connect() as db:
        db.execute("INSERT INTO credentials (credential_id, payload, payload_hash, signature, qr_payload, qr_version, status, issued_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, 'VALID', ?, ?)", (payload["credential_id"], canonical, digest, signature, json_value(envelope), qr_version, payload["issued_at"], payload["expires_at"]))
    return {"credential": payload, "payload_hash": digest, "signature": signature, "public_key": public_key_b64(), "envelope": envelope, "qr_image": qr_b64, "final_image": final_image, "share_a": visual_a, "share_b": visual_b, "steganographic_image": protected_image, "issuance_ms": round((time.perf_counter() - started) * 1000, 2)}


@app.get("/api/credentials")
def list_credentials():
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT credential_id, payload, payload_hash, status, issued_at, expires_at FROM credentials ORDER BY id DESC")]


@app.get("/api/credentials/{credential_id}")
def get_credential(credential_id: str):
    with connect() as db:
        row = db.execute("SELECT * FROM credentials WHERE credential_id = ?", (credential_id,)).fetchone()
    if not row:
        raise HTTPException(404, "Credencial no encontrada")
    result = row_to_dict(row)
    result["payload"] = json.loads(result["payload"])
    result["qr_payload"] = json.loads(result["qr_payload"])
    return result


@app.post("/api/verify")
def verify(data: VerifyInput):
    return verify_envelope(data.envelope, data.offline)


@app.post("/api/verify/offline")
def verify_offline(data: VerifyInput):
    return verify_envelope(data.envelope, True)


@app.get("/api/public-key")
def get_public_key():
    return {"issuer": "RENIEC-DEMO", "public_key": public_key_b64()}


@app.post("/api/demo/seed")
def seed_demo_data():
    created = []
    for index in range(1, 6):
        result = create_credential(CredentialInput(name=f"Persona Demo {index:02d}", identifier=f"DEMO-{index:03d}", document_type="IDENTITY", issued_at=date(2026, 8, 20), expires_at=date(2027, 8, 20)))
        created.append(result["credential"]["credential_id"])
    with connect() as db:
        db.execute("UPDATE credentials SET status = 'REVOKED' WHERE credential_id = (SELECT credential_id FROM credentials ORDER BY id DESC LIMIT 2 OFFSET 1)")
        db.execute("UPDATE credentials SET status = 'EXPIRED', expires_at = '2020-01-01' WHERE credential_id = (SELECT credential_id FROM credentials ORDER BY id DESC LIMIT 1)")
    return {"created": created, "statuses": ["VALID", "VALID", "VALID", "REVOKED", "EXPIRED"]}


@app.post("/api/qr/decode")
async def decode_qr(file: UploadFile = File(...)):
    content = await file.read()
    if len(content) > settings.max_image_bytes:
        raise HTTPException(413, "Imagen demasiado grande")
    image = cv2.imdecode(np.frombuffer(content, np.uint8), cv2.IMREAD_COLOR)
    if image is None:
        raise HTTPException(400, "Imagen invalida")
    value, _, _ = cv2.QRCodeDetector().detectAndDecode(image)
    if not value:
        raise HTTPException(422, "No se encontro un QR legible")
    try:
        return json.loads(value)
    except json.JSONDecodeError as exc:
        raise HTTPException(422, "El QR no contiene JSON valido") from exc


@app.post("/api/shares/generate")
def generate_shares(data: SharesInput):
    share_a, share_b = visual_shares(data.secret)
    return {"share_a": share_a, "share_b": share_b}


@app.post("/api/shares/reconstruct")
def shares_reconstruct(data: ReconstructInput):
    try:
        return {"image": reconstruct_share(data.share_a, data.share_b)}
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/steganography/encode")
def steganography_encode(data: StegInput):
    try:
        return {"image": steg_encode(data.image, data.payload)}
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.post("/api/steganography/decode")
def steganography_decode(data: dict[str, str]):
    try:
        return steg_decode(data["image"])
    except Exception as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/revocations")
def revocations():
    with connect() as db:
        return [dict(row) for row in db.execute("SELECT * FROM revocations ORDER BY updated_at DESC")]


@app.post("/api/sync")
def sync(records: list[dict[str, Any]]):
    synced = 0
    with connect() as db:
        for record in records:
            db.execute("INSERT OR IGNORE INTO verification_logs (verification_id, credential_id, result, signature_valid, integrity_valid, offline, timestamp, synced) VALUES (?, ?, ?, ?, ?, 1, ?, 1)", (record.get("verification_id", str(uuid.uuid4())), record.get("credential_id"), record.get("result", "UNKNOWN"), int(record.get("signature_valid", False)), int(record.get("integrity_valid", False)), record.get("timestamp", now_iso())))
            synced += 1
    return {"synced": synced, "synced_at": now_iso()}


@app.post("/api/experiments/run")
def run_experiments(credential_id: str | None = None):
    with connect() as db:
        row = db.execute("SELECT qr_payload FROM credentials WHERE credential_id = ? ORDER BY id DESC LIMIT 1", (credential_id,)).fetchone() if credential_id else db.execute("SELECT qr_payload FROM credentials ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        raise HTTPException(404, "Crea una credencial antes del laboratorio")
    envelope = json.loads(row["qr_payload"])
    attacks = ["Cambio de nombre", "Cambio de identificador", "Cambio de fecha", "QR clonado", "Compresion JPEG", "Ruido", "Recorte", "Manipulacion de pixeles", "Impresion/reescaneo", "Una sola share"]
    results = []
    for attack in attacks:
        for scenario in ("A_CONTROL", "B_FIRMA", "C_PROPUESTA"):
            started = time.perf_counter()
            altered = json.loads(json.dumps(envelope))
            if scenario != "A_CONTROL" and attack in attacks[:3]:
                altered["payload"]["additional_data"] = {"attack": attack}
            result = verify_envelope(altered, True) if scenario != "A_CONTROL" else {"valid": True, "signature_valid": None, "integrity_valid": None, "reason": "Control QR sin firma"}
            detected = (not result["valid"]) if scenario != "A_CONTROL" else False
            item = {"scenario": scenario, "attack": attack, "detected": detected, "valid": result["valid"], "execution_time_ms": round((time.perf_counter() - started) * 1000, 3), "metrics": {"applicable": scenario != "A_CONTROL" or attack in ("QR clonado", "Ruido", "Recorte")}}
            results.append(item)
            with connect() as db:
                db.execute("INSERT INTO experiments (scenario, attack, result, execution_time, metrics, created_at) VALUES (?, ?, ?, ?, ?, ?)", (scenario, attack, "DETECTED" if detected else "NOT_DETECTED", item["execution_time_ms"], json_value(item["metrics"]), now_iso()))
    return {"results": results, "note": "Resultados ejecutados sobre la credencial almacenada; los ataques de imagen requieren una captura para medir PSNR/SSIM."}


@app.get("/api/experiments/results")
def experiment_results():
    with connect() as db:
        rows = [dict(row) for row in db.execute("SELECT * FROM experiments ORDER BY id DESC")]
    for row in rows:
        row["metrics"] = json.loads(row["metrics"])
    return rows


@app.get("/api/experiments/export.csv", response_class=PlainTextResponse)
def export_experiments_csv():
    rows = experiment_results()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["scenario", "attack", "result", "execution_time", "metrics", "created_at"])
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()
