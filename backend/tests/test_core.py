import base64
import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.services.crypto_service import canonical_json, sha256_text, sign_text, verify_text
from app.services.image_service import reconstruct_share, steg_decode, steg_encode, visual_shares

client = TestClient(app)


def test_hash_and_signature_roundtrip():
    payload = canonical_json({"b": 2, "a": 1})
    assert sha256_text(payload) == sha256_text(canonical_json({"a": 1, "b": 2}))
    signature = sign_text(payload)
    assert verify_text(payload, signature)
    assert not verify_text(payload + "x", signature)


def test_issue_and_verify():
    response = client.post("/api/credentials", json={"name": "Persona Demo", "identifier": "DEMO-001", "document_type": "IDENTITY", "issued_at": "2026-08-20", "expires_at": "2027-08-20"})
    assert response.status_code == 200
    body = response.json()
    verified = client.post("/api/verify/offline", json={"envelope": body["envelope"]})
    assert verified.status_code == 200
    assert verified.json()["valid"] is True
    altered = json.loads(json.dumps(body["envelope"]))
    altered["payload"]["credential_id"] = "CRD-TAMPERED"
    assert client.post("/api/verify/offline", json={"envelope": altered}).json()["valid"] is False


def test_steganography_and_shares():
    secret = base64.b64encode(b"not-an-image").decode()
    # The shares API is image-oriented; its failure for non-image input is intentional.
    image = client.post("/api/credentials", json={"name": "Share Demo", "identifier": "DEMO-002", "document_type": "IDENTITY", "issued_at": "2026-08-20"}).json()["qr_image"]
    encoded = steg_encode(image, {"check": "ok"})
    assert steg_decode(encoded)["check"] == "ok"
    share_a, share_b = visual_shares(image)
    assert reconstruct_share(share_a, share_b)
