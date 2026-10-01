import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..config import settings


def canonical_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _private_key() -> Ed25519PrivateKey:
    if not settings.key_path.exists():
        settings.key_path.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    return serialization.load_pem_private_key(settings.key_path.read_bytes(), password=None)


def public_key_b64() -> str:
    return base64.b64encode(
        _private_key().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode("ascii")


def sign_text(value: str) -> str:
    return base64.b64encode(_private_key().sign(value.encode("utf-8"))).decode("ascii")


def verify_text(value: str, signature: str, public_key: str | None = None) -> bool:
    try:
        raw_key = base64.b64decode(public_key) if public_key else base64.b64decode(public_key_b64())
        Ed25519PublicKey.from_public_bytes(raw_key).verify(
            base64.b64decode(signature), value.encode("utf-8")
        )
        return True
    except Exception:
        return False
