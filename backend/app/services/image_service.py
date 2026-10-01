import base64
import io
import json
import secrets
import time
from typing import Any

import numpy as np
import qrcode
from PIL import Image, ImageDraw, ImageFont


def qr_image(payload: dict[str, Any]) -> tuple[str, int, int]:
    encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=8, border=4)
    qr.add_data(encoded)
    qr.make(fit=True)
    image = qr.make_image(fill_color="#0b1628", back_color="#f7fbff").convert("RGB")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii"), qr.version, len(encoded.encode("utf-8"))


def credential_image(payload: dict[str, Any], qr_b64: str) -> str:
    canvas = Image.new("RGB", (1100, 720), "#0b1628")
    draw = ImageDraw.Draw(canvas)
    draw.rectangle((30, 30, 1070, 690), outline="#69e6c9", width=3)
    draw.text((80, 75), "CREDENCIAL DIGITAL", fill="#f7fbff")
    draw.text((80, 125), "RENIEC-DEMO / DEMO ACADEMICA", fill="#69e6c9")
    draw.text((80, 240), f"ID  {payload['credential_id']}", fill="#f7fbff")
    draw.text((80, 290), f"TIPO  {payload['document_type']}", fill="#f7fbff")
    draw.text((80, 340), f"EMISION  {payload['issued_at'][:10]}", fill="#f7fbff")
    draw.text((80, 390), f"VENCE  {payload.get('expires_at') or 'SIN VENCIMIENTO'}", fill="#f7fbff")
    draw.text((80, 570), "FIRMA DIGITAL / INTEGRIDAD / VERIFICABLE OFFLINE", fill="#69e6c9")
    qr = Image.open(io.BytesIO(base64.b64decode(qr_b64))).convert("RGB").resize((330, 330))
    canvas.paste(qr, (700, 180))
    buffer = io.BytesIO()
    canvas.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def _bytes_for(image: Image.Image, payload: bytes) -> bytes:
    raw = bytearray(np.asarray(image.convert("RGB"), dtype=np.uint8).tobytes())
    framed = len(payload).to_bytes(4, "big") + payload
    if len(framed) * 8 > len(raw):
        raise ValueError("La imagen no tiene capacidad suficiente para el payload LSB")
    bits = [(byte >> shift) & 1 for byte in framed for shift in range(7, -1, -1)]
    for index, bit in enumerate(bits):
        raw[index] = (raw[index] & 254) | bit
    return bytes(raw)


def steg_encode(image_b64: str, payload: dict[str, Any]) -> str:
    image = Image.open(io.BytesIO(base64.b64decode(image_b64))).convert("RGB")
    encoded = _bytes_for(image, json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode())
    result = Image.frombytes("RGB", image.size, encoded)
    buffer = io.BytesIO()
    result.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def steg_decode(image_b64: str) -> dict[str, Any]:
    image = Image.open(io.BytesIO(base64.b64decode(image_b64))).convert("RGB")
    raw = np.asarray(image, dtype=np.uint8).tobytes()
    bits = [raw[index] & 1 for index in range(32)]
    size = int.from_bytes(bytes(sum(bits[offset + bit] << (7 - bit) for bit in range(8)) for offset in range(0, 32, 8)), "big")
    if size <= 0 or (size + 4) * 8 > len(raw):
        raise ValueError("Payload LSB invalido")
    data_bits = [raw[index] & 1 for index in range(32, 32 + size * 8)]
    data = bytes(sum(data_bits[offset + bit] << (7 - bit) for bit in range(8)) for offset in range(0, len(data_bits), 8))
    return json.loads(data.decode())


def visual_shares(secret_b64: str) -> tuple[str, str]:
    secret = Image.open(io.BytesIO(base64.b64decode(secret_b64))).convert("L")
    pixels = np.asarray(secret)
    random_mask = np.random.default_rng(secrets.randbits(64)).integers(0, 2, pixels.shape, dtype=np.uint8)
    secret_bits = (pixels < 128).astype(np.uint8)
    share_a = random_mask
    share_b = np.bitwise_xor(random_mask, secret_bits)
    output = []
    for share in (share_a, share_b):
        image = Image.fromarray((255 * (1 - share)).astype(np.uint8), mode="L")
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        output.append(base64.b64encode(buffer.getvalue()).decode("ascii"))
    return output[0], output[1]


def reconstruct_share(share_a_b64: str, share_b_b64: str) -> str:
    first = np.asarray(Image.open(io.BytesIO(base64.b64decode(share_a_b64))).convert("L"))
    second = np.asarray(Image.open(io.BytesIO(base64.b64decode(share_b_b64))).convert("L"))
    if first.shape != second.shape:
        raise ValueError("Las shares no tienen el mismo tamano")
    reconstructed = np.bitwise_xor((first < 128).astype(np.uint8), (second < 128).astype(np.uint8))
    image = Image.fromarray((255 * (1 - reconstructed)).astype(np.uint8), mode="L")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode("ascii")
