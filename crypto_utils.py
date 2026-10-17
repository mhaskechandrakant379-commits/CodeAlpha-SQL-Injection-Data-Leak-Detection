import base64
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_PATH = Path(__file__).with_name("encryption.key")


def _load_key():
    encoded_key = os.environ.get("ENCRYPTION_KEY_B64")

    if encoded_key:
        try:
            key = base64.b64decode(encoded_key, validate=True)
        except Exception as exc:
            raise RuntimeError(
                "ENCRYPTION_KEY_B64 must be valid Base64."
            ) from exc
    else:
        if not KEY_PATH.exists():
            raise RuntimeError(
                "Encryption key missing. Configure ENCRYPTION_KEY_B64 "
                "or provide encryption.key."
            )

        key = KEY_PATH.read_bytes()

    if len(key) != 32:
        raise RuntimeError("AES-256 key must be exactly 32 bytes.")

    return key


def encrypt_text(plaintext):
    if not isinstance(plaintext, str):
        raise TypeError("Plaintext must be a string.")

    nonce = os.urandom(12)
    ciphertext = AESGCM(_load_key()).encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None,
    )

    return base64.urlsafe_b64encode(
        nonce + ciphertext
    ).decode("ascii")


def decrypt_text(encoded_data):
    combined = base64.urlsafe_b64decode(encoded_data.encode("ascii"))

    if len(combined) < 13:
        raise ValueError("Encrypted data is invalid or incomplete.")

    nonce = combined[:12]
    ciphertext = combined[12:]

    plaintext = AESGCM(_load_key()).decrypt(
        nonce,
        ciphertext,
        None,
    )

    return plaintext.decode("utf-8")