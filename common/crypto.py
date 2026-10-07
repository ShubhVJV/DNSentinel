import os
import base64
from cryptography.exceptions import InvalidTag
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_SIZE = 32
NONCE_SIZE = 12

load_dotenv()


def get_key():
    """
    Load the shared AES-256 key from .env.
    """

    key_string = os.getenv("DNSENTINEL_AES_KEY")

    if not key_string:
        raise ValueError(
            "DNSENTINEL_AES_KEY is not set"
        )

    try:
        key = base64.b64decode(key_string)
    except Exception:
        raise ValueError(
            "Invalid Base64 AES key"
        )

    if len(key) != KEY_SIZE:
        raise ValueError(
            "AES key must be exactly 32 bytes"
        )

    return key


def generate_key():
    """
    Generate a 256-bit AES key.
    """

    return AESGCM.generate_key(
        bit_length=256
    )


def encrypt_data(plaintext, key):
    """
    Encrypt plaintext using AES-256-GCM.
    """

    if len(key) != KEY_SIZE:
        raise ValueError(
            "Key must be 32 bytes"
        )

    nonce = os.urandom(NONCE_SIZE)

    aes = AESGCM(key)

    ciphertext = aes.encrypt(
        nonce,
        plaintext.encode("utf-8"),
        None
    )

    encrypted_data = nonce + ciphertext

    return base64.b64encode(
        encrypted_data
    ).decode("ascii")


def decrypt_data(encrypted_data, key):
    """
    Decrypt AES-256-GCM encrypted data.

    Raises:
        ValueError: If authentication fails or the data is invalid.
    """

    if len(key) != KEY_SIZE:
        raise ValueError("Key must be 32 bytes")

    try:
        encrypted_bytes = base64.b64decode(
            encrypted_data
        )

        if len(encrypted_bytes) <= NONCE_SIZE:
            raise ValueError("Encrypted data is too short")

        nonce = encrypted_bytes[:NONCE_SIZE]
        ciphertext = encrypted_bytes[NONCE_SIZE:]

        aes = AESGCM(key)

        plaintext = aes.decrypt(
            nonce,
            ciphertext,
            None
        )

        return plaintext.decode("utf-8")

    except InvalidTag:
        raise ValueError(
            "AES-GCM authentication failed"
        )

    except Exception as e:
        raise ValueError(
            f"Decryption failed: {e}"
        )