"""Secure Keystore module for D6 (Key Management).

Provides password-based encryption (Scrypt + AES-256-GCM), structured serialization,
and fail-closed authentication for secp256k1 and Ed25519 private keys at rest.
"""

from __future__ import annotations

import datetime
import json
import os
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYSTORE_VERSION = "1.0"
PRIVATE_KEY_SIZE_BYTES = 32
SALT_SIZE_BYTES = 16
NONCE_SIZE_BYTES = 12
TAG_SIZE_BYTES = 16

DEFAULT_SCRYPT_N = 65536  # 2^16
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
DEFAULT_SCRYPT_DKLEN = 32

ALLOWED_ALGORITHMS = {
    "secp256k1": "decryption",
    "Ed25519": "signing",
}

_HEX_64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_USER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

REQUIRED_TOP_FIELDS = {
    "metadata",
    "kdf_parameters",
    "salt",
    "nonce",
    "encrypted_private_key",
}

REQUIRED_METADATA_FIELDS = {
    "version",
    "key_id",
    "algorithm",
    "usage",
    "created_at",
}

REQUIRED_KDF_FIELDS = {
    "algorithm",
    "n",
    "r",
    "p",
    "dklen",
}


class KeystoreError(ValueError):
    """Raised when keystore validation, authentication, or decryption fails."""


def _validate_hex_bytes(value: Any, field_name: str, expected_len: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise KeystoreError(f"Field '{field_name}' must be a hex string.")
    clean = value.removeprefix("0x")
    if clean != clean.lower():
        raise KeystoreError(f"Field '{field_name}' must use lowercase hexadecimal.")
    try:
        raw = bytes.fromhex(clean)
    except ValueError as exc:
        raise KeystoreError(f"Field '{field_name}' contains invalid hex.") from exc
    if expected_len is not None and len(raw) != expected_len:
        raise KeystoreError(
            f"Field '{field_name}' must be exactly {expected_len} bytes (got {len(raw)})."
        )
    return raw


def _validate_password(password: str) -> bytes:
    if not isinstance(password, str) or not password.strip():
        raise KeystoreError("Password must be a non-empty string.")
    return password.encode("utf-8")


def _derive_kek(password_bytes: bytes, salt: bytes, kdf_params: dict[str, Any]) -> bytes:
    if kdf_params.get("algorithm") != "scrypt":
        raise KeystoreError(f"Unsupported KDF algorithm: {kdf_params.get('algorithm')}")
    n = kdf_params.get("n")
    r = kdf_params.get("r")
    p = kdf_params.get("p")
    dklen = kdf_params.get("dklen")

    if not all(isinstance(x, int) and not isinstance(x, bool) for x in (n, r, p, dklen)):
        raise KeystoreError("KDF parameters n, r, p, and dklen must be integers.")
    if dklen != 32:
        raise KeystoreError("KDF dklen must be exactly 32 bytes for AES-256-GCM.")
    if n < 16384 or (n & (n - 1)) != 0:
        raise KeystoreError("Scrypt parameter 'n' must be a power of 2 and >= 16384.")
    if r < 1 or p < 1:
        raise KeystoreError("Scrypt parameters 'r' and 'p' must be positive integers.")

    try:
        kdf = Scrypt(salt=salt, length=dklen, n=n, r=r, p=p)
        return kdf.derive(password_bytes)
    except Exception as exc:
        raise KeystoreError("Failed to derive key encryption key from password.") from exc


def _build_keystore_aad(
    metadata: dict[str, Any], kdf_parameters: dict[str, Any], salt_hex: str
) -> bytes:
    """Canonical serialization binding metadata, KDF parameters, and salt as AAD."""
    aad_payload = {
        "kdf_parameters": kdf_parameters,
        "metadata": metadata,
        "salt": salt_hex,
    }
    canonical_json = json.dumps(aad_payload, sort_keys=True, separators=(",", ":"))
    return b"vault-d6-keystore/v1\x00" + canonical_json.encode("utf-8")


def validate_keystore_schema(keystore: dict[str, Any]) -> None:
    """Validates the structural integrity of a keystore dictionary."""
    if not isinstance(keystore, dict):
        raise KeystoreError("Keystore must be a dictionary.")

    actual_top = set(keystore.keys())
    if actual_top != REQUIRED_TOP_FIELDS:
        raise KeystoreError(
            f"Invalid keystore top-level fields. Expected {sorted(REQUIRED_TOP_FIELDS)}."
        )

    metadata = keystore["metadata"]
    if not isinstance(metadata, dict):
        raise KeystoreError("Keystore 'metadata' must be a dictionary.")
    if not REQUIRED_METADATA_FIELDS.issubset(metadata.keys()):
        raise KeystoreError("Keystore 'metadata' is missing required fields.")

    if metadata.get("version") != KEYSTORE_VERSION:
        raise KeystoreError(f"Unsupported keystore version: {metadata.get('version')}")

    algorithm = metadata.get("algorithm")
    usage = metadata.get("usage")
    if algorithm not in ALLOWED_ALGORITHMS:
        raise KeystoreError(f"Unsupported key algorithm: {algorithm}")
    if ALLOWED_ALGORITHMS[algorithm] != usage:
        raise KeystoreError(
            f"Key usage '{usage}' does not match algorithm '{algorithm}' "
            f"(expected '{ALLOWED_ALGORITHMS[algorithm]}')."
        )

    key_id = metadata.get("key_id")
    if not isinstance(key_id, str) or not _HEX_64_PATTERN.fullmatch(key_id):
        raise KeystoreError("Metadata 'key_id' must be a 64-character lowercase hex SHA-256 hash.")

    user_id = metadata.get("user_id")
    if user_id is not None:
        if not isinstance(user_id, str) or not _USER_ID_PATTERN.fullmatch(user_id):
            raise KeystoreError("Invalid metadata 'user_id'.")

    if not isinstance(metadata.get("created_at"), str) or not metadata["created_at"]:
        raise KeystoreError("Metadata 'created_at' must be a non-empty ISO timestamp string.")

    kdf_params = keystore["kdf_parameters"]
    if not isinstance(kdf_params, dict) or set(kdf_params.keys()) != REQUIRED_KDF_FIELDS:
        raise KeystoreError("Invalid 'kdf_parameters' structure.")

    _validate_hex_bytes(keystore["salt"], "salt", SALT_SIZE_BYTES)
    _validate_hex_bytes(keystore["nonce"], "nonce", NONCE_SIZE_BYTES)

    enc_bytes = _validate_hex_bytes(keystore["encrypted_private_key"], "encrypted_private_key")
    if len(enc_bytes) != PRIVATE_KEY_SIZE_BYTES + TAG_SIZE_BYTES:
        raise KeystoreError("Invalid 'encrypted_private_key' byte length.")


def create_keystore(
    private_key_hex: str,
    password: str,
    *,
    key_id: str,
    algorithm: str = "secp256k1",
    usage: str | None = None,
    user_id: str | None = None,
    scrypt_n: int = DEFAULT_SCRYPT_N,
    scrypt_r: int = DEFAULT_SCRYPT_R,
    scrypt_p: int = DEFAULT_SCRYPT_P,
) -> dict[str, Any]:
    """Encrypts a 32-byte private key under a password-derived key and returns a keystore dict."""
    raw_private_key = _validate_hex_bytes(
        private_key_hex, "private_key_hex", PRIVATE_KEY_SIZE_BYTES
    )
    password_bytes = _validate_password(password)

    if algorithm not in ALLOWED_ALGORITHMS:
        raise KeystoreError(
            f"Unsupported algorithm '{algorithm}'. Choose from {list(ALLOWED_ALGORITHMS)}."
        )

    expected_usage = ALLOWED_ALGORITHMS[algorithm]
    if usage is None:
        usage = expected_usage
    elif usage != expected_usage:
        raise KeystoreError(
            f"Ambiguous or invalid key usage '{usage}' for algorithm '{algorithm}' "
            f"(expected '{expected_usage}')."
        )

    clean_key_id = key_id.removeprefix("0x").lower() if isinstance(key_id, str) else ""
    if not _HEX_64_PATTERN.fullmatch(clean_key_id):
        raise KeystoreError("key_id must be a 64-character hexadecimal SHA-256 fingerprint.")

    metadata: dict[str, Any] = {
        "version": KEYSTORE_VERSION,
        "key_id": clean_key_id,
        "algorithm": algorithm,
        "usage": usage,
        "created_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    if user_id is not None:
        if not isinstance(user_id, str) or not _USER_ID_PATTERN.fullmatch(user_id):
            raise KeystoreError("Invalid user_id: use 1-64 letters, digits, '_' or '-'.")
        metadata["user_id"] = user_id

    kdf_parameters = {
        "algorithm": "scrypt",
        "n": scrypt_n,
        "r": scrypt_r,
        "p": scrypt_p,
        "dklen": DEFAULT_SCRYPT_DKLEN,
    }

    salt = os.urandom(SALT_SIZE_BYTES)
    salt_hex = salt.hex()
    nonce = os.urandom(NONCE_SIZE_BYTES)

    kek = _derive_kek(password_bytes, salt, kdf_parameters)
    aad = _build_keystore_aad(metadata, kdf_parameters, salt_hex)

    aesgcm = AESGCM(kek)
    ciphertext_with_tag = aesgcm.encrypt(nonce, raw_private_key, aad)

    keystore = {
        "metadata": metadata,
        "kdf_parameters": kdf_parameters,
        "salt": salt_hex,
        "nonce": nonce.hex(),
        "encrypted_private_key": ciphertext_with_tag.hex(),
    }
    validate_keystore_schema(keystore)
    return keystore


def decrypt_private_key(
    keystore: dict[str, Any],
    password: str,
    *,
    expected_usage: str | None = None,
    expected_key_id: str | None = None,
) -> str:
    """Authenticates and decrypts the private key from a keystore dictionary."""
    validate_keystore_schema(keystore)
    password_bytes = _validate_password(password)

    metadata = keystore["metadata"]
    if expected_usage is not None and metadata["usage"] != expected_usage:
        raise KeystoreError(
            f"Key usage mismatch: expected '{expected_usage}', found '{metadata['usage']}'."
        )
    if expected_key_id is not None and metadata["key_id"] != expected_key_id.lower():
        raise KeystoreError("Key identifier (key_id) mismatch.")

    salt = bytes.fromhex(keystore["salt"])
    nonce = bytes.fromhex(keystore["nonce"])
    ciphertext_with_tag = bytes.fromhex(keystore["encrypted_private_key"])
    kdf_params = keystore["kdf_parameters"]

    kek = _derive_kek(password_bytes, salt, kdf_params)
    aad = _build_keystore_aad(metadata, kdf_params, keystore["salt"])

    aesgcm = AESGCM(kek)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad)
    except InvalidTag as exc:
        raise KeystoreError(
            "Keystore authentication failed: wrong password or tampered keystore."
        ) from exc

    if len(plaintext_bytes) != PRIVATE_KEY_SIZE_BYTES:
        raise KeystoreError("Decrypted private key has an invalid size.")

    return plaintext_bytes.hex()


def save_keystore(keystore: dict[str, Any], file_path: str | Path) -> Path:
    """Validates and writes a keystore dictionary to disk as canonical JSON."""
    validate_keystore_schema(keystore)
    target = Path(file_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(keystore, indent=2, sort_keys=True)
    target.write_text(content + "\n", encoding="utf-8")
    return target


def load_keystore(file_path: str | Path) -> dict[str, Any]:
    """Reads and validates a keystore JSON file from disk."""
    target = Path(file_path)
    if not target.is_file():
        raise KeystoreError(f"Keystore file not found: {target}")
    try:
        raw_text = target.read_text(encoding="utf-8")
        data = json.loads(raw_text)
    except Exception as exc:
        raise KeystoreError("Failed to parse keystore JSON file.") from exc

    validate_keystore_schema(data)
    return data