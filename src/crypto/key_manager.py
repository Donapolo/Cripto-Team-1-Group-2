"""Key generation, identification and DEK wrapping for D3.

Private keys returned here are plaintext: D6 will address secure at-rest storage.
"""
import hashlib
import re

from ecies import decrypt, encrypt
from ecies.keys import PrivateKey


class ECIESKeyManager:
    CURVE = "secp256k1"
    DEK_SIZE = 32
    _USER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

    @classmethod
    def validate_user_id(cls, user_id: str) -> str:
        if not isinstance(user_id, str) or not cls._USER_ID_PATTERN.fullmatch(user_id):
            raise ValueError("Invalid user ID: use 1-64 letters, digits, '_' or '-'.")
        return user_id

    @classmethod
    def generate_key_pair(cls) -> dict[str, str]:
        private = PrivateKey(cls.CURVE)
        public_hex = private.public_key.to_hex(True)
        return {
            "private_key": private.to_hex(),
            "public_key": public_hex,
            "key_id": cls.get_key_id(public_hex),
        }

    @staticmethod
    def get_key_id(public_key: str) -> str:
        """SHA-256 fingerprint over canonical compressed secp256k1 public-key bytes."""
        if not isinstance(public_key, str):
            raise ValueError("Public key must be hex text.")
        try:
            key_bytes = bytes.fromhex(public_key.removeprefix("0x"))
        except ValueError as exc:
            raise ValueError("Malformed public key hex.") from exc
        if len(key_bytes) != 33 or key_bytes[0] not in (2, 3):
            raise ValueError("Expected a compressed secp256k1 public key (33 bytes).")
        return hashlib.sha256(key_bytes).hexdigest()

    @classmethod
    def encrypt_dek(cls, dek: bytes, public_key: str) -> str:
        if not isinstance(dek, bytes) or len(dek) != cls.DEK_SIZE:
            raise ValueError("DEK must be exactly 32 bytes.")
        cls.get_key_id(public_key)  # structural check before library invocation
        return encrypt(public_key, dek).hex()

    @classmethod
    def decrypt_dek(cls, encrypted_dek_hex: str, private_key: str) -> bytes:
        """Test/integration helper. Raises ValueError on failed recovery."""
        try:
            encrypted_dek = bytes.fromhex(encrypted_dek_hex)
            dek = decrypt(private_key, encrypted_dek)
            if len(dek) != cls.DEK_SIZE:
                raise ValueError("Invalid recovered DEK size.")
            return dek
        except Exception as exc:
            raise ValueError("Unable to recover DEK.") from exc

    @classmethod
    def encrypt_dek_for_recipients(
        cls, dek: bytes, recipients: dict[str, str]
    ) -> list[dict[str, str]]:
        """Map user IDs to public-key hex; return container-ready recipient entries."""
        if not isinstance(recipients, dict) or not recipients:
            raise ValueError("At least one recipient is required.")
        result = []
        for user_id, public_key in sorted(recipients.items()):
            cls.validate_user_id(user_id)
            result.append({
                "id": user_id,
                "key_id": cls.get_key_id(public_key),
                "encrypted_key": cls.encrypt_dek(dek, public_key),
            })
        return result
