"""Application-level operations for Secure Document Vault (D6).

No input() or getpass() calls live here. Passwords are provided by the caller
(CLI now, PySide6 dialogs later). The core cryptographic modules remain intact.
This prototype handles documents in memory, not streamed large files.
"""

import json
import os
from pathlib import Path
from typing import Callable

from src.crypto.key_backup import create_backup, restore_backup, verify_backup
from src.crypto.key_lifecycle import (
    KeyLifecycleError,
    build_trusted_signers,
    check_key_usable,
    encrypt_with_registry,
    generate_key,
    get_active_key,
    load_registry,
    revoke_key,
    rotate_key,
)
from src.crypto.secure_keystore import decrypt_private_key, load_keystore
from src.crypto.signature_manager import verify_container_with_registry

PasswordProvider = Callable[[dict], str]


def _write_new_file(path: Path, content: bytes) -> Path:
    """Create once, without overwriting a pre-existing document or symlink."""
    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    try:
        with path.open("xb") as f:
            created = True
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass  # Windows file permissions are handled by the platform.
            f.write(content)
    except BaseException:
        if created:
            path.unlink(missing_ok=True)
        raise
    return path


class VaultService:
    """Portable service layer. Never receives secrets as CLI arguments."""

    def __init__(self, data_dir: str | Path, registry_password: str):
        self.data_dir = Path(data_dir).expanduser()
        self.registry_path = self.data_dir / "registry.json"
        self.keystore_dir = self.data_dir / "keystores"
        self.registry_password = registry_password

    def registry(self) -> dict:
        return load_registry(self.registry_path, self.registry_password)

    def init_user(self, user_id: str, password: str, *, algorithm: str = "both",
                  validity_days: int = 365) -> list[dict]:
        algorithms = ("secp256k1", "Ed25519") if algorithm == "both" else (algorithm,)
        if not algorithms or any(a not in {"secp256k1", "Ed25519"} for a in algorithms):
            raise ValueError("Unsupported key algorithm.")
        # Validate before any side effects. A partial initial setup can be
        # resumed with --algorithm for the missing key type.
        if self.registry_path.exists():
            registry = self.registry()
            for a in algorithms:
                if any(e["user_id"] == user_id and e["algorithm"] == a and
                       e["status"] == "active" for e in registry["keys"].values()):
                    raise KeyLifecycleError(f"Active {a} key already exists for user {user_id}.")
        return [generate_key(self.registry_path, user_id, a, password, self.keystore_dir,
                             registry_password=self.registry_password,
                             validity_days=validity_days) for a in algorithms]

    def rotate(self, user_id: str, algorithm: str, new_password: str, *,
               validity_days: int = 365) -> dict:
        return rotate_key(self.registry_path, user_id, algorithm, new_password,
                          self.keystore_dir, registry_password=self.registry_password,
                          validity_days=validity_days)

    def revoke(self, key_id: str, reason: str) -> dict:
        return revoke_key(self.registry_path, key_id, reason,
                          registry_password=self.registry_password)

    def list_keys(self) -> list[dict]:
        return sorted(self.registry()["keys"].values(),
                      key=lambda item: (item["user_id"], item["algorithm"], item["created_at"]))

    def _unlock(self, entry: dict, password_provider: PasswordProvider, *, purpose: str) -> str:
        """Validate keystore metadata before requesting a password; authenticate after."""
        ks_path = self.keystore_dir / entry["keystore_file"]
        keystore = load_keystore(ks_path)
        meta = keystore["metadata"]
        expected_usage = "signing" if purpose == "sign" else "decryption"
        if (meta["key_id"] != entry["key_id"] or
            meta["algorithm"] != entry["algorithm"] or
            meta.get("user_id") != entry["user_id"] or
                meta["usage"] != expected_usage):
            raise KeyLifecycleError("Keystore identity or usage does not match the registry.")
        password = password_provider(entry)
        if not isinstance(password, str) or not password:
            raise ValueError("Keystore password is required.")
        try:
            return decrypt_private_key(keystore, password,
                                       expected_usage=expected_usage,
                                       expected_key_id=entry["key_id"])
        finally:
            del password

    def encrypt_file(self, source: str | Path, output: str | Path,
                     signer_user: str, recipients: list[str],
                     password_provider: PasswordProvider) -> Path:
        """Only registered, active recipients and signer can create a D5 file."""
        if len(recipients) < 2 or len(set(recipients)) != len(recipients):
            raise ValueError("Provide at least two distinct recipients.")
        destination = Path(output)
        if destination.exists():
            raise FileExistsError(f"Output file already exists: {destination}")
        registry = self.registry()
        signer = get_active_key(registry, signer_user, "Ed25519")
        check_key_usable(registry, signer["key_id"], "sign")
        recipient_keys = {}
        for user in recipients:
            entry = get_active_key(registry, user, "secp256k1")
            check_key_usable(registry, entry["key_id"], "encrypt_to")
            recipient_keys[user] = entry["public_key"]
        private_signing = self._unlock(signer, password_provider, purpose="sign")
        try:
            source = Path(source)
            content = source.read_bytes()
            container = encrypt_with_registry(registry, content, source.name,
                                              recipient_keys, private_signing)
        finally:
            del private_signing
        encoded = (json.dumps(container, indent=2, sort_keys=True) + "\n").encode("utf-8")
        return _write_new_file(destination, encoded)

    def decrypt_file(self, source: str | Path, output: str | Path, user_id: str,
                     password_provider: PasswordProvider) -> Path:
        """Check signature, identity and status BEFORE prompting for a password.

        Deliberately does not expose recovery=True for revoked keys: the D6
        follow-up matrix requires strict rejection for normal user operations.
        """
        destination = Path(output)
        if destination.exists():
            raise FileExistsError(f"Output file already exists: {destination}")
        registry = self.registry()
        container = json.loads(Path(source).read_text(encoding="utf-8"))
        # Authenticated D5 signature and D6 signer authorization first.
        verify_container_with_registry(registry, container)
        recipient = next((r for r in container["recipients"] if r["id"] == user_id), None)
        if recipient is None or not recipient.get("key_id"):
            raise KeyLifecycleError("User has no registered recipient key in this document.")
        entry = check_key_usable(registry, recipient["key_id"], "decrypt")
        if entry["user_id"] != user_id or entry["algorithm"] != "secp256k1":
            raise KeyLifecycleError("Recipient identity or algorithm mismatch.")
        private_decryption = self._unlock(entry, password_provider, purpose="decrypt")
        try:
            # Import lazily so unrelated CLI actions don't require eciespy/coincurve.
            from src.crypto.hybrid_vault import decrypt_hybrid

            plaintext = decrypt_hybrid(container, user_id, private_decryption,
                                       trusted_signers=build_trusted_signers(registry))
            return _write_new_file(destination, plaintext)
        finally:
            del private_decryption

    def backup_keystore(self, key_id: str, output: str | Path) -> dict:
        """Single-keystore backup only; Yuki owns future full-vault backups."""
        entry = self.registry()["keys"].get(key_id)
        if entry is None:
            raise KeyLifecycleError("Unknown key_id.")
        return create_backup(self.keystore_dir / entry["keystore_file"], output)

    def restore_keystore(self, key_id: str, backup: str | Path) -> Path:
        """Restore only an existing registered identity, with no overwrites."""
        entry = self.registry()["keys"].get(key_id)
        if entry is None:
            raise KeyLifecycleError("Unknown key_id; registry must be restored separately.")
        summary = verify_backup(backup, expected_key_id=key_id)
        if (summary["algorithm"] != entry["algorithm"] or
                summary["user_id"] != entry["user_id"]):
            raise KeyLifecycleError("Backup identity does not match the trusted registry.")
        return restore_backup(backup, self.keystore_dir / entry["keystore_file"],
                              expected_key_id=key_id, overwrite=False)
