"""D6 - Live demonstration: Secure Document Vault (Armando).

Run from the repository root:
    python tests/demo_d6.py

Demonstrates the five mandatory D6 acceptance criteria and, with ``eciespy``
and ``coincurve`` installed, a full D3/D5/D6 document roundtrip, including
backup/restore and lifecycle enforcement.

All keys and passwords are generated for this demo and deleted from disk when
it finishes; never copy temporary demo credentials into production code.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import secrets
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.crypto.key_backup import create_backup, restore_backup
from src.crypto.key_lifecycle import (
    KeyLifecycleError, generate_key, generate_key_material,
    load_registry, revoke_key,
)
from src.crypto.secure_keystore import (
    KeystoreError, create_keystore, decrypt_private_key,
    load_keystore, save_keystore,
)


def expect_denial(action, expected_exception):
    """A denied operation only passes when the correct failure is raised."""
    try:
        action()
    except expected_exception:
        return
    raise AssertionError("The operation was accepted but must be rejected.")


def execute(label, check):
    check()
    print(f"  [OK] {label}")


def five_required_cases(folder: Path, password: str):
    print("\nD6 - Five required acceptance scenarios")
    pair = generate_key_material("secp256k1")
    path = save_keystore(
        create_keystore(
            pair["private_key"], password, key_id=pair["key_id"],
            user_id="alice", scrypt_n=16384,
        ),
        folder / "alice_keystore.json",
    )

    def correct_password():
        unlocked = decrypt_private_key(
            load_keystore(path), password,
            expected_usage="decryption", expected_key_id=pair["key_id"],
        )
        assert unlocked == pair["private_key"]

    execute("1. Correct password -> access granted", correct_password)
    execute("2. Wrong password -> access denied", lambda: expect_denial(
        lambda: decrypt_private_key(load_keystore(path), "invalid-password"), KeystoreError,
    ))

    def altered_keystore():
        altered = copy.deepcopy(load_keystore(path))
        ct = altered["encrypted_private_key"]
        altered["encrypted_private_key"] = ("0" if ct[0] != "0" else "1") + ct[1:]
        expect_denial(lambda: decrypt_private_key(altered, password), KeystoreError)

    execute("3. Modified keystore -> authentication fails", altered_keystore)

    def restore_identity():
        backup = folder / "alice_backup.json"
        create_backup(path, backup)
        path.unlink()  # Test that restore actually works without the source file.
        restored = restore_backup(
            backup, folder / "alice_restored.json", expected_key_id=pair["key_id"],
        )
        assert decrypt_private_key(
            load_keystore(restored), password, expected_key_id=pair["key_id"],
        ) == pair["private_key"]

    execute("4. Backup -> original identity restored", restore_identity)

    def stolen_keystore():
        stolen = (folder / "alice_restored.json").read_bytes()
        assert pair["private_key"].encode("ascii") not in stolen
        assert password.encode("utf-8") not in stolen
        expect_denial(
            lambda: decrypt_private_key(json.loads(stolen), "unknown-password"), KeystoreError,
        )

    execute("5. Stolen keystore alone -> cannot unlock private key", stolen_keystore)


def hybrid_workflow(folder: Path, password: str, registry_password: str):
    missing = [name for name in ("ecies", "coincurve") if importlib.util.find_spec(name) is None]
    if missing:
        print("\nFull hybrid workflow: NOT RUN")
        print("  Missing dependencies: " + ", ".join(missing))
        print("  Install with: python -m pip install -r requirements.txt")
        return False

    from src.crypto.hybrid_vault import IntegrityError
    from src.crypto.key_lifecycle import decrypt_with_registry, encrypt_with_registry

    print("\nD3 + D5 + D6 - Real end-to-end verification")
    registry_path = folder / "registry.json"
    key_dir = folder / "keystores"
    entries = {}
    for user, algorithm in (
        ("alice", "secp256k1"),
        ("bob", "secp256k1"),
        ("sender", "Ed25519"),
    ):
        entries[user] = generate_key(
            registry_path, user, algorithm, password, key_dir,
            registry_password=registry_password, scrypt_n=16384,
        )

    registry = load_registry(registry_path, registry_password)
    signer_store = key_dir / entries["sender"]["keystore_file"]
    signing_private = decrypt_private_key(
        load_keystore(signer_store), password, expected_usage="signing",
        expected_key_id=entries["sender"]["key_id"],
    )
    secret = b"D6 live: confidential document with signature and two recipients"
    recipients = {user: entries[user]["public_key"] for user in ("alice", "bob")}
    container = encrypt_with_registry(
        registry, secret, "file_d6.txt", recipients, signing_private,
    )
    print("  [OK] File encrypted for Alice and Bob; signed by sender (D5)")

    alice_path = key_dir / entries["alice"]["keystore_file"]
    backup_path = folder / "alice.backup.json"
    create_backup(alice_path, backup_path)
    alice_path.unlink()
    restored = restore_backup(
        backup_path, folder / "alice.recovered.json",
        expected_key_id=entries["alice"]["key_id"],
    )
    with patch("getpass.getpass", return_value=password):
        assert decrypt_with_registry(registry, container, "alice", restored) == secret
    print("  [OK] Restored Alice keystore opens the signed hybrid document")

    tampered = copy.deepcopy(container)
    cipher_hex = tampered["ciphertext"]
    tampered["ciphertext"] = ("0" if cipher_hex[0] != "0" else "1") + cipher_hex[1:]
    with patch("getpass.getpass", side_effect=AssertionError("Prompt must not happen")):
        expect_denial(
            lambda: decrypt_with_registry(registry, tampered, "alice", restored),
            IntegrityError,
        )
    print("  [OK] Modified signed document rejected BEFORE asking for password")

    revoke_key(
        registry_path, entries["alice"]["key_id"], "demo compromised device",
        registry_password=registry_password,
    )
    current_registry = load_registry(registry_path, registry_password)
    with patch("getpass.getpass", side_effect=AssertionError("Prompt must not happen")):
        expect_denial(
            lambda: decrypt_with_registry(current_registry, container, "alice", restored),
            KeyLifecycleError,
        )
    print("  [OK] Revoked key is denied before a password prompt")

    with patch("getpass.getpass", return_value=password):
        recovered_secret = decrypt_with_registry(
            current_registry, container, "alice", restored, recovery=True,
        )
        assert recovered_secret == secret
    print("  [OK] Explicit recovery mode can open an old document (documented policy)")

    modified_registry = json.loads(registry_path.read_text(encoding="utf-8"))
    modified_registry["keys"][entries["alice"]["key_id"]]["status"] = "active"
    registry_path.write_text(json.dumps(modified_registry), encoding="utf-8")
    expect_denial(lambda: load_registry(registry_path, registry_password), KeyLifecycleError)
    print("  [OK] Manual revocation bypass in registry JSON rejected by HMAC")
    return True


def main() -> int:
    print("=" * 62)
    print("D6 - KEY MANAGEMENT | INTEGRATION DEMO")
    print("Jonathan: keystore | Jesus: vault access | Yuki: backup/lifecycle")
    print("Armando: end-to-end acceptance and demonstration")
    print("=" * 62)
    # Disposable random credentials. No real user passwords and no password output.
    demo_password = secrets.token_urlsafe(32)
    registry_password = secrets.token_urlsafe(32)

    try:
        with tempfile.TemporaryDirectory(prefix="d6_demo_") as temp:
            base = Path(temp)
            five_required_cases(base, demo_password)
            full = hybrid_workflow(base, demo_password, registry_password)
    except Exception as error:
        print(f"\n[FAILED] {type(error).__name__}: {error}", file=sys.stderr)
        return 1

    print("\nRESULT: 5/5 mandatory D6 scenarios PASS")
    if full:
        print("RESULT: Real D3 + D5 + D6 integration PASS")
    else:
        print("RESULT: Real D3 + D5 + D6 integration NOT VERIFIED in this environment")
    print("Demo files were stored in a temporary directory and cleaned up.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
