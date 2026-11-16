# D6 – Key Backup, Recovery and Lifecycle

Modules: `src/crypto/key_backup.py` and `src/crypto/key_lifecycle.py`
Tests: `tests/test_key_backup.py` and `tests/test_key_lifecycle.py`

## 1. Backup and recovery

A backup is a copy of Jonathan's keystore (`secure_keystore.py`) placed inside a JSON envelope:

```json
{ "backup_version": "1.0", "created_at": "...", "key_id": "...", "algorithm": "secp256k1",
  "checksum_sha256": "...", "keystore": { ... } }
```

- The private key is already encrypted (Scrypt + AES-256-GCM). So **creating, verifying and restoring a backup never asks for the password and never decrypts anything**. The backup contains no plaintext key and no password.
- Usage: `create_backup` → `verify_backup` → `restore_backup`. Restoring produces a normal keystore. The same password opens it and the `key_id` does not change, so documents encrypted for that key can still be opened.
- `checksum_sha256` (SHA-256 of the canonical keystore JSON) only detects a damaged file. **It is not a security defense**, because anyone with access to the file can recompute it. What really detects tampering is the keystore's AES-GCM tag, which is checked when the key is decrypted.
- No file is overwritten unless `overwrite=True` is passed. Files are written to a temporary file first and then renamed, and owner-only permissions (`0600`) are attempted (may not apply on Windows).
- `verify_backup` checks that the file is intact. Only decrypting the key proves the password works, so it is worth testing a restore from time to time.

## 2. Key lifecycle

A registry (JSON) tracks all keys: public key, status, dates and keystore file name. **It stores no secrets.** The `key_id` must equal the SHA-256 of the public key.

| State | Encrypt to / Sign | Decrypt / Verify old material |
|---|---|---|
| active | yes | yes |
| retired (by rotation) | no | yes |
| expired (`expires_at` passed) | no | yes |
| revoked | no | no, except `decrypt` with `recovery=True` for the owner |

Each algorithm has its own uses: secp256k1 → `encrypt_to` and `decrypt`; Ed25519 → `sign` and `verify`. Using a key for another purpose is rejected. There can be only one active key per user and algorithm.

- **Generation:** `generate_key` creates the key pair, stores the private key only in a password-protected keystore and registers the public data (365-day validity by default).
- **Rotation:** `rotate_key` retires the active key and activates a new one. Old documents can still be opened with the retired key, and new ones use the new key. Rotate on a schedule, before expiry, or if the password may be exposed.
- **Expiry:** happens at `expires_at`. An expired key behaves like a retired one: it no longer encrypts or signs anything new, but old material can still be opened and verified. `get_active_key` forces a rotation.
- **Compromise:** `handle_compromise` revokes the key (a reason is mandatory) and, if it was the active one, creates its replacement in the same save. It returns the steps still to be done by hand: re-encrypt the affected documents with the new key (reading them with `recovery=True`), tell people who encrypt to the old key, remove the revoked signer from trust lists, and delete or secure old keystores and backups.
- **Previous documents:** with retired or expired keys they still open and verify. With revoked keys they do not, and the owner recovers them with `recovery=True` to re-encrypt them. `build_trusted_signers` (active and retired signers, no revoked ones) feeds `decrypt_hybrid(trusted_signers=...)`. Signatures from a revoked signer stop verifying, on purpose.

## 3. Registry integrity and real use

- **Integrity:** the registry file carries an HMAC-SHA256. Its key comes from a password (`registry_password`) through Scrypt with a random salt. `load_registry` checks it first, so if someone edits the JSON by hand (for example, turning a revoked key back to active) loading fails. A wrong password and a modified file give the same error.
- **Applying the rules when encrypting and decrypting:** `encrypt_with_registry` and `decrypt_with_registry` wrap `encrypt_hybrid` and `decrypt_hybrid_with_keystore` and check the registry first. Recipients must be registered, belong to their user and allow `encrypt_to`; the signer must allow `sign`; when decrypting, the key status is checked before asking for the password; and `trusted_signers` is built from the registry. Code that calls `hybrid_vault` directly skips these checks, so these functions are the entry point for policy-aware use.

## 4. Limitations

- Revocation is logical. If an attacker already holds the private key and a copy of the container, they can decrypt it offline. The documents must be re-encrypted.
- A backup is only as strong as its password, because it is equivalent to a stolen keystore. A weak password is a documented risk. Keep the backup away from the keystore.
- The MAC prevents edits but not rollback: an attacker with access to the file can restore an older valid copy (for example, from before a revocation). Detecting that needs an external anchor, such as a counter or a copy stored elsewhere.
- Whoever knows `registry_password` can re-sign the registry.
- Python strings cannot be wiped from memory.

## 5. Running the tests

```
python -m pytest tests/test_key_backup.py tests/test_key_lifecycle.py -v
```
