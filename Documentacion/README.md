## Signatures & Authentication (Deliverable D5)

### Signature Design

- **Selected algorithm:** **Ed25519** (via the `cryptography` library). It gives small keys (32 bytes), fixed-size 64-byte signatures, deterministic signing (no per-signature nonce to get wrong) and is fast. Keys are raw 32-byte values stored as lowercase hex.
- **Signer identification (`signer_id`):** SHA-256 fingerprint (64 hex characters) of the raw Ed25519 public key, computed by `signer_id_from_ed25519_public_key` in `aad_builder.py`.
- **Signature encoding:** 64 raw bytes, stored as 128 lowercase hex characters in the `signature` field.
- **What is signed:** the canonical payload built by `build_signing_payload`: the domain prefix `vault-d5-signature/v1\x00` followed by the canonical JSON (sorted keys, compact separators) of `metadata`, `recipients`, `nonce`, `ciphertext`, `tag` and `signer_id`. The `signature` field itself is never part of the payload.
- **Hash -> Sign -> Verify:** the payload is hashed with SHA-256 and the 32-byte digest is the message signed with Ed25519. Ed25519 already hashes internally with SHA-512, so this pre-hash is not strictly required; we keep it to follow the Hash -> Sign -> Verify scheme, and it is harmless (the signer and verifier always apply it the same way).
- **Domain separation:** the `vault-d5-signature/v1\x00` prefix makes sure a signature made for this container format cannot be reused as a valid signature for other data (and it differs from the AAD prefix `vault-d3-aad/v1\x00`).

### Updated Container Schema (D5)

```json
{
  "metadata": { "...": "same as D3" },
  "recipients": [ { "...": "same as D3" } ],
  "nonce": "12-byte hex string (24 characters)",
  "ciphertext": "variable-length hex string",
  "tag": "16-byte hex string (32 characters)",
  "signature": "64-byte Ed25519 signature as hex (128 characters)",
  "signer_id": "SHA-256 fingerprint of the signer's public key (64 hex characters)"
}
```

### Flow

1. **Sign (encryption side):** Encrypt -> add metadata and recipients -> compute `signer_id` -> build the signing payload -> SHA-256 -> Ed25519 sign -> store the container (`sign_container`).
2. **Verify (decryption side), before decrypting:**
   1. Validate the container structure (a missing `signature` or `signer_id` is rejected here).
   2. Check that the given public key matches the container's `signer_id`.
   3. Rebuild the payload from the container, hash it and verify the signature (`verify_container`).
   4. Only if everything passes, continue with ECIES unwrap and AES-GCM decryption.
- Any failure raises `SignatureVerificationError` (or `ContainerFormatError` for malformed containers). Verification never returns `False`, so a caller cannot forget to check the result (fail-closed).

### Security Decisions

- **Why sign the ciphertext (and not the plaintext)?**
  The verifier can check authenticity before decrypting anything, so a forged or modified container is rejected without releasing plaintext or touching private keys. Signing the plaintext would force us to decrypt first and would make the signature depend on data the storage layer should never see.
- **Why add a signature if AES-GCM already authenticates the data?**
  GCM uses a symmetric key (the DEK) that every recipient can recover, so any recipient could build a container with a valid tag. The signature proves who produced the container: only the holder of the signer's private key can create it.
- **What if the signature is not verified first?**
  The system would parse, unwrap keys and decrypt data coming from an unauthenticated source. An attacker could swap in a container made with their own keys (valid for AES-GCM but not from the real sender) and the recipient would accept it, or feed malformed data to the decryption code. Verifying first means untrusted data is rejected before any decryption work.
- **What if the metadata (and recipients) were excluded from the signature?**
  An attacker could change the filename, the algorithms, the timestamp or the recipient list without breaking the signature. For example, they could re-label the container or add or remove recipients. By signing metadata, recipients, nonce, ciphertext, tag and `signer_id` together, changing any of them invalidates the signature.
- **Why is `signer_id` inside the signed payload?**
  So an attacker cannot change who the container claims to be signed by without invalidating the signature.

### Test Coverage (D5)

`tests/test_signature_manager.py` (23 tests) covers the five mandatory cases:
- **A:** valid signature accepted.
- **B:** modified ciphertext rejected.
- **C:** modified metadata, recipients, nonce or tag rejected.
- **D:** wrong public key rejected (also a swapped `signer_id`).
- **E:** removed `signature` (or `signer_id`) rejected.
- Plus malformed signatures (wrong length, uppercase hex, non-string, empty) and a signature copied from another container.

### Limitations

- **Trusted public key:** `verify_container` checks that the signature matches the public key it is given and that the key matches `signer_id`. Deciding which public key is trustworthy for a given signer (a key registry or the key storage of D6) is part of the full-flow integration and is not solved by this module.
- A valid old container can still be replayed (no rollback protection), and the signature does not hide any data (confidentiality comes from AES-GCM/ECIES).