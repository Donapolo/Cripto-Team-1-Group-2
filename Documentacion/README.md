### Encryption Design Section

*   **Selected AEAD algorithm:** AES-256-GCM (via the `cryptography` library), it encrypts and authenticates in a single primitive, giving us confidentiality, integrity and tamper detection together.

*   **Key size:** 256 bits (32 bytes), a fresh, unique key is generated for every file using the library's CSPRNG, which is backed by the operating system's randomness (`os.urandom`).

*   **Nonce strategy:** a 96-bit (12-byte) nonce is generated randomly with `os.urandom` for every encryption. Since each file also has its own fresh key, a (key, nonce) pair is never reused in practice, the nonce is not secret: it is stored in the container next to the ciphertext because it is required for decryption.

*   **Metadata authentication strategy:** the header (filename, algorithm version, encryption parameters, creation timestamp) is serialized as canonical JSON (sorted keys, compact separators) and passed to AES-GCM as Additional Authenticated Data (AAD). The header stays readable, but it is bound to the authentication tag: any change to it makes decryption fail with a generic `DecryptionError`, and no output file is written (fail-closed), the filename in the header is informational only and is never used as an output path.

### Security Decisions

*   **Why AEAD instead of encryption + hash?**
    A plain hash is not a keyed authenticator: an attacker who modifies the ciphertext can simply recompute the hash, so nothing is detected, a MAC fixes that, but combining a cipher and a MAC by hand is error-prone (order of operations, covering the metadata, constant-time comparison; MAC-then-encrypt designs enabled padding-oracle attacks), AEAD performs encryption and authentication in one well-reviewed primitive, and AAD extends the protection to the metadata.

*   **What happens if the nonce repeats?**
    In AES-GCM, reusing a nonce with the same key is catastrophic, two messages share the same keystream, so XORing their ciphertexts reveals the XOR of the plaintexts, and the attacker can recover the GHASH authentication key and forge valid tags, we mitigate this with a random 96-bit nonce per encryption and a fresh key per file, so each key encrypts exactly one message.

*   **What attacker are you defending against?**
    An attacker who obtains the encrypted container (stolen disk, compromised storage, intercepted copy) but does not have the key, and who may try to read it or modify it, after D2, they cannot read the contents or alter the ciphertext, tag, nonce or header without detection.
    Out of scope for this deliverable: compromise or storage of the key itself, rollback to an older valid container, and deletion of the file. The `metadata.json` activity log is an audit trail, not a security control, and is not authenticated.

