### Encryption Design Section

*   **Selected AEAD Algorithm:** AES-256-GCM, this provides authenticated encryption with associated data (AEAD) in a single, efficient cryptographic primitive.
*   **Key Size:** 256 bits (32 bytes), a fresh, unique symmetric key is generated per file using a Cryptographically Secure Pseudorandom Number Generator (CSPRNG).
*   **Nonce Strategy:** 96-bit (12 bytes) nonces generated randomly for each encryption operation, he nonce is stored alongside the ciphertext to ensure uniqueness and prevent keystream reuse.
*   **Metadata Authentication Strategy:** Metadata (filename, version, timestamps) is serialized into a canonical JSON format and cryptographically bound to the ciphertext using Additional Authenticated Data (AAD), any unauthorized modification to the JSON header will invalidate the authentication tag and cause the decryption to fail securely (fail-closed).

### Security Decisions

*   **Why AEAD instead of encryption + hash?**
    AEAD guarantees both confidentiality and integrity simultaneously through a single mathematical operation, performing encryption and hashing separately (such as Encrypt-then-MAC) is prone to implementation errors, composition flaws, and padding oracle attacks. AEAD ensures a strict, secure-by-default fail-closed mechanism.
*   **What happens if nonce repeats?**
    In AES-GCM, reusing a nonce with the same key is catastrophic, it cancels out the keystream, allowing an attacker to recover the XOR of the plaintexts and potentially forge authentication tags by compromising the internal GHASH key, this is why our design enforces strict nonce uniqueness.
*   **What attacker are you defending against?**
    We defend against an active network attacker (Man-in-the-Middle) who can intercept and modify the JSON container in transit (altering filenames for Path Traversal attacks or tampering with the ciphertext), we also defend against local attackers attempting to silently modify the stored metadata files to bypass security checks or forge integrity.