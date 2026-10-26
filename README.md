# Cripto-Team-1-Group-2

Project cryptography semestre 2027-1
jonathanGF - Jonathan Uriel Gonzalez Fernandez
JeedPR - Jesús Eduardo Paz Rosas
Donapol -Vázquez Apolonio Armando
YukiGab - Yukioayax Canek Gabriel Hernández

# Cripto-Team-1-Group-2: Secure Document Vault (D2)

## 1. Overview & Core Architecture
This module implements the core cryptographic engine for a secure document vault. It provides authenticated symmetric encryption to ensure both the confidentiality and integrity of stored files and their associated metadata.

## 2. Cryptographic Algorithm & Security Design
* **Algorithm:** **AES-256-GCM** (Advanced Encryption Standard in Galois/Counter Mode).
* **Mode Selection (AEAD):** We selected an Authenticated Encryption with Associated Data (AEAD) scheme instead of traditional encryption-then-MAC combinations. AES-GCM provides simultaneous cryptographic confidentiality and message integrity within a single primitive, backed by hardware acceleration via AES-NI through Python's `cryptography` library.
* **Key Size:** 256-bit symmetric keys generated securely via the operating system's Cryptographically Secure Pseudo-Random Number Generator (`AESGCM.generate_key(bit_length=256)`).
* **Nonce Strategy:** A unique 96-bit (12 bytes) nonce is generated for every encryption operation using `os.urandom(12)`. This strictly prevents nonce reuse, protecting the counter-mode stream from catastrophic key and plaintext recovery vulnerabilities.

* ## 3. Metadata Protection & AAD (Additional Authenticated Data)
To prevent tampering with file context (such as renaming or substituting files), metadata is cryptographically bound to the ciphertext:
* **Captured Metadata:** Includes algorithm version (`AES-256-GCM`), original filename, timestamp (UTC), and cryptographic parameters.
* **Binding Mechanism:** The metadata dictionary is deterministically serialized (`json.dumps` with sorted keys) and passed as **AAD** to the AES-GCM encryption function. 
* **Security Effect:** The authentication tag (GHASH) authenticates both the payload and the AAD. Any unauthorized modification to the filename or headers during storage or transit will cause the integrity verification to fail.

## 4. Fail-Closed Security Policy
The decryption process follows a strict **fail-closed** paradigm:
* **Exception Handling:** Operations are wrapped to catch cryptographic failures (`InvalidTag`) and structural malformations.
* **Behavior:** If a ciphertext byte or a metadata field is tampered with, or if an incorrect key is provided, the module immediately halts processing, raises a critical error (`RuntimeError`), and refuses to release any partial or plaintext data, preventing attacks based on corrupted states.

* ## 5. Encrypted Vault Container Structure
The vault output is structured as a self-contained dictionary containing:
* **`header`**: Metadata fields in plain view, cryptographically bound via AAD.
* **`nonce`**: Base64-encoded 96-bit initialization vector.
* **`payload`**: Base64-encoded concatenation of the ciphertext and the 128-bit authentication tag.

## 6. Testing & Quality Assurance
The test suite is modularized to ensure independent verification of core components:
* `test_roundtrip.py`: Validates successful encryption/decryption cycles and nonce uniqueness.
* `test_metadata.py`: Validates AAD binding and detects unauthorized header tampering.
* `test_security_failures.py`: Validates the fail-closed policy against incorrect keys and modified ciphertexts.

To run the complete test suite locally, execute:
```bash
python -m pytest -o pythonpath="." -v

# Cripto-Team-1-Group-2: Hybrid Encryption (D3)

## Hybrid Design Explanation

### 1. Why hybrid encryption is used
Asymmetric cryptography (such as ECIES over secp256k1) involves heavy mathematical operations over elliptic curve points, making it computationally inefficient and unsuitable for encrypting large arbitrary payloads. Conversely, symmetric encryption provides optimal performance at line-rate speeds but requires a secure channel to share the secret key beforehand. Hybrid encryption resolves this trade-off: bulk data is encrypted using high-performance symmetric cryptography, while asymmetric mechanisms securely distribute the single-use key to authorized entities without pre-shared secrets.

### 2. Why symmetric encryption is still needed
Symmetric encryption—specifically AES-256-GCM—is essential for several reasons:
* **Throughput and Scalability:** AES-GCM leverages hardware acceleration (AES-NI and CLMUL) to process multi-megabyte and gigabyte payloads with negligible latency.
* **Payload Size Constraints:** Asymmetric algorithms impose strict limits on the maximum message size they can directly encapsulate.
* **Authenticated Encryption (AEAD):** AES-GCM provides confidentiality and cryptographic integrity simultaneously, ensuring ciphertext tampering is detected immediately during the GHASH evaluation step.

### 3. Why per-recipient key encryption is required
Each authorized recipient possesses a unique secp256k1 key pair. To grant access to multiple recipients without duplicating the encrypted payload:
* A single, ephemeral 256-bit Data Encryption Key (DEK) encrypts the bulk file once.
* The DEK is independently encapsulated (wrapped) for each recipient using their specific public key via ECIES.
* This architecture maintains strict cryptographic isolation: compromise of an individual recipient's private key does not leak the private keys of peer recipients, while revoking or adding a participant only requires managing lightweight key-wrap entries rather than re-encrypting the entire dataset.

---

## Security Decisions

### 1. How do recipients identify their key?
The container structure identifies recipient entries through deterministic metadata:
* **`id`:** A validated user identifier (conforming to regex restrictions) allowing deterministic lookup without trying trial decryptions.
* **`key_id`:** A canonical SHA-256 fingerprint generated over the 33-byte compressed secp256k1 public key (`ECIESKeyManager.get_key_id()`). This allows a client with multiple keys or sub-identities to resolve the target key pair unambiguously.

### 2. What happens if an attacker modifies the recipient list?
The implementation enforces a **Fail-Closed policy**:
* The canonical serialization of both `metadata` and the complete `recipients` list is bound directly to the AES-GCM Additional Authenticated Data (`AAD`) via `build_aad()`.
* If an attacker alters an `id`, modifies an `encrypted_key`, reorders the recipients, injects a rogue entry, or drops a recipient, the calculated GHASH authentication tag will not match the container's `tag`.
* AES-GCM decryption immediately fails and raises an `IntegrityError` before any plaintext is released, preventing unauthorized key substitution, recipient drop attacks, or metadata tampering.

### 3. What happens if a public key is wrong?
* **Malformed or invalid format:** Validated strictly before operations take place. If a public key does not represent a valid 33-byte compressed point on `secp256k1` (or cannot be parsed to one), `ECIESKeyManager` rejects the operation with a `ValueError`.
* **Valid key but wrong recipient:** If encrypted with an unintended public key, the recipient's private key will fail the ECIES ephemeral ECDH point multiplication / MAC verification stage during `decrypt_dek`, rejecting the process with a `ValueError` without attempting AES-GCM payload decryption.
