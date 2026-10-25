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
