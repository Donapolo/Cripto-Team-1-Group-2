# Cripto-Team-1-Group-2

**Course:** Cryptography (Term 2027-1)  
**Team Members:**
* Jonathan Uriel González Fernández (`jonathanGF`)
* Jesús Eduardo Paz Rosas (`JeedPR`)
* Armando Vázquez Apolonio (`Donapolo`)
* Yukioayax Canek Gabriel Hernández (`YukiGab`)

---

# Phase 1: Secure Document Vault (Deliverable D2)

## 1. Overview & Core Architecture
Implementation of the core symmetric cryptographic engine for the secure document vault, ensuring confidentiality and integrity for both the stored payload and its associated metadata.

## 2. Cryptographic Algorithm & Security Design
* **Algorithm:** **AES-256-GCM** (Galois/Counter Mode).
* **AEAD Scheme:** Authenticated Encryption with Associated Data combined into a single primitive, leveraging hardware acceleration (AES-NI).
* **Key Size:** 256 bits generated via a CSPRNG (`AESGCM.generate_key(bit_length=256)`).
* **Nonce Strategy:** A 96-bit (12-byte) unique nonce generated per operation (`os.urandom(12)`) to strictly prevent IV reuse vulnerabilities.

## 3. Metadata Protection & AAD
* **Bound Metadata:** Algorithm version, original filename, and UTC timestamp.
* **Mechanism:** Deterministic serialization supplied as Additional Authenticated Data (AAD) to AES-GCM.
* **Impact:** Any alteration to header fields causes immediate GHASH tag verification failure.

## 4. Fail-Closed Security Policy
If tampering is detected within the ciphertext or metadata, execution halts immediately (`RuntimeError` / `InvalidTag`) without releasing any plaintext data.

## 5. Original Symmetric Container (D2)
Serialized as a dictionary containing Base64-encoded fields:
* `header`: Plainview metadata bound via AAD.
* `nonce`: 96-bit initialization vector in Base64.
* `payload`: Concatenation of the ciphertext and the authentication tag in Base64.

## 6. D2 Test Suite
* `test_roundtrip.py`: Verifies symmetric encryption/decryption roundtrips.
* `test_metadata.py`: Validates detection of unauthorized header modifications.
* `test_security_failures.py`: Tests error handling against invalid keys and corrupted payloads.

---

# Phase 2: Hybrid Encryption & Multi-Recipient Vault (Deliverable D3)

## 1. Hybrid Design Explanation

### Why hybrid encryption is used
Asymmetric cryptography (such as ECIES over secp256k1) relies on intensive point operations across elliptic curves, making it computationally expensive and impractical for bulk payloads. Conversely, symmetric encryption offers optimal throughput at line rate but requires an existing secure channel to exchange the shared secret. Hybrid encryption resolves this limitation: bulk data is encrypted using high-performance symmetric cryptography, while asymmetric mechanisms securely distribute the single-use key to authorized entities without pre-shared secrets.

### Why symmetric encryption is still needed
* **Throughput and Scalability:** AES-GCM takes full advantage of hardware instructions (AES-NI / CLMUL) to process multi-megabyte files with negligible latency.
* **Payload Constraints:** Asymmetric algorithms impose strict limits on the maximum message size they can directly encapsulate.
* **Integrated Integrity:** AES-GCM natively generates a GHASH authentication tag, ensuring both confidentiality and message authenticity simultaneously.

### Why per-recipient key encryption is required
Each authorized recipient holds an independent secp256k1 key pair. To grant access to multiple recipients without duplicating the encrypted file payload:
* A single, ephemeral 256-bit Data Encryption Key (DEK) encrypts the bulk file once.
* The DEK is independently encapsulated (wrapped) for each recipient using their specific public key via ECIES.
* This guarantees cryptographic isolation: compromising one recipient's private key does not leak peers' keys, and granting or revoking access only requires managing lightweight recipient entries rather than re-encrypting the dataset.

---

## 2. Security Decisions

### How do recipients identify their key?
The container structure identifies recipient entries through deterministic fields:
* **`id`:** Validated user identifier (alphanumeric, max 64 characters) allowing direct lookup without trial decryptions. Duplicate IDs in recipient lists are strictly rejected with a `ValueError`.
* **`key_id`:** Canonical SHA-256 fingerprint generated over the 33-byte compressed secp256k1 public key (`ECIESKeyManager.get_key_id()`), resolving specific key pairs when a participant manages multiple credentials.

### What happens if an attacker modifies the recipient list?
The implementation enforces a strict **Fail-Closed policy**:
* The canonical serialization of both `metadata` and the complete `recipients` list is bound directly into the AES-GCM Additional Authenticated Data (`AAD`) via `build_aad()`.
* If an attacker modifies an `id`, alters an `encrypted_key`, reorders entries, injects a rogue recipient, or drops a participant, the calculated GHASH tag will not match the container's `tag`.
* AES-GCM decryption terminates immediately with an `IntegrityError` before releasing any plaintext.

### What happens if a public key is wrong?
* **Malformed Key:** Keys not conforming to valid 33-byte compressed secp256k1 points (or convertible to them) are rejected prior to encryption with a `ValueError`.
* **Unintended Recipient Key:** The target recipient's private key will fail ECIES ephemeral point multiplication / MAC verification during DEK decapsulation, raising a `ValueError` without attempting payload decryption.

---

## 3. Canonical Hybrid Container (D3 Schema)

In D3, the container structure was updated to canonical JSON serialization with lowercase hexadecimal encoding, conforming strictly to the `aad_builder.py` schema:

```json
{
  "metadata": {
    "version": 1,
    "filename": "document.pdf",
    "aead_algorithm": "AES-256-GCM",
    "key_wrap_algorithm": "ECIES-secp256k1",
    "creation_timestamp": "2026-10-25T20:00:00+00:00"
  },
  "recipients": [
    {
      "id": "alice",
      "key_id": "8a3f... (SHA-256 fingerprint)",
      "encrypted_key": "04a1... (hex-encoded ECIES wrapped DEK)"
    },
    {
      "id": "bob",
      "key_id": "3c9b... (SHA-256 fingerprint)",
      "encrypted_key": "04b2... (hex-encoded ECIES wrapped DEK)"
    }
  ],
  "nonce": "12-byte hex string (24 characters)",
  "ciphertext": "variable-length hex string",
  "tag": "16-byte hex string (32 characters)"
}
