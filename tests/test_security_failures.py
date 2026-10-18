import pytest
import base64
from src.SecureVaultEncryption import SecureVaultEncryption, DecryptionError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

vault = SecureVaultEncryption()

def test_wrong_key_fails():
    """
    Validates that attempting to decrypt the file with an incorrect key 
    fails immediately (ensuring confidentiality and fail-closed).
    """
    data = b"Secret data for wrong key test"
    container, key1 = vault.encrypt(data, filename="secreto.txt")
    key2 = AESGCM.generate_key(bit_length=256)
    
    # Attempt to decrypt using a different key (incorrect key)
    with pytest.raises(DecryptionError):
        vault.decrypt(container, key2)

def test_modified_ciphertext_fails():
    """
    Validates that any alteration in the ciphertext payload body (tampering) 
    is detected by the authentication tag (AEAD).
    """
    container, key = vault.encrypt(b"Protected original text", filename="doc.txt")
    
    # Decode payload from Base64 to raw bytes, modify a byte, and re-encode
    ciphertext_bytes = bytearray(base64.b64decode(container["ciphertext"]))
    ciphertext_bytes[0] ^= 0xFF  # Bit inversion in the actual ciphertext
    container["ciphertext"] = base64.b64encode(ciphertext_bytes).decode('utf-8')
    
    # The system must securely reject the modified container (Fail-Closed)
    with pytest.raises(DecryptionError):
        vault.decrypt(container, key)

def test_modified_metadata_fails():
    """
    Validates that if metadata (AAD - Associated Authenticated Data) is altered, 
    the system detects it and rejects decryption (Header Protection).
    """
    container, key = vault.encrypt(b"Original text", filename="doc.txt")
    
    # Maliciously modify the header metadata (AAD)
    container["header"]["filename"] = "malicious_tampered_file.pdf"
    
    with pytest.raises(DecryptionError):
        vault.decrypt(container, key)


def test_fail_closed_behavior():
    """
    Ensures that upon any integrity or authentication failure, 
    the system never returns partial or unverified data (Fail-Closed).
    """
    container, key = vault.encrypt(b"Confidential test data", filename="vault.dat")
    
    # Corrupt the nonce to force a structural or decryption failure
    nonce_bytes = bytearray(base64.b64decode(container["nonce"]))
    nonce_bytes[0] ^= 0x01
    container["nonce"] = base64.b64encode(nonce_bytes).decode('utf-8')
    
    result = None
    exception_raised = False
    
    try:
        result = vault.decrypt(container, key)
    except DecryptionError:
        exception_raised = True
        
    assert exception_raised is True, "The system must raise an exception on integrity failures."
    assert result is None, "The fail-closed principle forbids returning plaintext if authentication fails."