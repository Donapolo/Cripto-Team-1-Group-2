import pytest
from src.SecureVaultEncryption import SecureVaultEncryption

vault = SecureVaultEncryption()

def test_roundtrip_standard_text():
    """
    Verifies the basic workflow: Encrypting and decrypting standard plaintext
    returns the exact original information identically.
    """
    original_data = b"This is a confidential test document for module D2."
    filename = "confidential_contract.txt"

    # 1. Encrypt
    container, key = vault.encrypt(original_data, filename=filename)
    
    # 2. Decrypt
    decrypted_data = vault.decrypt(container, key)
    
    # 3. Validate strict identity
    assert original_data == decrypted_data, "The decrypted content does not match the original."


def test_roundtrip_binary_content():
    """
    Verifies that the system correctly handles binary data
    (simulating the upload of a PDF, image, or compiled binary file).
    """
    original_data = bytes(range(256)) 
    filename = "binary_file.pdf"

    container, key = vault.encrypt(original_data, filename=filename)
    decrypted_data = vault.decrypt(container, key)

    assert original_data == decrypted_data, "Binary integrity failed during roundtrip."


def test_roundtrip_empty_content():
    """
    Edge case: Verifies the behavior when encrypting an empty file (0 bytes).
    """
    original_data = b""
    filename = "empty.txt"

    container, key = vault.encrypt(original_data, filename=filename)
    decrypted_data = vault.decrypt(container, key)

    assert original_data == decrypted_data