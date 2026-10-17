import pytest
from src.crypto.vault_encryption import SecureVaultEncryption

def test_roundtrip_standard_text():
    """
    Verifies the basic workflow: Encrypting and decrypting standard plaintext
    returns the exact original information identically.
    """
    key = SecureVaultEncryption.generate_key()
    original_data = b"This is a confidential test document for module D2."
    filename = "confidential_contract.txt"

    # 1. Encrypt
    container = SecureVaultEncryption.encrypt_file(original_data, filename, key)
    
    # 2. Decrypt
    decrypted_data = SecureVaultEncryption.decrypt_file(container, key)
    
    # 3. Validate strict identity
    assert original_data == decrypted_data, "The decrypted content does not match the original."


def test_roundtrip_binary_content():
    """
    Verifies that the system correctly handles binary data
    (simulating the upload of a PDF, image, or compiled binary file).
    """
    key = SecureVaultEncryption.generate_key()
    original_data = bytes(range(256)) 
    filename = "binary_file.pdf"

    container = SecureVaultEncryption.encrypt_file(original_data, filename, key)
    decrypted_data = SecureVaultEncryption.decrypt_file(container, key)

    assert original_data == decrypted_data, "Binary integrity failed during roundtrip."


def test_roundtrip_empty_content():
    """
    Edge case: Verifies the behavior when encrypting an empty file (0 bytes).
    """
    key = SecureVaultEncryption.generate_key()
    original_data = b""
    filename = "empty.txt"

    container = SecureVaultEncryption.encrypt_file(original_data, filename, key)
    decrypted_data = SecureVaultEncryption.decrypt_file(container, key)

    assert original_data == decrypted_data