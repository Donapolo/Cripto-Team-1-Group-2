import pytest
from src.crypto.vault_encryption import SecureVaultEncryption

def test_encrypt_decrypt_roundtrip():
    """Demuestra que Encrypt -> Decrypt devuelve el archivo idéntico."""
    key = SecureVaultEncryption.generate_key()
    original_data = b"Contenido confidencial del documento para las pruebas de D2."
    filename = "documento_prueba.pdf"
    
    container = SecureVaultEncryption.encrypt_file(original_data, filename, key)
    decrypted_data = SecureVaultEncryption.decrypt_file(container, key)
    
    assert original_data == decrypted_data

def test_wrong_key_fails():
    """Demuestra que intentar descifrar con una clave incorrecta falla (Fail-Closed)."""
    key1 = SecureVaultEncryption.generate_key()
    key2 = SecureVaultEncryption.generate_key()
    data = b"Datos secretos"
    
    container = SecureVaultEncryption.encrypt_file(data, "secreto.txt", key1)
    
    with pytest.raises(RuntimeError, match="Integrity check failed"):
        SecureVaultEncryption.decrypt_file(container, key2)

def test_modified_ciphertext_fails():
    """Demuestra que alterar el contenido cifrado es detectado inmediatamente."""
    key = SecureVaultEncryption.generate_key()
    container = SecureVaultEncryption.encrypt_file(b"Texto original", "doc.txt", key)
    
    # Manipular el payload cifrado (modificando un carácter en Base64)
    payload_bytes = bytearray(container["payload"], 'utf-8')
    payload_bytes[5] = ord('A') if payload_bytes[5] != ord('A') else ord('B')
    container["payload"] = payload_bytes.decode('utf-8')
    
    with pytest.raises(RuntimeError, match="Integrity check failed"):
        SecureVaultEncryption.decrypt_file(container, key)

def test_modified_metadata_fails():
    """Demuestra que alterar los metadatos (AAD) es detectado (protección de metadatos)."""
    key = SecureVaultEncryption.generate_key()
    container = SecureVaultEncryption.encrypt_file(b"Texto original", "doc.txt", key)
    
    # Intentar alterar el nombre del archivo en los metadatos sin recalcular el tag
    container["header"]["filename"] = "nombre_malicioso.pdf"
    
    with pytest.raises(RuntimeError, match="Integrity check failed"):
        SecureVaultEncryption.decrypt_file(container, key)

def test_multiple_encryptions_produce_unique_ciphertexts():
    """Demuestra que cifrar el mismo contenido dos veces genera nonces y ciphertexts distintos."""
    key = SecureVaultEncryption.generate_key()
    data = b"Mismo contenido"
    
    c1 = SecureVaultEncryption.encrypt_file(data, "doc.txt", key)
    c2 = SecureVaultEncryption.encrypt_file(data, "doc.txt", key)
    
    assert c1["nonce"] != c2["nonce"]
    assert c1["payload"] != c2["payload"]