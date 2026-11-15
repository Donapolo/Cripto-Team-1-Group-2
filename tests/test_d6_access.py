import pytest
import getpass
from src.crypto.key_manager import ECIESKeyManager
from src.crypto.hybrid_vault import encrypt_hybrid, decrypt_hybrid_with_keystore, IntegrityError
from src.crypto.signature_manager import generate_key_pair as generate_signing_key_pair

@pytest.fixture
def setup_d6_environment(tmp_path):
    # Generate keys for recipient (Alice) and sender
    alice = ECIESKeyManager.generate_key_pair()
    bob = ECIESKeyManager.generate_key_pair()
    sender = generate_signing_key_pair()
    
    trusted_signers = {sender["signer_id"]: sender["public_key"]}
    recipients = {"alice": alice["public_key"], "bob": bob["public_key"]}
    
    # Save Alice's private key to a D6 Keystore
    keystore_file = tmp_path / "alice_keystore.json"
    ECIESKeyManager.save_key_to_keystore(
        key_pair=alice,
        password="SuperSecretPassword123!",
        keystore_path=str(keystore_file)
    )
    
    # Create a document
    payload = b"Contrato Confidencial D6"
    container = encrypt_hybrid(
        file_bytes=payload,
        filename="d6_contract.pdf",
        recipients=recipients,
        signing_private_key=sender["private_key"]
    )
    
    return {
        "container": container,
        "alice": alice,
        "keystore_path": str(keystore_file),
        "trusted_signers": trusted_signers,
        "payload": payload
    }

def test_d6_correct_password_grants_access(setup_d6_environment, monkeypatch):
    env = setup_d6_environment
    
    # Mock getpass to simulate user entering the correct password
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "SuperSecretPassword123!")
    
    # Should decrypt successfully
    result = decrypt_hybrid_with_keystore(
        container=env["container"],
        user_id="alice",
        keystore_path=env["keystore_path"],
        trusted_signers=env["trusted_signers"],
        expected_key_id=env["alice"]["key_id"]
    )
    assert result == env["payload"]

def test_d6_incorrect_password_denies_access(setup_d6_environment, monkeypatch):
    env = setup_d6_environment
    
    # Mock getpass to simulate user entering the WRONG password
    monkeypatch.setattr(getpass, "getpass", lambda prompt: "WrongPassword")
    
    # Should fail with ValueError (Access Denied)
    with pytest.raises(ValueError, match="Access Denied"):
        decrypt_hybrid_with_keystore(
            container=env["container"],
            user_id="alice",
            keystore_path=env["keystore_path"],
            trusted_signers=env["trusted_signers"]
        )