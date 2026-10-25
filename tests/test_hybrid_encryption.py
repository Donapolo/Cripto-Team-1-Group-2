import pytest
from src.crypto.key_manager import ECIESKeyManager
from src.crypto.aad_builder import validate_container, ContainerFormatError
from src.crypto.hybrid_vault import HybridVault


@pytest.fixture
def test_recipients():
    """Generates two valid secp256k1 key pairs for recipient testing."""
    user_a = ECIESKeyManager.generate_key_pair()
    user_b = ECIESKeyManager.generate_key_pair()
    return {
        "alice": user_a["public_key"],
        "bob": user_b["public_key"],
    }


def test_encrypt_hybrid_success(test_recipients):
    """Verifies successful hybrid encryption and container schema compliance."""
    data = b"Confidential payload for vault storage"
    filename = "document.pdf"

    container = HybridVault.encrypt_hybrid(data, filename, test_recipients)

    # Validate structural compliance through canonical schema checker
    validate_container(container)

    # Check recipient encapsulation integrity
    assert len(container["recipients"]) == 2
    recipient_ids = {r["id"] for r in container["recipients"]}
    assert recipient_ids == {"alice", "bob"}

    # Ensure key_id and hex-encoded encrypted_key exist
    for r in container["recipients"]:
        assert "key_id" in r
        assert "encrypted_key" in r
        assert len(r["encrypted_key"]) > 0


def test_encrypt_hybrid_enforces_minimum_two_recipients():
    """Ensures encryption fails if fewer than 2 recipients are supplied."""
    user = ECIESKeyManager.generate_key_pair()
    single_recipient = {"alice": user["public_key"]}

    with pytest.raises(ValueError, match="at least 2 distinct authorized recipients"):
        HybridVault.encrypt_hybrid(b"Data", "file.txt", single_recipient)


def test_encrypt_hybrid_accepts_list_format(test_recipients):
    """Validates backward compatibility with recipient list format."""
    recipients_list = [
        {"id": uid, "public_key": pk}
        for uid, pk in test_recipients.items()
    ]
    container = HybridVault.encrypt_hybrid(b"List format test", "list.txt", recipients_list)
    assert validate_container(container) is None