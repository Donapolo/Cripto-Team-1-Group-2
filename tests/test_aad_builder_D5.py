import pytest
import json
from src.crypto.aad_builder import (
    build_metadata,
    build_recipient_entry,
    build_container,
    signing_payload_from_container,
    validate_container,
    ContainerFormatError
)

# --- Dummy Data for testing ---
# These simulate what Gabriel and the system would generate
DUMMY_SIGNER_ID = "a" * 64 # Simulates a SHA-256 fingerprint
DUMMY_SIGNATURE_BYTES = b"x" * 64 # Simulates a valid size Ed25519 signature
DUMMY_NONCE = b"y" * 12
DUMMY_CIPHERTEXT = b"cipher_text_data"
DUMMY_TAG = b"t" * 16

@pytest.fixture
def base_metadata():
    return build_metadata(filename="documento_secreto.pdf")

@pytest.fixture
def base_recipients():
    return [
        build_recipient_entry("user1", "aa" * 33, "kid1"),
        build_recipient_entry("user2", "bb" * 33, "kid2")
    ]

@pytest.fixture
def valid_container(base_metadata, base_recipients):
    return build_container(
        metadata=base_metadata,
        recipients=base_recipients,
        nonce=DUMMY_NONCE,
        ciphertext=DUMMY_CIPHERTEXT,
        tag=DUMMY_TAG,
        signature=DUMMY_SIGNATURE_BYTES,
        signer_id=DUMMY_SIGNER_ID
    )

# --- D5 TESTS ---

def test_valid_container_builds_successfully(valid_container):
    """Test that a container with a valid signature and signer_id passes validation."""
    assert "signature" in valid_container
    assert "signer_id" in valid_container
    validate_container(valid_container) # Should not raise an error

def test_signing_payload_is_canonical(valid_container):
    """Test that the signed payload is rebuilt exactly the same."""
    payload_bytes = signing_payload_from_container(valid_container)
    
    # Verify it starts with our exclusive domain prefix
    assert payload_bytes.startswith(b"vault-d5-signature/v1\x00")
    
    # Verify the internal JSON is sorted and compact
    json_part = payload_bytes[len(b"vault-d5-signature/v1\x00"):].decode("ascii")
    data = json.loads(json_part)
    
    assert data["signer_id"] == DUMMY_SIGNER_ID
    assert data["nonce"] == DUMMY_NONCE.hex()
    # sort_keys=True guarantees the JSON order does not change
    assert json_part == json.dumps(data, sort_keys=True, separators=(",", ":"))

def test_container_rejects_missing_signature(valid_container):
    """Test E: The container must reject if the signature is removed."""
    # Simulate an attacker deleting the signature from the JSON
    del valid_container["signature"]
    
    with pytest.raises(ContainerFormatError, match="missing fields"):
        validate_container(valid_container)

def test_container_rejects_missing_signer_id(valid_container):
    """Test E extended: The container must reject if the signer_id is removed."""
    del valid_container["signer_id"]
    
    with pytest.raises(ContainerFormatError, match="missing fields"):
        validate_container(valid_container)

def test_payload_changes_if_metadata_is_tampered(valid_container):
    """Test C: If someone modifies the metadata, the signing payload changes (tag and signature would fail)."""
    original_payload = signing_payload_from_container(valid_container)
    
    # Simulate an attacker modifying the metadata
    valid_container["metadata"]["filename"] = "virus.exe"
    
    # The rebuilt payload must be different, so the original signature would no longer validate
    tampered_payload = signing_payload_from_container(valid_container)
    assert original_payload != tampered_payload

def test_payload_changes_if_ciphertext_is_tampered(valid_container):
    """Test B: If someone modifies the ciphertext, the signing payload changes."""
    original_payload = signing_payload_from_container(valid_container)
    
    # Simulate ciphertext modification
    valid_container["ciphertext"] = "00" + valid_container["ciphertext"][2:]
    
    tampered_payload = signing_payload_from_container(valid_container)
    assert original_payload != tampered_payload