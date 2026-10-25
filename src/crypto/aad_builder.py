"""
Canonical AAD builder for hybrid encryption containers.

NOTE: Provisional implementation created to unblock the decryption module. The public interface
(build_aad) is designed to remain stable so that the encryption and
decryption sides reconstruct byte-identical AAD.

"""

import json

AAD_VERSION = 1


def build_aad(metadata: dict, recipients: list) -> bytes:
    """
    Build canonical AAD bytes from container metadata and recipient entries.

    The AAD commits to:
      - The AAD schema version.
      - The filename from metadata.
      - Every recipient's id AND encrypted_key, sorted by id.

    Committing to encrypted_key ensures that swapping a recipient's wrapped
    DEK (without changing ids) is detected by AES-GCM authentication.
    """
    filename = metadata.get("filename", "unknown")
    sorted_recipients = sorted(
        ({"id": r["id"], "encrypted_key": r["encrypted_key"]} for r in recipients),
        key=lambda r: r["id"],
    )

    payload = {
        "v": AAD_VERSION,
        "filename": filename,
        "recipients": sorted_recipients,
    }

    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
