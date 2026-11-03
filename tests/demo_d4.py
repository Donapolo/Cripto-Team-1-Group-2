"""
tests/demo_d4.py
Live Verification Suite for Secure Document Vault (Deliverable D4)
Team: Cripto-Team-1-Group-2
Speaker: Armando Vázquez Apolonio
"""

import copy
import sys
from pathlib import Path

# Garantizar resolución de paquetes desde la raíz del proyecto
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.crypto.key_manager import ECIESKeyManager
from src.crypto.hybrid_vault import encrypt_hybrid, decrypt_hybrid, IntegrityError


# Estilos de formato ANSI para la terminal en vivo
class Term:
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def header(title: str):
    print(f"\n{Term.BOLD}{Term.CYAN}{'=' * 75}")
    print(f" {title.upper()}")
    print(f"{'=' * 75}{Term.RESET}")


def pass_banner(scenario_num: int, name: str, detail: str):
    print(f"  {Term.BOLD}{Term.GREEN}[PASS] Scenario {scenario_num}: {name}{Term.RESET}")
    print(f"         {Term.DIM}-> {detail}{Term.RESET}")


def fail_closed_banner(scenario_num: int, name: str, detail: str):
    print(f"  {Term.BOLD}{Term.RED}[FAIL-CLOSED] Scenario {scenario_num}: {name}{Term.RESET}")
    print(f"         {Term.DIM}-> {detail}{Term.RESET}")


def run_demo():
    header("Secure Document Vault - D4 Live Demonstration Matrix")
    print(f"{Term.DIM}Course: Cryptography (Semestre 2027-1) | Facultad de Ingeniería, UNAM")
    print(f"Executing: tests/demo_d4.py{Term.RESET}\n")

    # -------------------------------------------------------------------------
    # SETUP: Generación de identidades y llaves secp256k1
    # -------------------------------------------------------------------------
    print(f"{Term.BOLD}[00] Initializing Cryptographic Identities & secp256k1 Keypairs...{Term.RESET}")
    alice = ECIESKeyManager.generate_key_pair()
    bob = ECIESKeyManager.generate_key_pair()
    carol = ECIESKeyManager.generate_key_pair()

    print(f"     * Alice (Authorized Emisor)    ID: alice | KeyID: {alice['key_id'][:16]}...")
    print(f"     * Bob   (Authorized Receptor)  ID: bob   | KeyID: {bob['key_id'][:16]}...")
    print(f"     * Carol (Unauthorized Attacker) ID: carol | KeyID: {carol['key_id'][:16]}...\n")

    # Archivo simulado (PDF confidencial en memoria)
    # Cargar un archivo PDF real desde demo_files
    pdf_path = PROJECT_ROOT / "demo_files" / "confidencial.pdf"

    if not pdf_path.is_file():
        raise FileNotFoundError(
            f"No se encontró el archivo PDF: {pdf_path}"
        )

    filename = pdf_path.name
    plaintext_payload = pdf_path.read_bytes()

    print(f"     [+] PDF loaded: {filename}")
    print(f"     [+] Original file size: {len(plaintext_payload)} bytes\n")
 
 

    recipients_map = {
        "alice": alice["public_key"],
        "bob": bob["public_key"],
    }

    print(f"{Term.YELLOW}>> Alice performs Hybrid Encryption targeting ['alice', 'bob']...{Term.RESET}")
    container = encrypt_hybrid(
        file_bytes=plaintext_payload,
        filename=filename,
        recipients=recipients_map,
    )
    print(f"   [+] Canonical JSON Container constructed:")
    print(f"       - Algorithm: {container['metadata']['aead_algorithm']} + {container['metadata']['key_wrap_algorithm']}")
    print(f"       - Nonce:     {container['nonce']}")
    print(f"       - Tag:       {container['tag']}")
    print(f"       - Payload:   {len(container['ciphertext'])} hex characters")
    print(f"       - Recipient entries: {len(container['recipients'])}\n")

    # -------------------------------------------------------------------------
    # SCENARIO 1: Valid Encryption & Decryption (Alice)
    # -------------------------------------------------------------------------
    print(f"{Term.BOLD}[SCENARIO 01] Valid Encryption & Decryption Verification{Term.RESET}")
    recovered_alice = decrypt_hybrid(
        container=container,
        user_id="alice",
        private_key=alice["private_key"],
    )
    assert recovered_alice == plaintext_payload, "Plaintext mismatch for Alice!"
    # Guardar el PDF recuperado
    output_dir = PROJECT_ROOT / "demo_output"
    output_dir.mkdir(exist_ok=True)

    output_file = output_dir / "recuperado_alice.pdf"
    output_file.write_bytes(recovered_alice)

    print(f"     [+] Recovered PDF saved: {output_file}")
    pass_banner(
        1,
        "Valid Encryption & Decryption",
        f"Alice successfully decrypted payload with 100% bit-level fidelity ({len(recovered_alice)} bytes restored).",
    )
    print()

    # -------------------------------------------------------------------------
    # SCENARIO 2: Multi-Recipient Sharing (Bob)
    # -------------------------------------------------------------------------
    print(f"{Term.BOLD}[SCENARIO 02] Multi-Recipient Key Decapsulation{Term.RESET}")
    recovered_bob = decrypt_hybrid(
        container=container,
        user_id="bob",
        private_key=bob["private_key"],
    )
    assert recovered_bob == plaintext_payload, "Plaintext mismatch for Bob!"
    pass_banner(
        2,
        "Multi-Recipient Sharing",
        "Bob decrypted the EXACT same container using his independent secp256k1 key without payload re-encryption.",
    )
    print()

    # -------------------------------------------------------------------------
    # SCENARIO 3: Non-Recipient Rejection (Carol)
    # -------------------------------------------------------------------------
    print(f"{Term.BOLD}[SCENARIO 03] Non-Recipient Access Rejection{Term.RESET}")
    try:
        decrypt_hybrid(
            container=container,
            user_id="carol",
            private_key=carol["private_key"],
        )
        print(f"  {Term.RED}[FAILED] Carol gained unauthorized access!{Term.RESET}")
        sys.exit(1)
    except ValueError as e:
        fail_closed_banner(
            3,
            "Non-Recipient Rejection",
            f"Carol was immediately rejected: '{e}'",
        )
    print()

    # -------------------------------------------------------------------------
    # SCENARIO 4: Tampering & Fail-Closed Enforcement
    # -------------------------------------------------------------------------
    print(f"{Term.BOLD}[SCENARIO 04] Tampering & Fail-Closed Enforcement{Term.RESET}")

    # 4A: Manipulación del texto cifrado (Active MITM)
    tampered_ciphertext_container = copy.deepcopy(container)
    raw_ct = list(tampered_ciphertext_container["ciphertext"])
    raw_ct[0] = "0" if raw_ct[0] != "0" else "1"  # Inversión de 1 nibble
    tampered_ciphertext_container["ciphertext"] = "".join(raw_ct)

    try:
        decrypt_hybrid(
            container=tampered_ciphertext_container,
            user_id="bob",
            private_key=bob["private_key"],
        )
        print(f"  {Term.RED}[FAILED] Tampered ciphertext was decrypted!{Term.RESET}")
        sys.exit(1)
    except IntegrityError as e:
        fail_closed_banner(
            4,
            "Tampered Ciphertext Detected",
            f"AES-GCM GHASH mismatch triggered: '{e}' -> Zero plaintext leaked.",
        )

    # 4B: Manipulación de la tabla de destinatarios / AAD
    tampered_recipient_container = copy.deepcopy(container)
    tampered_recipient_container["recipients"][1]["id"] = "mallory"  # Suplantación de Bob

    try:
        decrypt_hybrid(
            container=tampered_recipient_container,
            user_id="mallory",
            private_key=bob["private_key"],
        )
        print(f"  {Term.RED}[FAILED] Modified recipient list bypassed verification!{Term.RESET}")
        sys.exit(1)
    except (IntegrityError, ValueError) as e:
        fail_closed_banner(
            4,
            "Tampered Recipient / AAD Table Detected",
            f"Reconstructed canonical AAD validation rejected alteration: '{e}'.",
        )

    # -------------------------------------------------------------------------
    # SUMMARY
    # -------------------------------------------------------------------------
    print(f"\n{Term.BOLD}{Term.GREEN}{'=' * 75}")
    print(" ALL 4 DEMONSTRATION SCENARIOS VERIFIED: SYSTEM STATUS 100% OPERATIONAL")
    print(f"{'=' * 75}{Term.RESET}\n")


if __name__ == "__main__":
    run_demo()