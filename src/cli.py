"""Secure Document Vault: D6 command-line entry point.

Usage: python -m src.cli --help
No passwords or private keys are ever passed through command-line arguments.
"""

import argparse
import getpass
import sys
from pathlib import Path

from src.services.vault_service import VaultService


DEFAULT_DATA_DIR = Path.home() / ".secure-document-vault"


def make_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure Document Vault — D6 CLI")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR,
                        help="Directory for authenticated registry and encrypted keystores")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init-user", help="Generate encrypted secp256k1 / Ed25519 keystores")
    p.add_argument("--user", required=True)
    p.add_argument("--algorithm", choices=["both", "secp256k1", "Ed25519"], default="both")
    p.add_argument("--days", type=int, default=365)

    p = sub.add_parser("list-keys", help="List public identifiers and current states")

    p = sub.add_parser("rotate-key", help="Retire an active key and generate a replacement")
    p.add_argument("--user", required=True)
    p.add_argument("--algorithm", choices=["secp256k1", "Ed25519"], required=True)
    p.add_argument("--days", type=int, default=365)

    p = sub.add_parser("revoke-key", help="Revoke a key (no normal decryption recovery)")
    p.add_argument("--key-id", required=True)
    p.add_argument("--reason", required=True)

    p = sub.add_parser("encrypt", help="Encrypt and sign a document for 2+ recipients")
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--signer", required=True, help="User ID of the registered Ed25519 signer")
    p.add_argument("--recipients", nargs="+", required=True, help="Two or more user IDs")

    p = sub.add_parser("decrypt", help="Verify and decrypt a D5 container")
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--user", required=True, help="Authorized recipient user ID")

    p = sub.add_parser("backup", help="Backup ONE encrypted keystore (not whole registry)")
    p.add_argument("--key-id", required=True)
    p.add_argument("--output", required=True, type=Path)

    p = sub.add_parser("restore", help="Restore ONE registered keystore (no overwrite)")
    p.add_argument("--key-id", required=True)
    p.add_argument("--input", required=True, type=Path)

    return parser


def _new_password() -> str:
    password = getpass.getpass("Nueva contraseña del keystore: ")
    if password != getpass.getpass("Confirma la contraseña: "):
        raise ValueError("Passwords do not match.")
    if not password:
        raise ValueError("Keystore password is required.")
    return password


def _unlock_password(entry: dict) -> str:
    return getpass.getpass(f"Contraseña de {entry['user_id']} ({entry['algorithm']}): ")


def main(argv=None) -> int:
    args = make_parser().parse_args(argv)
    try:
        registry_password = getpass.getpass("Contraseña del registro D6: ")
        if not registry_password:
            raise ValueError("Registry password is required.")
        service = VaultService(args.data_dir, registry_password)

        if args.command == "init-user":
            entries = service.init_user(args.user, _new_password(), algorithm=args.algorithm,
                                        validity_days=args.days)
            for entry in entries:
                print(f"Created {entry['algorithm']} for {entry['user_id']}: {entry['key_id']}")
        elif args.command == "list-keys":
            for entry in service.list_keys():
                print(f"{entry['user_id']}  {entry['algorithm']}  {entry['status']}  {entry['key_id']}")
        elif args.command == "rotate-key":
            entry = service.rotate(args.user, args.algorithm, _new_password(), validity_days=args.days)
            print(f"Rotated {entry['algorithm']} for {entry['user_id']}: {entry['key_id']}")
        elif args.command == "revoke-key":
            entry = service.revoke(args.key_id, args.reason)
            print(f"Revoked {entry['key_id']}")
        elif args.command == "encrypt":
            path = service.encrypt_file(args.input, args.output, args.signer, args.recipients,
                                        _unlock_password)
            print(f"Encrypted and signed: {path}")
        elif args.command == "decrypt":
            path = service.decrypt_file(args.input, args.output, args.user, _unlock_password)
            print(f"Verified and decrypted: {path}")
        elif args.command == "backup":
            service.backup_keystore(args.key_id, args.output)
            print(f"Single-keystore backup created: {args.output}")
        elif args.command == "restore":
            path = service.restore_keystore(args.key_id, args.input)
            print(f"Single keystore restored: {path}")
        return 0
    except (ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except ModuleNotFoundError as exc:
        if exc.name in {"ecies", "coincurve"}:
            print("ERROR: Missing ECIES dependencies; install requirements.txt.", file=sys.stderr)
            return 1
        raise


if __name__ == "__main__":
    raise SystemExit(main())
