"""Command-line entry point for the Secure Data Vault.

Run with::

    python -m secure_vault.cli

On first run it provisions a neutral CA and demo entities (``vault``,
``user1``, ``user2``) under ``$VAULT_HOME`` (default ``./data``), then presents
a menu to start the vault and act as either user. No personal data is
requested or stored.
"""
import os
import shutil

from .ca import CertificateAuthority, setup_entities
from .client_app import interactive_client_session
from .config import (
    get_ca_cert_path,
    get_ca_dir,
    get_user_dir,
    get_vault_dir,
)
from .vault_server import VaultServer


def display_banner():
    """Print the application banner."""
    print(
        """
    +===================================================+
    |              SECURE DATA VAULT                    |
    |   Hybrid AES-256 / RSA-2048 encrypted storage     |
    +===================================================+
    """
    )


def setup_system():
    """Provision the CA and demo entities if they do not already exist."""
    print("\n=== System Setup ===")

    if not os.path.exists(get_ca_cert_path()):
        print("Setting up Certificate Authority...")
        ca = CertificateAuthority()
        print("Setting up entities (Vault, User1, User2)...")
        setup_entities(ca)
        print("\nSetup completed!")
    else:
        print("System already set up. CA and certificates found.")

    return True


def create_sample_files():
    """Create a couple of neutral sample files for demonstration."""
    sample_dir = os.path.join(str(get_vault_dir().parent), "sample_files")
    os.makedirs(sample_dir, exist_ok=True)

    with open(os.path.join(sample_dir, "demo_document.txt"), "w") as f:
        f.write("This is a sample document for the Secure Data Vault demo.\n")
        f.write("It contains no personal data.\n")

    with open(os.path.join(sample_dir, "notes.txt"), "w") as f:
        f.write("Design notes:\n")
        f.write("- AES-256-CBC is used for file encryption.\n")
        f.write("- RSA-2048 (OAEP) wraps the per-file AES key.\n")
        f.write("- SHA-256 is used for integrity verification.\n")

    print(f"Sample files created in '{sample_dir}'")


def main_menu():
    """Print the main menu and return the user's selection."""
    print("\n=== Main Menu ===")
    print("1. Start Vault Server")
    print("2. Connect as User1")
    print("3. Connect as User2")
    print("4. System Status")
    print("5. Initial Setup / Reset")
    print("6. Exit")
    return input("\nSelect option: ").strip()


def main():
    """Run the interactive command-line application."""
    display_banner()

    # Provision the system (neutral identities, no prompts) and sample files.
    setup_system()
    create_sample_files()

    vault = None

    while True:
        choice = main_menu()

        if choice == "1":
            if vault is None:
                print("\nStarting Vault Server...")
                vault = VaultServer()
                vault.start_service()
                print("Vault Server started successfully!")
            else:
                print("Vault Server is already running!")

        elif choice == "2":
            if vault is None:
                print("Error: Please start the Vault Server first!")
            else:
                print("\nConnecting as User1...")
                interactive_client_session("user1", vault)

        elif choice == "3":
            if vault is None:
                print("Error: Please start the Vault Server first!")
            else:
                print("\nConnecting as User2...")
                interactive_client_session("user2", vault)

        elif choice == "4":
            print("\n=== System Status ===")
            if vault:
                status = vault.get_status()
                print(f"Vault Server: {'Running' if status['running'] else 'Stopped'}")
                print(f"Registered Users: {status['registered_users']}")
                print(f"Users: {', '.join(status['users'])}")
            else:
                print("Vault Server: Not started")

            print("\nCertificates:")
            certs = [
                ("CA", str(get_ca_cert_path())),
                ("Vault", os.path.join(str(get_vault_dir()), "vault_cert.pem")),
                ("User1", os.path.join(str(get_user_dir("user1")), "user1_cert.pem")),
                ("User2", os.path.join(str(get_user_dir("user2")), "user2_cert.pem")),
            ]
            for name, path in certs:
                mark = "[OK]" if os.path.exists(path) else "[X]"
                print(f"  {name}: {mark}")

        elif choice == "5":
            confirm = input(
                "\nThis will delete all existing certificates and data. Continue? (yes/no): "
            )
            if confirm.lower() == "yes":
                if vault is not None:
                    vault.stop_service()
                    vault = None
                for directory in [get_ca_dir(), get_vault_dir(), get_user_dir("user1").parent]:
                    if os.path.exists(directory):
                        shutil.rmtree(directory)
                        print(f"Removed {directory}")
                setup_system()

        elif choice == "6":
            print("\nShutting down...")
            if vault:
                vault.stop_service()
            print("Goodbye!")
            break

        else:
            print("Invalid option!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nApplication terminated by user.")
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback

        traceback.print_exc()
