"""The Secure Data Vault client.

A client owns a user's certificate and private key. On upload it encrypts the
file with a fresh AES key and wraps that key with *its own* public key, so the
vault stores something only this user can later decrypt. On download it unwraps
the AES key with its private key and decrypts the file.
"""
import os

from .config import get_user_dir
from .crypto_utils import CryptoUtils


class VaultClient:
    """Client-side encryption/decryption and vault interaction for one user."""

    def __init__(self, username, user_dir=None):
        self.username = username

        # Resolve the user's key material location.
        if user_dir is None:
            user_dir = str(get_user_dir(username))
        self.user_dir = str(user_dir)
        self.cert_path = os.path.join(self.user_dir, f"{username}_cert.pem")
        self.key_path = os.path.join(self.user_dir, f"{username}_key.pem")

        # Load the user's certificate and private key.
        if os.path.exists(self.cert_path) and os.path.exists(self.key_path):
            self.user_cert = CryptoUtils.load_certificate(self.cert_path)
            self.user_key = CryptoUtils.load_private_key(self.key_path)
            print(f"Client initialized for user: {username}")
        else:
            raise FileNotFoundError(f"Certificate or key not found for user {username}")

    def register_with_vault(self, vault):
        """Register this client's certificate with the vault."""
        success, message = vault.register_user(self.username, self.user_cert)
        print(f"Registration: {message}")
        return success

    def store_file(self, vault, filepath):
        """Encrypt a local file and store it in the vault.

        The AES key is wrapped with this user's own public key, so the vault
        cannot read the file it stores.
        """
        if not os.path.exists(filepath):
            print(f"Error: File '{filepath}' not found")
            return False

        try:
            # Generate a per-file AES key.
            aes_key = CryptoUtils.generate_aes_key()

            # Encrypt the file contents with AES.
            encrypted_file_data = CryptoUtils.encrypt_file_symmetric(filepath, aes_key)

            # Wrap the AES key with this user's public key (zero-knowledge storage).
            user_public_key = self.user_cert.public_key()
            encrypted_key = CryptoUtils.encrypt_asymmetric(aes_key, user_public_key)

            # Hand the ciphertext and wrapped key to the vault.
            filename = os.path.basename(filepath)
            success, file_id = vault.store_file(
                self.username, filename, encrypted_file_data, encrypted_key
            )

            if success:
                print(f"File stored successfully with ID: {file_id}")
                # Keep a small local reference note.
                self._save_file_info(file_id, filename, filepath)
            else:
                print(f"Failed to store file: {file_id}")

            return success

        except Exception as e:
            print(f"Error storing file: {str(e)}")
            return False

    def retrieve_file(self, vault, file_id, output_path=None):
        """Retrieve and decrypt a file from the vault.

        If the vault reports an integrity failure the method still attempts to
        decrypt (mirroring the original project) -- this "force decrypt" is
        noted as a limitation in the threat model.
        """
        try:
            # Retrieve the (verified) blob and wrapped key from the vault.
            success, message, encrypted_file_data, encrypted_key = vault.retrieve_file(
                self.username, file_id
            )

            if not success:
                print(f"Retrieval failed: {message}")
                if encrypted_file_data is None:
                    return False

                # Integrity check failed; the original design still tries to decrypt.
                print("WARNING: Proceeding with decryption despite integrity failure")

            # Unwrap the AES key with this user's private key.
            aes_key = CryptoUtils.decrypt_asymmetric(encrypted_key, self.user_key)

            # Decrypt the file contents.
            decrypted_data = CryptoUtils.decrypt_file_symmetric(encrypted_file_data, aes_key)

            # Save to disk, or print if it looks like text.
            if output_path:
                with open(output_path, "wb") as f:
                    f.write(decrypted_data)
                print(f"File decrypted and saved to: {output_path}")
            else:
                try:
                    content = decrypted_data.decode("utf-8")
                    print("\n--- File Content ---")
                    print(content)
                    print("--- End of File ---\n")
                except UnicodeDecodeError:
                    print("File appears to be binary. Specify output path to save.")

            return True

        except Exception as e:
            print(f"Error retrieving file: {str(e)}")
            return False

    def list_files(self, vault):
        """Print all files this user has stored in the vault."""
        files = vault.list_user_files(self.username)

        if not files:
            print("No files stored in vault")
            return

        print(f"\nFiles for user '{self.username}':")
        print("-" * 70)
        print(f"{'File ID':<20} {'Original Name':<30} {'Stored At':<20}")
        print("-" * 70)

        for file_info in files:
            print(
                f"{file_info['file_id']:<20} {file_info['original_filename']:<30} "
                f"{file_info['stored_at'][:19]}"
            )
        print("-" * 70)

    def verify_file_integrity(self, vault, file_id):
        """Ask the vault to verify a stored file's integrity and report."""
        success, message, _, _ = vault.retrieve_file(self.username, file_id)

        if success:
            print(f"File '{file_id}' integrity: VERIFIED [OK]")
        else:
            print(f"File '{file_id}' integrity: FAILED [X] - {message}")

        return success

    def _save_file_info(self, file_id, filename, original_path):
        """Write a small local reference note for a stored file."""
        info_dir = os.path.join(self.user_dir, "file_info")
        os.makedirs(info_dir, exist_ok=True)

        info_file = os.path.join(info_dir, f"{file_id}.txt")
        with open(info_file, "w") as f:
            f.write(f"File ID: {file_id}\n")
            f.write(f"Original filename: {filename}\n")
            f.write(f"Original path: {original_path}\n")


def interactive_client_session(username, vault):
    """Run a simple text menu for one user against a running vault."""
    try:
        client = VaultClient(username)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        return

    # Register with the vault on first use.
    if username not in vault.users:
        if not client.register_with_vault(vault):
            print("Failed to register with vault")
            return

    while True:
        print(f"\n=== Vault Client ({username}) ===")
        print("1. Store file")
        print("2. Retrieve file")
        print("3. List files")
        print("4. Verify file integrity")
        print("5. Exit")

        choice = input("\nSelect option: ").strip()

        if choice == "1":
            filepath = input("Enter file path to store: ").strip()
            client.store_file(vault, filepath)

        elif choice == "2":
            file_id = input("Enter file ID to retrieve: ").strip()
            save_option = input("Save to file? (y/n): ").strip().lower()
            if save_option == "y":
                output_path = input("Enter output path: ").strip()
                client.retrieve_file(vault, file_id, output_path)
            else:
                client.retrieve_file(vault, file_id)

        elif choice == "3":
            client.list_files(vault)

        elif choice == "4":
            file_id = input("Enter file ID to verify: ").strip()
            client.verify_file_integrity(vault, file_id)

        elif choice == "5":
            print("Exiting...")
            break

        else:
            print("Invalid option")


if __name__ == "__main__":
    print("Client module loaded. Use 'python -m secure_vault.cli' to run the full system.")
