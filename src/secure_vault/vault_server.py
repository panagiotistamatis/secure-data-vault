"""The Secure Data Vault server.

The "server" is an in-process component (no networking) that stores encrypted
blobs on behalf of registered users. For every stored file it keeps four
artifacts:

* ``<id>.enc``  -- ``IV || ciphertext`` (AES-256-CBC encrypted file)
* ``<id>.key``  -- the per-file AES key, RSA-OAEP wrapped with the *uploading
  user's own* public key (so the vault cannot decrypt the file)
* ``<id>.sig``  -- the vault's RSA-PSS signature over the SHA-256 of the blob
* ``<id>.meta`` -- JSON metadata (original filename, timestamp, hash, size)

The vault's own key pair is used only to sign stored blobs, giving
tamper-evidence that a client can check on retrieval.
"""
import json
import os
import threading
import time
from datetime import datetime

from .config import get_ca_cert_path, get_vault_dir
from .crypto_utils import CryptoUtils


class VaultServer:
    """Stores and serves encrypted user files with integrity protection."""

    def __init__(self, vault_dir=None, ca_cert_path=None):
        self.vault_dir = str(vault_dir) if vault_dir is not None else str(get_vault_dir())
        self.storage_dir = os.path.join(self.vault_dir, "storage")
        self.cert_path = os.path.join(self.vault_dir, "vault_cert.pem")
        self.key_path = os.path.join(self.vault_dir, "vault_key.pem")
        self.ca_cert_path = str(ca_cert_path) if ca_cert_path is not None else str(get_ca_cert_path())

        # Ensure the storage directory exists.
        os.makedirs(self.storage_dir, exist_ok=True)

        # Load the vault's own certificate/key and the CA certificate.
        self.vault_cert = CryptoUtils.load_certificate(self.cert_path)
        self.vault_key = CryptoUtils.load_private_key(self.key_path)
        self.ca_cert = CryptoUtils.load_certificate(self.ca_cert_path)

        # Registry of known users.
        self.users = self.load_users()

        # Background service state.
        self.running = False
        self.thread = None

        print(f"Vault server initialized. Storage directory: {self.storage_dir}")

    def load_users(self):
        """Load the registered-user registry from ``users.json``."""
        users_file = os.path.join(self.vault_dir, "users.json")
        if os.path.exists(users_file):
            with open(users_file, "r") as f:
                return json.load(f)
        return {}

    def save_users(self):
        """Persist the registered-user registry to ``users.json``."""
        users_file = os.path.join(self.vault_dir, "users.json")
        with open(users_file, "w") as f:
            json.dump(self.users, f, indent=2)

    def register_user(self, username, user_cert):
        """Register a user by their certificate; returns ``(success, message)``."""
        if username in self.users:
            return False, "User already exists"

        # Create the user's storage subdirectory.
        user_dir = os.path.join(self.storage_dir, username)
        os.makedirs(user_dir, exist_ok=True)

        # Record identifying information from the certificate.
        self.users[username] = {
            "registered_at": datetime.now().isoformat(),
            "cert_subject": str(user_cert.subject),
            "cert_serial": str(user_cert.serial_number),
        }
        self.save_users()

        print(f"User '{username}' registered successfully")
        return True, "User registered successfully"

    def store_file(self, username, filename, encrypted_file_data, encrypted_key):
        """Store an encrypted file plus its wrapped key, signature and metadata.

        The vault never sees plaintext: it receives already-encrypted data and
        an already-wrapped key. It adds its own RSA-PSS signature over the blob
        hash for tamper-evidence. Returns ``(success, file_id_or_message)``.
        """
        if username not in self.users:
            return False, "User not registered"

        user_dir = os.path.join(self.storage_dir, username)

        # Derive a unique file identifier.
        file_id = f"{filename}_{int(time.time())}"

        # Persist the encrypted file.
        file_path = os.path.join(user_dir, f"{file_id}.enc")
        with open(file_path, "wb") as f:
            f.write(encrypted_file_data)

        # Persist the wrapped AES key.
        key_path = os.path.join(user_dir, f"{file_id}.key")
        with open(key_path, "wb") as f:
            f.write(encrypted_key)

        # Sign the SHA-256 of the ciphertext for integrity.
        file_hash = CryptoUtils.calculate_hash(encrypted_file_data)
        signature = CryptoUtils.sign_data(file_hash.encode(), self.vault_key)

        # Persist the signature.
        sig_path = os.path.join(user_dir, f"{file_id}.sig")
        with open(sig_path, "wb") as f:
            f.write(signature)

        # Persist metadata.
        metadata = {
            "original_filename": filename,
            "stored_at": datetime.now().isoformat(),
            "file_hash": file_hash,
            "file_size": len(encrypted_file_data),
        }
        meta_path = os.path.join(user_dir, f"{file_id}.meta")
        with open(meta_path, "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"File '{filename}' stored for user '{username}' with ID '{file_id}'")
        return True, file_id

    def retrieve_file(self, username, file_id):
        """Return a stored blob and its wrapped key after verifying integrity.

        Returns ``(success, message, encrypted_file_data, encrypted_key)``. On
        an integrity failure ``success`` is ``False`` but the (suspect) data is
        still returned so the caller can decide what to do.
        """
        if username not in self.users:
            return False, "User not registered", None, None

        user_dir = os.path.join(self.storage_dir, username)

        # Resolve the four artifact paths.
        file_path = os.path.join(user_dir, f"{file_id}.enc")
        key_path = os.path.join(user_dir, f"{file_id}.key")
        sig_path = os.path.join(user_dir, f"{file_id}.sig")
        meta_path = os.path.join(user_dir, f"{file_id}.meta")

        if not all(os.path.exists(p) for p in [file_path, key_path, sig_path, meta_path]):
            return False, "File not found", None, None

        # Load all artifacts.
        with open(file_path, "rb") as f:
            encrypted_file_data = f.read()
        with open(key_path, "rb") as f:
            encrypted_key = f.read()
        with open(sig_path, "rb") as f:
            signature = f.read()
        with open(meta_path, "r") as f:
            metadata = json.load(f)

        # Verify the vault's signature and the recorded hash.
        current_hash = CryptoUtils.calculate_hash(encrypted_file_data)
        vault_public_key = self.vault_cert.public_key()

        if CryptoUtils.verify_signature(current_hash.encode(), signature, vault_public_key):
            if current_hash == metadata["file_hash"]:
                print(f"File '{file_id}' retrieved successfully with integrity verified")
                return True, "File retrieved successfully", encrypted_file_data, encrypted_key
            else:
                print(f"WARNING: File hash mismatch for '{file_id}'")
                return (
                    False,
                    "File integrity check failed - hash mismatch",
                    encrypted_file_data,
                    encrypted_key,
                )
        else:
            print(f"WARNING: Invalid signature for file '{file_id}'")
            return (
                False,
                "File integrity check failed - invalid signature",
                encrypted_file_data,
                encrypted_key,
            )

    def list_user_files(self, username):
        """Return a list of metadata dicts for every file a user has stored."""
        if username not in self.users:
            return []

        user_dir = os.path.join(self.storage_dir, username)
        files = []

        for filename in os.listdir(user_dir):
            if filename.endswith(".meta"):
                file_id = filename[:-5]  # Strip the '.meta' suffix.
                meta_path = os.path.join(user_dir, filename)
                with open(meta_path, "r") as f:
                    metadata = json.load(f)
                files.append(
                    {
                        "file_id": file_id,
                        "original_filename": metadata["original_filename"],
                        "stored_at": metadata["stored_at"],
                        "file_size": metadata["file_size"],
                    }
                )

        return files

    def start_service(self):
        """Start the background service thread."""
        self.running = True
        self.thread = threading.Thread(target=self._service_loop)
        self.thread.start()
        print("Vault service started")

    def stop_service(self):
        """Stop the background service thread and join it."""
        self.running = False
        if self.thread:
            self.thread.join()
        print("Vault service stopped")

    def _service_loop(self):
        """Keep-alive loop for the in-process service.

        A networked implementation would listen for requests here; this project
        simply keeps the service thread alive.
        """
        while self.running:
            time.sleep(1)

    def get_status(self):
        """Return a snapshot of the vault's runtime status."""
        return {
            "running": self.running,
            "registered_users": len(self.users),
            "users": list(self.users.keys()),
            "storage_directory": self.storage_dir,
        }


if __name__ == "__main__":
    # Manual smoke test of the vault server.
    vault = VaultServer()
    vault.start_service()

    print("Vault Status:", vault.get_status())

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        vault.stop_service()
