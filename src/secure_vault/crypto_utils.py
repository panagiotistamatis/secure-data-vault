"""Low-level cryptographic primitives for the Secure Data Vault.

This module intentionally wraps :mod:`cryptography` with a small, explicit
API so the rest of the project reads at the level of "encrypt this file",
"wrap this key", "sign this blob". The primitives are:

* **AES-256-CBC** for bulk file encryption, with a random 16-byte IV and
  PKCS#7 padding. The output is ``IV || ciphertext``.
* **RSA-2048 / OAEP (MGF1+SHA-256)** for wrapping the per-file AES key.
* **RSA-PSS (MGF1+SHA-256, salt = MAX_LENGTH)** for signatures.
* **SHA-256** for hashing.

The padding here is hand-rolled PKCS#7 to mirror the original university
project; a production system would prefer an authenticated cipher such as
AES-GCM (see ``docs/threat-model.md``).
"""
import hashlib
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class CryptoUtils:
    """Stateless helpers for the vault's cryptographic operations."""

    @staticmethod
    def generate_rsa_keypair(key_size=2048):
        """Generate an RSA key pair and return ``(private_key, public_key)``."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend(),
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def save_private_key(private_key, filepath, password=None):
        """Serialize a private key to a PEM file (PKCS#8).

        .. warning::
            With the default ``password=None`` the key is written with
            ``NoEncryption`` -- i.e. unprotected on disk. This mirrors the
            original project and is called out as a known limitation in the
            threat model. Passing a password uses ``BestAvailableEncryption``.
        """
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password.encode())

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption,
        )

        with open(filepath, "wb") as f:
            f.write(pem)

    @staticmethod
    def load_private_key(filepath, password=None):
        """Load a private key from a PEM file."""
        with open(filepath, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=password.encode() if password else None,
                backend=default_backend(),
            )
        return private_key

    @staticmethod
    def save_certificate(cert, filepath):
        """Serialize an X.509 certificate to a PEM file."""
        with open(filepath, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

    @staticmethod
    def load_certificate(filepath):
        """Load an X.509 certificate from a PEM file."""
        with open(filepath, "rb") as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert

    @staticmethod
    def generate_aes_key(key_size=256):
        """Generate a random AES key of ``key_size`` bits (default 256)."""
        return os.urandom(key_size // 8)

    @staticmethod
    def encrypt_file_symmetric(filepath, aes_key):
        """Encrypt a file with AES-CBC and return ``IV || ciphertext``.

        A fresh random 16-byte IV is generated per call and PKCS#7 padding is
        applied before encryption.
        """
        # Generate a random IV.
        iv = os.urandom(16)

        # Read the plaintext file.
        with open(filepath, "rb") as f:
            plaintext = f.read()

        # Apply PKCS#7 padding to a multiple of the 16-byte block size.
        pad_len = 16 - (len(plaintext) % 16)
        plaintext += bytes([pad_len]) * pad_len

        # Encrypt.
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        # Prepend the IV so decryption is self-contained.
        return iv + ciphertext

    @staticmethod
    def encrypt_bytes_symmetric(plaintext, aes_key):
        """Encrypt an in-memory ``bytes`` value with AES-CBC.

        Identical scheme to :meth:`encrypt_file_symmetric` (random IV, PKCS#7
        padding, output ``IV || ciphertext``) but operating on bytes rather
        than a file path. Convenient for tests and callers holding data in
        memory.
        """
        iv = os.urandom(16)
        pad_len = 16 - (len(plaintext) % 16)
        plaintext = plaintext + bytes([pad_len]) * pad_len

        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return iv + ciphertext

    @staticmethod
    def decrypt_file_symmetric(encrypted_data, aes_key):
        """Decrypt ``IV || ciphertext`` produced by the encrypt helpers."""
        # Split the leading IV from the ciphertext.
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]

        # Decrypt.
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend(),
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Strip PKCS#7 padding.
        pad_len = plaintext[-1]
        plaintext = plaintext[:-pad_len]

        return plaintext

    @staticmethod
    def encrypt_asymmetric(data, public_key):
        """RSA-OAEP encrypt (wrap) a small blob with a public key."""
        encrypted = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return encrypted

    @staticmethod
    def decrypt_asymmetric(encrypted_data, private_key):
        """RSA-OAEP decrypt (unwrap) a blob with a private key."""
        decrypted = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted

    @staticmethod
    def sign_data(data, private_key):
        """Produce an RSA-PSS (MGF1+SHA-256, max salt) signature over ``data``."""
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return signature

    @staticmethod
    def verify_signature(data, signature, public_key):
        """Verify an RSA-PSS signature; return ``True`` on success, else ``False``."""
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def calculate_hash(data):
        """Return the hex-encoded SHA-256 digest of ``data``."""
        return hashlib.sha256(data).hexdigest()
