"""Secure Data Vault.

A hybrid-cryptography file vault built around an in-process X.509 PKI. Files
are encrypted with AES-256-CBC; each per-file AES key is wrapped with the
*uploading user's own* RSA public key, so the vault stores data it cannot
read ("zero-knowledge storage"). The vault signs every stored blob with
RSA-PSS to make tampering detectable.

Public API::

    from secure_vault import CryptoUtils, CertificateAuthority, VaultServer, VaultClient
"""
from .crypto_utils import CryptoUtils
from .ca import CertificateAuthority, setup_entities
from .vault_server import VaultServer
from .client_app import VaultClient

__all__ = [
    "CryptoUtils",
    "CertificateAuthority",
    "setup_entities",
    "VaultServer",
    "VaultClient",
]

__version__ = "1.0.0"
