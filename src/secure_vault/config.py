"""Central path and identity configuration for the Secure Data Vault.

Every on-disk artifact (the CA, the vault, per-user key material and the
encrypted storage) lives under a single, deterministically resolved base
directory so the application no longer depends on the current working
directory.

The base directory is resolved from the ``VAULT_HOME`` environment variable
and defaults to ``./data``. The on-disk layout underneath it is unchanged
from the original project::

    <VAULT_HOME>/
    |-- ca/
    |   |-- ca_cert.pem
    |   |-- ca_key.pem
    |   `-- certs/
    |-- vault/
    |   |-- vault_cert.pem
    |   |-- vault_key.pem
    |   |-- users.json
    |   `-- storage/
    `-- users/
        |-- user1/
        `-- user2/

Identity fields used in issued certificates are also parameterisable (via
environment variables) and default to neutral, non-personal values.
"""
from __future__ import annotations

import os
from pathlib import Path

#: Environment variable that overrides the base directory.
VAULT_HOME_ENV = "VAULT_HOME"

#: Default base directory (relative to the process, resolved to absolute).
DEFAULT_VAULT_HOME = "data"


def get_vault_home() -> Path:
    """Return the absolute base directory for all vault data.

    Controlled by the ``VAULT_HOME`` environment variable; defaults to
    ``./data`` resolved to an absolute path.
    """
    return Path(os.environ.get(VAULT_HOME_ENV, DEFAULT_VAULT_HOME)).resolve()


def get_ca_dir() -> Path:
    """Return the Certificate Authority directory (``<VAULT_HOME>/ca``)."""
    return get_vault_home() / "ca"


def get_vault_dir() -> Path:
    """Return the vault server directory (``<VAULT_HOME>/vault``)."""
    return get_vault_home() / "vault"


def get_users_dir() -> Path:
    """Return the parent directory for user key material (``<VAULT_HOME>/users``)."""
    return get_vault_home() / "users"


def get_user_dir(username: str) -> Path:
    """Return the directory holding a single user's certificate and key."""
    return get_users_dir() / username


def get_ca_cert_path() -> Path:
    """Return the path to the CA certificate."""
    return get_ca_dir() / "ca_cert.pem"


# --- Identity configuration (neutral defaults, no personal data) -------------

#: Organization name used in the CA and leaf certificate subjects.
def get_organization() -> str:
    """Return the organization (``O``) field for certificate subjects."""
    return os.environ.get("VAULT_ORG", "Secure Data Vault")


def get_country() -> str:
    """Return the two-letter country (``C``) field for certificate subjects."""
    return os.environ.get("VAULT_COUNTRY", "GR")


#: Common name of the self-signed root CA.
CA_COMMON_NAME = "Secure Data Vault CA"

#: Neutral demo entities: (short name used for filenames, certificate CN).
DEMO_ENTITIES = (
    ("vault", "Secure Data Vault"),
    ("user1", "User 1"),
    ("user2", "User 2"),
)
