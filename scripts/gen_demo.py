"""Generate a fresh, fully working demo of the Secure Data Vault.

This is the required first step from the README. It provisions, under
``$VAULT_HOME`` (default ``<repo>/data``):

* a self-signed RSA-4096 Certificate Authority;
* CA-signed RSA-2048 certificates for the neutral entities ``vault``,
  ``user1`` and ``user2``;
* a copy of the synthetic sample files (from ``examples/sample_files``) placed
  under ``<VAULT_HOME>/sample_files`` ready to be uploaded via the CLI or GUI.

No secrets are committed to the repository: everything it writes lives under
``data/`` (gitignored). Re-run with ``--fresh`` to wipe and rebuild.

Usage::

    python scripts/gen_demo.py [--fresh] [--home PATH]
"""
import argparse
import os
import shutil
import sys
from pathlib import Path

# Make the `secure_vault` package importable without installation.
REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
sys.path.insert(0, str(SRC_DIR))

from secure_vault.ca import CertificateAuthority, setup_entities  # noqa: E402
from secure_vault import config  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description="Generate a demo Secure Data Vault.")
    parser.add_argument(
        "--home",
        default=None,
        help="Base directory for all vault data (overrides VAULT_HOME; default ./data).",
    )
    parser.add_argument(
        "--fresh",
        action="store_true",
        help="Delete any existing data directory before building.",
    )
    args = parser.parse_args()

    # Resolve and pin the base directory via VAULT_HOME so the whole package agrees.
    if args.home is not None:
        os.environ[config.VAULT_HOME_ENV] = args.home
    elif config.VAULT_HOME_ENV not in os.environ:
        os.environ[config.VAULT_HOME_ENV] = str(REPO_ROOT / "data")

    vault_home = config.get_vault_home()

    if args.fresh and vault_home.exists():
        print(f"Removing existing data directory: {vault_home}")
        shutil.rmtree(vault_home)

    vault_home.mkdir(parents=True, exist_ok=True)
    print(f"Building demo under: {vault_home}\n")

    # 1. Certificate Authority.
    print("[1/3] Provisioning Certificate Authority (RSA-4096, self-signed)...")
    ca = CertificateAuthority()

    # 2. Vault + user certificates.
    print("\n[2/3] Issuing certificates for vault, user1 and user2 (RSA-2048)...")
    setup_entities(ca)

    # 3. Copy synthetic sample files in.
    print("\n[3/3] Copying sample files...")
    src_samples = REPO_ROOT / "examples" / "sample_files"
    dst_samples = vault_home / "sample_files"
    dst_samples.mkdir(parents=True, exist_ok=True)
    copied = []
    if src_samples.exists():
        for item in sorted(src_samples.iterdir()):
            if item.is_file():
                shutil.copy2(item, dst_samples / item.name)
                copied.append(item.name)
    if copied:
        print(f"Copied {len(copied)} sample file(s) to {dst_samples}: {', '.join(copied)}")
    else:
        print(f"No sample files found in {src_samples}")

    print("\nDemo ready.")
    print("Next steps:")
    print("  CLI:  python -m secure_vault.cli")
    print("  GUI:  python -m secure_vault.gui")
    print(f"Sample files to upload are in: {dst_samples}")


if __name__ == "__main__":
    main()
