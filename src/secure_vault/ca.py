"""A minimal X.509 Certificate Authority for the Secure Data Vault.

The CA is a self-signed RSA-4096 root (valid 3650 days) that issues RSA-2048
leaf certificates (valid 365 days) to the vault and to users. All identity
fields are neutral and parameterisable -- no personal data is embedded in any
subject.
"""
import os
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

from .config import (
    CA_COMMON_NAME,
    DEMO_ENTITIES,
    get_ca_dir,
    get_country,
    get_organization,
    get_user_dir,
    get_vault_dir,
)
from .crypto_utils import CryptoUtils


class CertificateAuthority:
    """Issues and verifies certificates for the vault and its users."""

    def __init__(self, ca_dir=None):
        self.ca_dir = str(ca_dir) if ca_dir is not None else str(get_ca_dir())
        self.ca_cert_path = os.path.join(self.ca_dir, "ca_cert.pem")
        self.ca_key_path = os.path.join(self.ca_dir, "ca_key.pem")
        self.certs_dir = os.path.join(self.ca_dir, "certs")

        # Create directories if they do not exist.
        os.makedirs(self.certs_dir, exist_ok=True)

        # Load an existing CA, or create a fresh one on first run.
        if os.path.exists(self.ca_cert_path) and os.path.exists(self.ca_key_path):
            self.ca_cert = CryptoUtils.load_certificate(self.ca_cert_path)
            self.ca_key = CryptoUtils.load_private_key(self.ca_key_path)
        else:
            self.create_ca_certificate()

    def _leaf_subject(self, common_name):
        """Build a neutral subject name for a leaf (vault/user) certificate."""
        return x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, get_country()),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, get_organization()),
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ]
        )

    def create_ca_certificate(self):
        """Create and persist a self-signed RSA-4096 root CA certificate."""
        print("Creating new CA certificate...")

        # Generate the CA key pair (RSA-4096).
        self.ca_key, _ = CryptoUtils.generate_rsa_keypair(4096)

        # Neutral, non-personal CA subject/issuer.
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, get_country()),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, get_organization()),
                x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
            ]
        )

        now = datetime.now(timezone.utc)
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(subject)
        cert_builder = cert_builder.issuer_name(issuer)
        cert_builder = cert_builder.public_key(self.ca_key.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(now + timedelta(days=3650))

        # CA extensions: allow this cert to sign other certificates.
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(self.ca_key.public_key()),
            critical=False,
        )

        # Self-sign.
        self.ca_cert = cert_builder.sign(self.ca_key, hashes.SHA256(), default_backend())

        # Persist certificate and key.
        CryptoUtils.save_certificate(self.ca_cert, self.ca_cert_path)
        CryptoUtils.save_private_key(self.ca_key, self.ca_key_path)

        print(f"CA certificate created and saved to {self.ca_cert_path}")

    def create_csr(self, private_key, common_name):
        """Build a Certificate Signing Request for a neutral ``common_name``."""
        csr_builder = x509.CertificateSigningRequestBuilder()
        csr_builder = csr_builder.subject_name(self._leaf_subject(common_name))

        # Sign the CSR with the requester's private key.
        csr = csr_builder.sign(private_key, hashes.SHA256(), default_backend())

        return csr.public_bytes(serialization.Encoding.PEM)

    def process_csr(self, csr_pem, entity_name, common_name):
        """Validate a CSR and issue a signed RSA-2048 leaf certificate.

        ``entity_name`` is the short, filesystem-safe name (e.g. ``vault``,
        ``user1``) used for the stored certificate filename; ``common_name``
        is the human-readable subject CN.
        """
        # Load and validate the CSR.
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
        if not csr.is_signature_valid:
            raise ValueError("Invalid CSR signature")

        now = datetime.now(timezone.utc)
        cert_builder = x509.CertificateBuilder()
        cert_builder = cert_builder.subject_name(self._leaf_subject(common_name))
        cert_builder = cert_builder.issuer_name(self.ca_cert.subject)
        cert_builder = cert_builder.public_key(csr.public_key())
        cert_builder = cert_builder.serial_number(x509.random_serial_number())
        cert_builder = cert_builder.not_valid_before(now)
        cert_builder = cert_builder.not_valid_after(now + timedelta(days=365))

        # Leaf extensions.
        cert_builder = cert_builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        cert_builder = cert_builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=True,
                data_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        cert_builder = cert_builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
            critical=False,
        )
        cert_builder = cert_builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca_key.public_key()),
            critical=False,
        )

        # Sign with the CA key.
        certificate = cert_builder.sign(self.ca_key, hashes.SHA256(), default_backend())

        # Persist the issued certificate in the CA's certs directory.
        cert_filename = f"{entity_name}_cert.pem"
        cert_path = os.path.join(self.certs_dir, cert_filename)
        CryptoUtils.save_certificate(certificate, cert_path)

        print(f"Certificate issued for {entity_name} and saved to {cert_path}")

        return certificate

    def verify_certificate(self, cert_to_verify):
        """Verify a certificate was issued by this CA and is currently valid.

        Returns ``(is_valid, message)``.
        """
        try:
            # Verify the CA's signature over the certificate body.
            ca_public_key = self.ca_cert.public_key()
            ca_public_key.verify(
                cert_to_verify.signature,
                cert_to_verify.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert_to_verify.signature_hash_algorithm,
            )

            # Check the validity window (timezone-aware UTC comparison).
            now = datetime.now(timezone.utc)
            if now < cert_to_verify.not_valid_before_utc or now > cert_to_verify.not_valid_after_utc:
                return False, "Certificate has expired or is not yet valid"

            return True, "Certificate is valid"
        except Exception as e:
            return False, f"Certificate verification failed: {str(e)}"


def setup_entities(ca):
    """Create key pairs and CA-signed certificates for the demo entities.

    Produces neutral ``vault``, ``user1`` and ``user2`` identities. The vault's
    material is written under the vault directory; each user's under its own
    user directory. No personal data is involved.
    """
    for entity_name, common_name in DEMO_ENTITIES:
        # Determine where this entity's material lives on disk.
        if entity_name == "vault":
            entity_dir = str(get_vault_dir())
        else:
            entity_dir = str(get_user_dir(entity_name))
        os.makedirs(entity_dir, exist_ok=True)

        # Generate the entity key pair (RSA-2048).
        private_key, _ = CryptoUtils.generate_rsa_keypair()

        # Persist the private key.
        key_path = os.path.join(entity_dir, f"{entity_name}_key.pem")
        CryptoUtils.save_private_key(private_key, key_path)

        # Request and receive a certificate from the CA.
        csr_pem = ca.create_csr(private_key, common_name)
        cert = ca.process_csr(csr_pem, entity_name, common_name)

        # Persist the certificate alongside the key.
        cert_path = os.path.join(entity_dir, f"{entity_name}_cert.pem")
        CryptoUtils.save_certificate(cert, cert_path)

        print(f"Setup completed for {common_name}")


if __name__ == "__main__":
    # Initialise the CA and provision the neutral demo entities.
    authority = CertificateAuthority()
    setup_entities(authority)
