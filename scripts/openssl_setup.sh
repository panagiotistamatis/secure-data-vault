#!/bin/bash
#
# Manual PKI setup with the OpenSSL command-line tools.
#
# This mirrors, step by step, the certificate hierarchy that the Python code
# builds programmatically (see src/secure_vault/ca.py). It exists to document
# the underlying OpenSSL commands; the Python application does NOT call it.
#
# All identity fields are neutral and parameterised -- no personal data. Override
# the organisation, country or output directory via environment variables:
#
#   VAULT_ORG="Secure Data Vault"   ORG (O) field
#   VAULT_COUNTRY="GR"               country (C) field
#   VAULT_HOME="./data"              base output directory
#
# Usage:
#   ./scripts/openssl_setup.sh
#
set -euo pipefail

ORG="${VAULT_ORG:-Secure Data Vault}"
COUNTRY="${VAULT_COUNTRY:-GR}"
HOME_DIR="${VAULT_HOME:-./data}"

CA_DIR="${HOME_DIR}/ca"
VAULT_DIR="${HOME_DIR}/vault"
USER1_DIR="${HOME_DIR}/users/user1"
USER2_DIR="${HOME_DIR}/users/user2"

echo "=== OpenSSL Certificate Setup ==="
echo "Organisation: ${ORG}"
echo "Country:      ${COUNTRY}"
echo "Output dir:   ${HOME_DIR}"
echo ""

mkdir -p "${CA_DIR}/certs" "${VAULT_DIR}" "${USER1_DIR}" "${USER2_DIR}"

echo "Step 1: Generate CA private key (RSA-4096)"
openssl genpkey -algorithm RSA -out "${CA_DIR}/ca_key.pem" -pkeyopt rsa_keygen_bits:4096

echo ""
echo "Step 2: Create the self-signed CA certificate (3650 days)"
openssl req -new -x509 -key "${CA_DIR}/ca_key.pem" -out "${CA_DIR}/ca_cert.pem" -days 3650 -sha256 \
    -subj "/C=${COUNTRY}/O=${ORG}/CN=Secure Data Vault CA"

# issue_leaf <short-name> <common-name> <output-dir>
issue_leaf() {
    local name="$1"
    local cn="$2"
    local dir="$3"

    echo ""
    echo "Generating ${name} private key (RSA-2048), CSR and certificate (365 days)"
    openssl genpkey -algorithm RSA -out "${dir}/${name}_key.pem" -pkeyopt rsa_keygen_bits:2048
    openssl req -new -key "${dir}/${name}_key.pem" -out "${dir}/${name}.csr" \
        -subj "/C=${COUNTRY}/O=${ORG}/CN=${cn}"
    openssl x509 -req -in "${dir}/${name}.csr" \
        -CA "${CA_DIR}/ca_cert.pem" -CAkey "${CA_DIR}/ca_key.pem" -CAcreateserial \
        -out "${dir}/${name}_cert.pem" -days 365 -sha256
}

echo ""
echo "Step 3: Issue the vault certificate"
issue_leaf "vault" "Secure Data Vault" "${VAULT_DIR}"

echo ""
echo "Step 4: Issue the user certificates"
issue_leaf "user1" "User 1" "${USER1_DIR}"
issue_leaf "user2" "User 2" "${USER2_DIR}"

echo ""
echo "Step 5: Verify the issued certificates against the CA"
openssl verify -CAfile "${CA_DIR}/ca_cert.pem" "${VAULT_DIR}/vault_cert.pem"
openssl verify -CAfile "${CA_DIR}/ca_cert.pem" "${USER1_DIR}/user1_cert.pem"
openssl verify -CAfile "${CA_DIR}/ca_cert.pem" "${USER2_DIR}/user2_cert.pem"

echo ""
echo "Cleaning up temporary CSR and serial files..."
rm -f "${VAULT_DIR}/vault.csr" "${USER1_DIR}/user1.csr" "${USER2_DIR}/user2.csr" "${CA_DIR}/ca_cert.srl"

echo "Done."
