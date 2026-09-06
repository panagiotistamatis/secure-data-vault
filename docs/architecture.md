# Architecture

Secure Data Vault is a file store built on hybrid cryptography, with a small
X.509 PKI of its own. This document walks through the components, the trust
chain, the upload and download flows, and how files end up laid out on disk.

## Components

| Component | Module | Responsibility |
|-----------|--------|----------------|
| **Certificate Authority** | `secure_vault.ca` | Self-signed RSA-4096 root; issues RSA-2048 leaf certificates to the vault and users; verifies certificates. |
| **Vault server** | `secure_vault.vault_server` | Stores encrypted blobs, wrapped keys, signatures and metadata; signs each blob for tamper-evidence; keeps a user registry. Runs in-process (no networking). |
| **Client** | `secure_vault.client_app` | Owns a user's key pair; does all the encryption and decryption; talks to the vault. |
| **Crypto utilities** | `secure_vault.crypto_utils` | Thin wrappers over `cryptography` for AES, RSA-OAEP, RSA-PSS and SHA-256. |
| **Configuration** | `secure_vault.config` | Resolves a single base directory (`VAULT_HOME`) and the neutral identity fields. |
| **CLI / GUI** | `secure_vault.cli`, `secure_vault.gui` | Two front-ends over the same core. |

## Trust chain

```
                 +-------------------------+
                 |   Root CA (self-signed) |
                 |   RSA-4096, 3650 days   |
                 +------------+------------+
                              | signs (RSA / SHA-256)
             +----------------+-----------------+
             |                |                 |
     +-------v------+  +------v-------+  +------v-------+
     | Vault cert   |  | User1 cert   |  | User2 cert   |
     | RSA-2048     |  | RSA-2048     |  | RSA-2048     |
     | 365 days     |  | 365 days     |  | 365 days     |
     +--------------+  +--------------+  +--------------+
```

The CA gets created once, on first run, and its certificate is the single trust
anchor. Everything else is signed by the CA. All the subjects use neutral
identity fields (the organization defaults to "Secure Data Vault"), so no
personal data ends up in any certificate.

## Upload (store) data flow

The important property here is that the per-file AES key is wrapped with the
uploading user's *own* public key. That's what leaves the vault holding data it
can't decrypt, the "zero-knowledge storage" property.

```
Client (user1)                                   Vault
--------------                                   -----
1. AES key K = random 256 bits
2. C = AES-256-CBC(file, K)   -> IV || ciphertext
3. WK = RSA-OAEP(K, user1_pubkey)
                         store_file(C, WK)  ---->
                                                 4. H = SHA-256(C)
                                                 5. S = RSA-PSS(H, vault_privkey)
                                                 6. write C -> .enc
                                                    write WK -> .key
                                                    write S  -> .sig
                                                    write metadata -> .meta
```

Since `WK` is wrapped with user1's public key, only user1's private key can get
`K` back out. The vault never sees `K` in the clear.

## Download (retrieve) data flow

```
Client (user1)                                   Vault
--------------                                   -----
                         retrieve_file(id)  ---->
                                                 1. read C, WK, S, metadata
                                                 2. H' = SHA-256(C)
                                                 3. verify RSA-PSS(S, H', vault_pubkey)
                                                 4. check H' == metadata.file_hash
                         <----  (ok, C, WK)
5. K = RSA-OAEP-unwrap(WK, user1_privkey)
6. file = AES-256-CBC-decrypt(C, K)
```

When the signature or hash check fails, the vault reports the failure. One thing
to flag: the client in this project still goes ahead and tries to decrypt anyway
(a "force decrypt"). I've listed that as a limitation in the threat model.

## Storage format

For each stored file the vault writes four artifacts under
`<VAULT_HOME>/vault/storage/<username>/`, all sharing a `<file_id>` of the form
`<original_filename>_<unix_timestamp>`:

| Artifact | Contents |
|----------|----------|
| `<file_id>.enc` | `IV (16 bytes) || AES-256-CBC ciphertext` |
| `<file_id>.key` | The per-file AES key, RSA-OAEP-wrapped with the user's public key |
| `<file_id>.sig` | The vault's RSA-PSS signature over the hex SHA-256 of `.enc` |
| `<file_id>.meta` | JSON: `original_filename`, `stored_at`, `file_hash`, `file_size` |

## On-disk layout

Everything the application generates lives under `VAULT_HOME` (default `./data`),
which is gitignored:

```
data/
|-- ca/
|   |-- ca_cert.pem
|   |-- ca_key.pem
|   `-- certs/
|-- vault/
|   |-- vault_cert.pem
|   |-- vault_key.pem
|   |-- users.json
|   `-- storage/<username>/<file_id>.{enc,key,sig,meta}
`-- users/
    |-- user1/{user1_cert.pem, user1_key.pem}
    `-- user2/{user2_cert.pem, user2_key.pem}
```
