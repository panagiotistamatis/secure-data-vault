# Threat model and limitations

This is an academic project. It shows off a hybrid encryption + PKI design, and
I've tried to be upfront about what it actually protects and what it doesn't.
It is **not** production-ready. Both sides are laid out below.

## What it protects

| Property | Mechanism |
|----------|-----------|
| **Confidentiality at rest** | Files are encrypted with AES-256-CBC before they ever reach the vault, so the vault only stores ciphertext. |
| **Key confidentiality** | Each per-file AES key is wrapped with the uploading user's own RSA-2048 public key (OAEP/SHA-256). Only that user's private key can unwrap it, so the vault can't decrypt the files it stores ("zero-knowledge storage"). |
| **Tamper-evidence** | The vault signs the SHA-256 of every stored blob with RSA-PSS, so a client can tell if the stored ciphertext was modified before it retrieves it. |
| **Identity / authenticity** | A self-signed CA issues X.509 certificates to the vault and users, and they all chain back to a single trust anchor. |

## What it does NOT protect (known limitations / future work)

- **Private keys are stored unencrypted on disk.** `CryptoUtils.save_private_key`
  gets called with no password, so the PEM keys are written with `NoEncryption`.
  The password path is there in the code but nothing uses it. Anyone with
  filesystem access to a user's key can impersonate that user and decrypt their
  files. To fix it properly I'd encrypt the keys at rest (passphrase-protected
  PKCS#8) or hand them to an OS keystore or HSM.
- **No password or passphrase authentication.** Having the certificate and its
  key *is* the identity. There's no login, no second factor, nothing beyond
  possession of the key file.
- **AES-CBC is not authenticated encryption.** The confidentiality comes from
  AES-256-CBC, but CBC on its own gives you no integrity. Integrity is bolted on
  separately, and only by the vault's signature, not by the cipher. The right
  move is to switch to AES-256-GCM (AEAD), which I didn't get to.
- **Integrity is only vault-verifiable.** The tamper-evidence signature is made
  with the vault's key over the ciphertext. It catches storage-side tampering,
  but it isn't an end-to-end user signature over the plaintext, and a malicious
  vault could just re-sign altered data.
- **The client can force-decrypt past an integrity failure.** When a
  signature or hash check fails the vault says so, but the client still tries to
  decrypt. A stricter client would refuse.
- **No networking, so there's no real transport story.** The "server" is an
  in-process thread, not a network service. So there's nothing here that
  meaningfully protects against (or even demonstrates) replay, MITM, or TLS
  concerns. A real version would be a proper service behind mutual TLS.
- **No revocation.** There's no CRL or OCSP, so a compromised certificate can't
  be revoked before it expires.
- **Hand-rolled PKCS#7 padding.** The padding is written out by hand instead of
  going through a vetted padding API, purely to match the original coursework.
  In real code that's an easy way to shoot yourself in the foot.
- **Not constant-time, no side-channel hardening.** Key generation leans on the
  platform CSPRNG through `os.urandom` and the `cryptography` library.

## Summary

As a teaching example this holds up: it's a working demonstration of hybrid
encryption (symmetric bulk encryption plus asymmetric key wrapping) and
PKI-based identity, with a real zero-knowledge storage property. The main things
standing between it and a real system are key-at-rest protection, authenticated
encryption (AES-GCM), real transport security, and revocation.
