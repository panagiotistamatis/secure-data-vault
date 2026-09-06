"""Round-trip tests for the Secure Data Vault cryptographic primitives.

These exercise the exact primitives the application relies on:

* AES-256-CBC encrypt -> decrypt returns the original plaintext.
* RSA-OAEP wrap -> unwrap of an AES key returns the original key.
* RSA-PSS sign -> verify succeeds, and verification fails on tampered data.
"""
import os

from secure_vault.crypto_utils import CryptoUtils


def test_aes_encrypt_decrypt_roundtrip():
    """AES-256-CBC encryption then decryption returns the original plaintext."""
    aes_key = CryptoUtils.generate_aes_key()  # 256-bit key
    assert len(aes_key) == 32

    plaintext = b"Secret vault contents -- with some length past one block boundary."
    ciphertext = CryptoUtils.encrypt_bytes_symmetric(plaintext, aes_key)

    # Ciphertext is IV (16 bytes) || AES-CBC ciphertext, and differs from input.
    assert len(ciphertext) >= 16 + 16
    assert ciphertext[16:] != plaintext

    recovered = CryptoUtils.decrypt_file_symmetric(ciphertext, aes_key)
    assert recovered == plaintext


def test_aes_roundtrip_various_lengths():
    """Padding is handled correctly for block-aligned and empty inputs."""
    aes_key = CryptoUtils.generate_aes_key()
    for length in (0, 1, 15, 16, 17, 64):
        plaintext = os.urandom(length)
        ciphertext = CryptoUtils.encrypt_bytes_symmetric(plaintext, aes_key)
        assert CryptoUtils.decrypt_file_symmetric(ciphertext, aes_key) == plaintext


def test_rsa_oaep_wrap_unwrap_roundtrip():
    """An AES key wrapped with RSA-OAEP unwraps back to the same bytes."""
    private_key, public_key = CryptoUtils.generate_rsa_keypair(2048)
    aes_key = CryptoUtils.generate_aes_key()

    wrapped = CryptoUtils.encrypt_asymmetric(aes_key, public_key)
    assert wrapped != aes_key

    unwrapped = CryptoUtils.decrypt_asymmetric(wrapped, private_key)
    assert unwrapped == aes_key


def test_sign_verify_success_and_tamper_detection():
    """RSA-PSS verify passes for a genuine signature and fails after tampering."""
    private_key, public_key = CryptoUtils.generate_rsa_keypair(2048)

    aes_key = CryptoUtils.generate_aes_key()
    ciphertext = CryptoUtils.encrypt_bytes_symmetric(b"payload to protect", aes_key)

    # The vault signs the hex SHA-256 of the ciphertext (as bytes).
    digest = CryptoUtils.calculate_hash(ciphertext).encode()
    signature = CryptoUtils.sign_data(digest, private_key)

    # Genuine signature verifies.
    assert CryptoUtils.verify_signature(digest, signature, public_key) is True

    # Tampering with the ciphertext changes its hash, so verification fails.
    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01
    tampered_digest = CryptoUtils.calculate_hash(bytes(tampered)).encode()
    assert CryptoUtils.verify_signature(tampered_digest, signature, public_key) is False


def test_full_hybrid_flow():
    """End-to-end: encrypt file, wrap key, sign, then reverse the whole chain."""
    private_key, public_key = CryptoUtils.generate_rsa_keypair(2048)
    aes_key = CryptoUtils.generate_aes_key()

    plaintext = b"Hybrid encryption end-to-end test payload."
    ciphertext = CryptoUtils.encrypt_bytes_symmetric(plaintext, aes_key)
    wrapped_key = CryptoUtils.encrypt_asymmetric(aes_key, public_key)

    digest = CryptoUtils.calculate_hash(ciphertext).encode()
    signature = CryptoUtils.sign_data(digest, private_key)

    # Verify integrity, unwrap the key, and decrypt.
    assert CryptoUtils.verify_signature(digest, signature, public_key)
    recovered_key = CryptoUtils.decrypt_asymmetric(wrapped_key, private_key)
    assert recovered_key == aes_key
    assert CryptoUtils.decrypt_file_symmetric(ciphertext, recovered_key) == plaintext
