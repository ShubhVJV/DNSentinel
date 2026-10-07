from common.crypto import generate_key, encrypt_data, decrypt_data


def test_encryption_decryption():

    plaintext = "Hello DNSentinel!"

    # Generate AES-256 key
    key = generate_key()

    print("Generated AES-256 key:")
    print(key.hex())

    # Encrypt
    encrypted = encrypt_data(
        plaintext,
        key
    )

    print("\nEncrypted data:")
    print(encrypted)

    # Make sure encrypted data is different
    assert encrypted != plaintext

    # Decrypt
    decrypted = decrypt_data(
        encrypted,
        key
    )

    print("\nDecrypted data:")
    print(decrypted)

    # Verify original data is recovered
    assert decrypted == plaintext

    print("\nAES-GCM encryption/decryption test passed!")


def test_tampered_data():

    plaintext = "Hello DNSentinel!"

    key = generate_key()

    encrypted = encrypt_data(
        plaintext,
        key
    )

    # Modify encrypted data
    encrypted_bytes = bytearray(
        __import__("base64").b64decode(encrypted)
    )

    encrypted_bytes[-1] ^= 1

    tampered = __import__("base64").b64encode(
        encrypted_bytes
    ).decode("ascii")

    try:
        decrypt_data(
            tampered,
            key
        )

        assert False, "Tampered data was accepted"

    except ValueError:
        pass

    print("Tampering detection test passed!")


if __name__ == "__main__":

    test_encryption_decryption()

    test_tampered_data()

    print("\nAll AES-GCM tests passed!")