from common.crypto import get_key


def test_key_loading():

    key = get_key()

    print("Loaded AES key successfully")
    print(f"Key length: {len(key)} bytes")

    assert len(key) == 32

    print("AES-256 key test passed!")


if __name__ == "__main__":
    test_key_loading()