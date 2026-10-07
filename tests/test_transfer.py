from common.crypto import get_key
from common.transfer import (
    prepare_transfer,
    recover_transfer
)


def test_encrypted_fragmented_transfer():

    plaintext = (
        "This is a longer DNSentinel message "
        "that must be split into multiple "
        "fragments before transmission."
    )

    key = get_key()

    packets = prepare_transfer(
        client_id="C01",
        session_id="SESSION001",
        plaintext=plaintext,
        key=key,
        fragment_size=20
    )

    print("Created packets:")

    for packet in packets:

        print(
            f"Sequence: {packet.sequence} | "
            f"Total: {packet.total_fragments} | "
            f"Flag: {packet.flags} | "
            f"Payload length: "
            f"{len(packet.payload)}"
        )

    assert len(packets) > 1

    recovered = recover_transfer(
        packets,
        key
    )

    print("\nRecovered plaintext:")
    print(recovered)

    assert recovered == plaintext

    print(
        "\nEncrypted fragmented "
        "transfer test passed!"
    )


if __name__ == "__main__":

    test_encrypted_fragmented_transfer()

    print(
        "\nAll transfer tests passed!"
    )