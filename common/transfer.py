from common.crypto import encrypt_data, decrypt_data
from common.fragmentation import (
    create_fragment_packets,
    reassemble_packets
)


def prepare_transfer(
    client_id,
    session_id,
    plaintext,
    key,
    fragment_size
):
    encrypted_data = encrypt_data(
        plaintext,
        key
    )

    packets = create_fragment_packets(
        client_id=client_id,
        session_id=session_id,
        data=encrypted_data,
        fragment_size=fragment_size
    )

    return packets


def recover_transfer(
    packets,
    key
):
    encrypted_data = reassemble_packets(
        packets
    )

    plaintext = decrypt_data(
        encrypted_data,
        key
    )

    return plaintext