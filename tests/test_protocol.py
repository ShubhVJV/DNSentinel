from common.protocol import Packet, FLAG_DATA


def test_packet_serialization():
    client_id = "C01"
    session_id = "SESSION001"
    sequence = 42
    flags = FLAG_DATA
    payload = "Hello DNSentinel!"

    original_packet = Packet(
        client_id=client_id,
        session_id=session_id,
        sequence=sequence,
        flags=flags,
        payload=payload
    )

    serialized = original_packet.serialize()

    print("Serialized packet:")
    print(serialized)

    decoded_packet = Packet.deserialize(serialized)

    # Verify every field
    assert decoded_packet.version == original_packet.version
    assert decoded_packet.client_id == client_id
    assert decoded_packet.session_id == session_id
    assert decoded_packet.sequence == sequence
    assert decoded_packet.flags == flags
    assert decoded_packet.payload == payload

    # Verify payload length
    assert len(decoded_packet.payload) == len(payload)

    parts = serialized.split("|", 6)
    serialized_payload_length = int(parts[5])

    assert serialized_payload_length == len(payload)
    assert serialized_payload_length == len(decoded_packet.payload)

    print("Basic serialization/deserialization test passed!")


def test_malformed_packet():
    # Missing required fields
    malformed_packet = "1|C01|SESSION001|42|DATA"

    try:
        Packet.deserialize(malformed_packet)
        assert False, "Malformed packet was incorrectly accepted"
    except ValueError:
        pass

    print("Malformed packet test passed!")


def test_payload_length_mismatch():
    # Declares payload length as 100, but actual payload is only "Hello"
    invalid_packet = "1|C01|SESSION001|42|DATA|100|Hello"

    try:
        Packet.deserialize(invalid_packet)
        assert False, "Payload-length mismatch was incorrectly accepted"
    except ValueError:
        pass

    print("Payload-length mismatch test passed!")


def test_invalid_version():
    # Protocol version 99 is not supported
    invalid_version_packet = "99|C01|SESSION001|42|DATA|5|Hello"

    try:
        Packet.deserialize(invalid_version_packet)
        assert False, "Invalid protocol version was incorrectly accepted"
    except ValueError:
        pass

    print("Invalid version test passed!")

def test_base32_encoding():
    original_packet = Packet(
        client_id="C01",
        session_id="SESSION001",
        sequence=1,
        flags=FLAG_DATA,
        payload="Hello DNSentinel!"
    )

    encoded = original_packet.encode_base32()

    print("\nBase32 encoded packet:")
    print(encoded)

    # Verify DNS-safe characters
    assert all(
        c in "abcdefghijklmnopqrstuvwxyz234567"
        for c in encoded
    )

    decoded_packet = Packet.decode_base32(encoded)

    assert decoded_packet.client_id == original_packet.client_id
    assert decoded_packet.session_id == original_packet.session_id
    assert decoded_packet.sequence == original_packet.sequence
    assert decoded_packet.flags == original_packet.flags
    assert decoded_packet.payload == original_packet.payload

    print("Base32 encoding/decoding test passed!")


if __name__ == "__main__":
    test_packet_serialization()
    test_malformed_packet()
    test_base32_encoding()
    test_payload_length_mismatch()
    test_invalid_version()

    print("\nAll protocol tests passed!")