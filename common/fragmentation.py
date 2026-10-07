from common.config import FRAGMENT_SIZE
from common.protocol import (
    Packet,
    FLAG_START,
    FLAG_DATA,
    FLAG_END
)
from common.dns_encoding import (
    base32_encoded_length,
    calculate_safe_fragment_size
)
def validate_fragment_size(fragment_size):
    """
    Verify that a fragment can fit safely
    inside a DNS label after Base32 encoding.
    """

    safe_size = calculate_safe_fragment_size()

    if fragment_size > safe_size:
        raise ValueError(
            f"Fragment size {fragment_size} is too large. "
            f"Maximum safe size is {safe_size}."
        )

    encoded_size = base32_encoded_length(
        fragment_size
    )

    if encoded_size > 63:
        raise ValueError(
            "Fragment produces an oversized DNS label"
        )

    return True
def fragment_data(data, fragment_size=FRAGMENT_SIZE):

    if fragment_size <= 0:
        raise ValueError(
            "Fragment size must be greater than zero"
        )

    validate_fragment_size(
        fragment_size
    )

    if not data:
        return [""]

    return [
        data[i:i + fragment_size]
        for i in range(
            0,
            len(data),
            fragment_size
        )
    ]


def create_fragment_packets(
    client_id,
    session_id,
    data,
    fragment_size=FRAGMENT_SIZE
):
    """
    Split data and create Packet objects
    for every fragment.
    """

    fragments = fragment_data(
        data,
        fragment_size
    )

    total_fragments = len(fragments)

    packets = []

    for index, fragment in enumerate(
        fragments,
        start=1
    ):

        if index == 1:
            flags = FLAG_START

        elif index == total_fragments:
            flags = FLAG_END

        else:
            flags = FLAG_DATA

        packet = Packet(
            client_id=client_id,
            session_id=session_id,
            sequence=index,
            total_fragments=total_fragments,
            flags=flags,
            payload=fragment
        )

        packets.append(packet)

    return packets


def reassemble_packets(packets):

    if not packets:
        return ""

    ordered_packets = sorted(
        packets,
        key=lambda packet: packet.sequence
    )

    total_fragments = (
        ordered_packets[0].total_fragments
    )

    if len(ordered_packets) != total_fragments:
        raise ValueError(
            "Missing fragments"
        )

    expected_sequence = 1

    for packet in ordered_packets:

        if packet.sequence != expected_sequence:
            raise ValueError(
                "Missing or duplicate fragment"
            )

        if packet.total_fragments != total_fragments:
            raise ValueError(
                "Fragment count mismatch"
            )

        expected_sequence += 1

    return "".join(
        packet.payload
        for packet in ordered_packets
    )