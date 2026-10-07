import math

from common.config import MAX_DNS_LABEL_LENGTH


def split_dns_labels(data):
    """
    Split a DNS-safe string into labels of at most 63 characters.
    """

    return [
        data[i:i + MAX_DNS_LABEL_LENGTH]
        for i in range(
            0,
            len(data),
            MAX_DNS_LABEL_LENGTH
        )
    ]


def join_dns_labels(labels):
    """
    Reconstruct the original string from DNS labels.
    """

    return "".join(labels)


def base32_encoded_length(data_length):
    """
    Calculate Base32 encoded length without padding.
    """

    return math.ceil(
        data_length * 8 / 5
    )


def calculate_safe_fragment_size(
    max_label_length=MAX_DNS_LABEL_LENGTH
):
    """
    Calculate a conservative fragment size
    that fits within one DNS label after
    Base32 encoding.

    The protocol header is not included here,
    so we reserve space for it.
    """

    protocol_overhead = 20

    available = (
        max_label_length
        - protocol_overhead
    )

    return int(
        available * 5 / 8
    )