import socket
import time

from dnslib import DNSRecord

from common.config import (
    SERVER_IP,
    SERVER_PORT,
    DNS_DOMAIN
)

from common.crypto import get_key, encrypt_data
from common.fragmentation import create_fragment_packets
from common.dns_encoding import split_dns_labels


CLIENTS = [
    ("C01", "SESSION001", "Message from Client 1."),
    ("C02", "SESSION002", "Message from Client 2."),
    ("C03", "SESSION003", "Message from Client 3.")
]


def send_fragment(sock, packet):

    encoded_packet = packet.encode_base32()

    labels = split_dns_labels(
        encoded_packet
    )

    domain = (
        ".".join(labels)
        + "."
        + DNS_DOMAIN
    )

    request = DNSRecord.question(
        domain,
        "A"
    )

    sock.sendto(
        request.pack(),
        (SERVER_IP, SERVER_PORT)
    )

    data, _ = sock.recvfrom(4096)

    DNSRecord.parse(data)


def main():

    key = get_key()

    client_packets = []

    for client_id, session_id, message in CLIENTS:

        encrypted_data = encrypt_data(
            message,
            key
        )

        packets = create_fragment_packets(
            client_id=client_id,
            session_id=session_id,
            data=encrypted_data
        )

        client_packets.append(packets)

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:

        max_fragments = max(
            len(packets)
            for packets in client_packets
        )

        for index in range(max_fragments):

            for packets in client_packets:

                if index < len(packets):

                    packet = packets[index]

                    print(
                        f"Sending "
                        f"{packet.client_id} "
                        f"fragment "
                        f"{packet.sequence}/"
                        f"{packet.total_fragments}"
                    )

                    send_fragment(
                        sock,
                        packet
                    )

                    time.sleep(0.1)

    finally:

        sock.close()


if __name__ == "__main__":
    main()