import socket
import json
import os
from datetime import datetime

from dnslib import DNSRecord, QTYPE, RR, A

from common.config import (
    SERVER_IP,
    SERVER_PORT,
    BUFFER_SIZE,
    DNS_DOMAIN
)

from common.protocol import Packet
from common.dns_encoding import join_dns_labels
from common.crypto import get_key, decrypt_data
from common.fragmentation import reassemble_packets


CLIENT_BUFFERS = {}
def save_last_transfer(client_id, session_id, plaintext, fragment_count):

    project_root = os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )

    analysis_dir = os.path.join(
        project_root,
        "analysis"
    )

    os.makedirs(
        analysis_dir,
        exist_ok=True
    )

    result_file = os.path.join(
        analysis_dir,
        "last_transfer.json"
    )

    result = {
        "client_id": client_id,
        "session_id": session_id,
        "status": "success",
        "message": plaintext,
        "fragments": fragment_count,
        "timestamp": datetime.now().isoformat()
    }

    with open(
        result_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            result,
            file,
            indent=4,
            ensure_ascii=False
        )

    print(f"Transfer result saved to: {result_file}")
def start_server():

    print(
        f"DNSentinel server starting on "
        f"{SERVER_IP}:{SERVER_PORT}..."
    )

    try:
        key = get_key()
        print("AES-256 key loaded successfully.")

    except ValueError as e:
        print(f"ERROR loading AES key: {e}")
        return

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.bind(
        (SERVER_IP, SERVER_PORT)
    )

    print("DNS server is running.")
    print("Waiting for DNS queries...\n")

    try:

        while True:

            data, address = sock.recvfrom(
                BUFFER_SIZE
            )

            try:

                request = DNSRecord.parse(data)

                if not request.questions:
                    continue

                question = request.questions[0]

                domain = str(
                    question.qname
                ).rstrip(".")

                print(
                    f"Received query from "
                    f"{address[0]}:{address[1]}"
                )

                print(
                    f"Query: {domain}"
                )
                print(
                    f"Query: {domain}"
                )

                # ==========================================
                # DNS Health Check
                # ==========================================

                if domain.lower() == "health.dnsentinel.local":

                    reply = request.reply()

                    reply.add_answer(
                        RR(
                            rname=question.qname,
                            rtype=QTYPE.A,
                            rdata=A("127.0.0.1"),
                            ttl=5
                        )
                    )

                    sock.sendto(
                        reply.pack(),
                        address
                    )

                    print("DNS health check responded successfully.\n")

                    continue

                suffix = "." + DNS_DOMAIN
                suffix = "." + DNS_DOMAIN

                if not domain.endswith(suffix):

                    print(
                        "Not a DNSentinel packet.\n"
                    )

                    continue

                encoded_data = domain[
                    :-len(suffix)
                ]

                labels = encoded_data.split(".")

                try:

                    encoded_packet = join_dns_labels(
                        labels
                    )

                    packet = Packet.decode_base32(
                        encoded_packet
                    )

                    print(
                        "\nDNSentinel packet decoded:"
                    )

                    print(
                        f"Client ID       : "
                        f"{packet.client_id}"
                    )

                    print(
                        f"Session ID      : "
                        f"{packet.session_id}"
                    )

                    print(
                        f"Sequence        : "
                        f"{packet.sequence}"
                    )

                    print(
                        f"Total fragments : "
                        f"{packet.total_fragments}"
                    )

                    print(
                        f"Flags           : "
                        f"{packet.flags}"
                    )

                    print(
                        f"Payload length  : "
                        f"{len(packet.payload)}"
                    )

                    # Create buffer for this session
                    session_key = (
                        packet.client_id,
                        packet.session_id
                    )

                    if session_key not in CLIENT_BUFFERS:

                        CLIENT_BUFFERS[session_key] = {}

                    fragments = CLIENT_BUFFERS[
                        session_key
                    ]

                    # Store fragment
                    if packet.sequence in fragments:

                        print(
                            f"Duplicate fragment "
                            f"{packet.sequence} "
                            f"received."
                        )

                    else:

                        fragments[
                            packet.sequence
                        ] = packet

                        print(
                            f"Fragment "
                            f"{packet.sequence}/"
                            f"{packet.total_fragments} "
                            f"stored."
                        )

                    received_count = len(
                        fragments
                    )

                    print(
                        f"Fragments received: "
                        f"{received_count}/"
                        f"{packet.total_fragments}"
                    )

                    # Check whether complete
                    if (
                        received_count
                        == packet.total_fragments
                    ):

                        print(
                            "\nAll fragments "
                            "received!"
                        )

                        packet_list = list(
                            fragments.values()
                        )

                        try:

                            encrypted_payload = (
                                reassemble_packets(
                                    packet_list
                                )
                            )

                            print(
                                "Encrypted payload "
                                "reassembled."
                            )

                            plaintext = decrypt_data(
                                encrypted_payload,
                                key
                            )

                            print(
                                "\nRecovered "
                                "plaintext:"
                            )

                            print(
                                plaintext
                            )

                            print(
                                "\nAES-GCM "
                                "decryption "
                                "successful!"
                            )

                            save_last_transfer(
                                client_id=packet.client_id,
                                session_id=packet.session_id,
                                plaintext=plaintext,
                                fragment_count=packet.total_fragments
                            )

                            print(
                                "Transfer result saved to "
                                "analysis/last_transfer.json"
                            )

                            # Remove completed session
                            del CLIENT_BUFFERS[
                                session_key
                            ]

                        except ValueError as e:

                            if str(e) == (
                                "AES-GCM "
                                "authentication failed"
                            ):

                                print(
                                    "\nAUTHENTICATION "
                                    "FAILURE:"
                                )

                                print(
                                    "AES-GCM "
                                    "authentication "
                                    "failed."
                                )

                                print(
                                    "Transfer rejected."
                                )

                            else:

                                print(
                                    f"\nTransfer "
                                    f"reassembly/"
                                    f"decryption "
                                    f"failed: {e}"
                                )

                            # Remove invalid transfer
                            if session_key in CLIENT_BUFFERS:

                                del CLIENT_BUFFERS[
                                    session_key
                                ]

                        print()

                except ValueError as e:

                    print(
                        f"Invalid DNSentinel "
                        f"packet: {e}\n"
                    )

                # Send DNS response
                reply = request.reply()

                if question.qtype == QTYPE.A:

                    reply.add_answer(
                        RR(
                            rname=question.qname,
                            rtype=QTYPE.A,
                            rdata=A("127.0.0.1"),
                            ttl=60
                        )
                    )

                sock.sendto(
                    reply.pack(),
                    address
                )

            except Exception as e:

                print(
                    f"Error processing "
                    f"DNS query: {e}\n"
                )

    except KeyboardInterrupt:

        print(
            "\nDNS server stopped."
        )

    finally:

        sock.close()


if __name__ == "__main__":
    start_server()