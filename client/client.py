import socket
import sys
import time
import random

from dnslib import DNSRecord

from common.congestion import CongestionController
from common.config import (
    SERVER_IP,
    SERVER_PORT,
    DNS_DOMAIN,
    DNS_TIMEOUT
)
from common.metrics_logger import (
    initialize_metrics_file,
    log_metric
)
from common.metrics import (
    get_timestamp,
    calculate_rtt,
    calculate_average,
    calculate_min,
    calculate_max
)
from common.fragmentation import create_fragment_packets
from common.dns_encoding import split_dns_labels
from common.crypto import get_key, encrypt_data


DEFAULT_CLIENT_ID = sys.argv[1] if len(sys.argv) > 1 else "C01"
DEFAULT_SESSION_ID = sys.argv[2] if len(sys.argv) > 2 else "SESSION001"


def send_packet(
    payload,
    client_id=DEFAULT_CLIENT_ID,
    session_id=DEFAULT_SESSION_ID,
    loss_rate=0.0
):
    initialize_metrics_file()

    key = get_key()

    print("Original plaintext:")
    print(payload)

    encrypted_payload = encrypt_data(
        payload,
        key
    )

    print("\nEncrypted payload:")
    print(encrypted_payload)

    packets = create_fragment_packets(
        client_id=client_id,
        session_id=session_id,
        data=encrypted_payload
    )

    print(
        f"\nTotal fragments: "
        f"{len(packets)}"
    )

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    sock.settimeout(
        DNS_TIMEOUT
    )

    rtt_values = []
    controller = CongestionController()

    successful_fragments = 0
    lost_fragments = 0

    try:

        for packet in packets:

            print(
                f"\nSending fragment "
                f"{packet.sequence}/"
                f"{packet.total_fragments}"
            )

            print(
                f"Flag: {packet.flags}"
            )

            encoded_packet = (
                packet.encode_base32()
            )

            print(
                f"Base32 length: "
                f"{len(encoded_packet)}"
            )

            labels = split_dns_labels(
                encoded_packet
            )

            domain = (
                ".".join(labels)
                + "."
                + DNS_DOMAIN
            )

            print(
                f"DNS domain: {domain}"
            )

            request = DNSRecord.question(
                domain,
                "A"
            )

            start_time = get_timestamp()

            simulated_loss = (
                random.random() < loss_rate
            )

            if simulated_loss:

                controller.record_loss()
                controller.update()

                lost_fragments += 1

                log_metric(
                    client_id=client_id,
                    session_id=session_id,
                    fragment=packet.sequence,
                    total_fragments=packet.total_fragments,
                    rtt_ms=None,
                    success=0,
                    loss=1,
                    adaptive_delay=controller.get_delay()
                )

                print(
                    f"SIMULATED LOSS: "
                    f"fragment {packet.sequence}"
                )

                print(
                    f"Loss rate: "
                    f"{controller.loss_rate() * 100:.2f}%"
                )

                print(
                    f"Adaptive delay: "
                    f"{controller.get_delay():.3f} s"
                )

                time.sleep(
                    controller.get_delay()
                )

                continue

            sock.sendto(
                request.pack(),
                (SERVER_IP, SERVER_PORT)
            )

            data, address = sock.recvfrom(4096)

            end_time = get_timestamp()

            rtt = calculate_rtt(
                start_time,
                end_time
            )

            rtt_values.append(rtt)

            successful_fragments += 1

            controller.record_rtt(rtt)
            controller.record_success()
            controller.update()

            log_metric(
                client_id=client_id,
                session_id=session_id,
                fragment=packet.sequence,
                total_fragments=packet.total_fragments,
                rtt_ms=rtt,
                success=1,
                loss=0,
                adaptive_delay=controller.get_delay()
            )

            print(
                f"RTT: {rtt:.3f} ms"
            )

            print(
                f"Adaptive delay: "
                f"{controller.get_delay():.3f} s"
            )

            response = DNSRecord.parse(
                data
            )

            print(
                f"DNS response received "
                f"from {address[0]}:"
                f"{address[1]}"
            )

            print(
                f"Status: "
                f"{response.header.rcode}"
            )

            time.sleep(
                controller.get_delay()
            )

        average_rtt = calculate_average(
            rtt_values
        )

        minimum_rtt = calculate_min(
            rtt_values
        )

        maximum_rtt = calculate_max(
            rtt_values
        )

        observed_loss_rate = (
            controller.loss_rate() * 100
        )

        final_delay = (
            controller.get_delay()
        )

        print("\nRTT Statistics:")

        print(
            f"Average RTT: "
            f"{average_rtt:.3f} ms"
        )

        print(
            f"Minimum RTT: "
            f"{minimum_rtt:.3f} ms"
        )

        print(
            f"Maximum RTT: "
            f"{maximum_rtt:.3f} ms"
        )

        print(
            f"Packet loss rate: "
            f"{observed_loss_rate:.2f}%"
        )

        print(
            f"Final adaptive delay: "
            f"{final_delay:.3f} s"
        )

        return {
            "success": True,
            "client_id": client_id,
            "session_id": session_id,
            "fragments": len(packets),
            "successful_fragments": successful_fragments,
            "lost_fragments": lost_fragments,
            "average_rtt": average_rtt,
            "minimum_rtt": minimum_rtt,
            "maximum_rtt": maximum_rtt,
            "packet_loss": observed_loss_rate,
            "adaptive_delay": final_delay
        }

    except socket.timeout:

        print(
            "\nERROR: DNS server "
            "did not respond."
        )

        return {
            "success": False,
            "error": "DNS server did not respond."
        }

    except Exception as e:

        print(
            f"\nERROR: {e}"
        )

        return {
            "success": False,
            "error": str(e)
        }

    finally:

        sock.close()


if __name__ == "__main__":

    test_message = (
        "Hello DNSentinel! "
        "This is a longer message "
        "that will be divided into "
        "multiple encrypted fragments "
        "for DNS transmission."
    )

    send_packet(
        test_message,
        DEFAULT_CLIENT_ID,
        DEFAULT_SESSION_ID,
        0.0
    )