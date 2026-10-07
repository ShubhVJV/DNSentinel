import base64

PROTOCOL_NAME = "DNSentinel"
PROTOCOL_VERSION = 1

MAX_CLIENT_ID_LENGTH = 16
MAX_SESSION_ID_LENGTH = 32
MAX_PAYLOAD_LENGTH = 512

FLAG_DATA = "DATA"
FLAG_ACK = "ACK"
FLAG_START = "START"
FLAG_END = "END"


class Packet:

    def __init__(
        self,
        client_id,
        session_id,
        sequence,
        total_fragments,
        flags,
        payload
    ):

        if len(client_id) > MAX_CLIENT_ID_LENGTH:
            raise ValueError("Client ID is too long")

        if len(session_id) > MAX_SESSION_ID_LENGTH:
            raise ValueError("Session ID is too long")

        if total_fragments <= 0:
            raise ValueError(
                "Total fragments must be greater than zero"
            )

        if sequence <= 0:
            raise ValueError(
                "Sequence must be greater than zero"
            )

        if sequence > total_fragments:
            raise ValueError(
                "Sequence cannot exceed total fragments"
            )

        if len(payload) > MAX_PAYLOAD_LENGTH:
            raise ValueError("Payload is too large")

        self.version = PROTOCOL_VERSION
        self.client_id = client_id
        self.session_id = session_id
        self.sequence = sequence
        self.total_fragments = total_fragments
        self.flags = flags
        self.payload = payload

    def serialize(self):

        payload_length = len(self.payload)

        return (
            f"{self.version}|"
            f"{self.client_id}|"
            f"{self.session_id}|"
            f"{self.sequence}|"
            f"{self.total_fragments}|"
            f"{self.flags}|"
            f"{payload_length}|"
            f"{self.payload}"
        )

    @staticmethod
    def deserialize(data):

        parts = data.split("|", 7)

        if len(parts) != 8:
            raise ValueError(
                "Invalid DNSentinel packet format"
            )

        version = int(parts[0])
        client_id = parts[1]
        session_id = parts[2]
        sequence = int(parts[3])
        total_fragments = int(parts[4])
        flags = parts[5]
        payload_length = int(parts[6])
        payload = parts[7]

        if version != PROTOCOL_VERSION:
            raise ValueError(
                f"Unsupported protocol version: {version}"
            )

        if payload_length != len(payload):
            raise ValueError(
                "Payload length mismatch"
            )

        return Packet(
            client_id=client_id,
            session_id=session_id,
            sequence=sequence,
            total_fragments=total_fragments,
            flags=flags,
            payload=payload
        )

    def encode_base32(self):

        serialized = self.serialize()

        encoded = base64.b32encode(
            serialized.encode("utf-8")
        ).decode("ascii")

        return encoded.rstrip("=").lower()

    @staticmethod
    def decode_base32(encoded_data):

        encoded_data = encoded_data.upper()

        padding = "=" * (
            (8 - len(encoded_data) % 8) % 8
        )

        encoded_data += padding

        try:

            decoded = base64.b32decode(
                encoded_data
            ).decode("utf-8")

        except Exception as e:

            raise ValueError(
                f"Invalid Base32 data: {e}"
            )

        return Packet.deserialize(decoded)

    def __repr__(self):

        return (
            f"Packet("
            f"client_id={self.client_id}, "
            f"session_id={self.session_id}, "
            f"sequence={self.sequence}, "
            f"total_fragments={self.total_fragments}, "
            f"flags={self.flags}, "
            f"payload={self.payload!r}"
            f")"
        )