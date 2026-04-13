# protocol.py
# Defines the message format for our secure chat protocol.
#
# Every message has a fixed-size header followed by a variable-length payload.
# The header tells you what type of message it is, which tells you how to
# deserialize the payload. Keeping the header fixed-size makes parsing easier
# since you always know exactly how many bytes to read before you know
# anything else about the message.
#

from __future__ import annotations

import hashlib
import struct
import time
from dataclasses import dataclass
from enum import IntEnum


# Header layout (big-endian):
#   1 byte  - message type
#  16 bytes - sender id
#  16 bytes - recipient id
#   8 bytes - timestamp (unix ms)
#   8 bytes - sequence number (per-sender monotonic counter, replay protection)
#   4 bytes - payload length
#  32 bytes - SHA-256 of payload (data integrity)
HEADER_FORMAT = "!B16s16sQQI32s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 85 bytes


class MessageType(IntEnum):
    KEY_EXCHANGE = 0x01   # client registers its public key with the server
    SESSION_INIT = 0x02   # joiner sends ephemeral pub key + signature to creator
    CHAT = 0x03           # actual message, AES-256-GCM encrypted + RSA-PSS signed
    ACK = 0x04            # let the sender know the message arrived
    ERROR = 0x05
    DISCONNECT = 0x06
    JOIN_CREATE = 0x07    # client wants to create a new room
    JOIN_RESPONSE = 0x08  # server replies with the generated join code
    JOIN_REQUEST = 0x09   # client wants to join an existing room by code
    SESSION_ACCEPT = 0x0A # creator replies with its ephemeral pub key + signature


@dataclass(frozen=True)
class Header:
    message_type:    MessageType
    sender_id:       bytes  # 16 bytes
    recipient_id:    bytes  # 16 bytes
    timestamp:       int    # unix ms
    sequence_number: int    # per-sender monotonic counter (replay protection)
    payload_length:  int
    payload_hash:    bytes  # SHA-256 of payload (data integrity, 32 bytes)

    def __post_init__(self) -> None:
        if not isinstance(self.message_type, MessageType):
            raise TypeError(
                f"message_type must be a MessageType, "
                f"got {type(self.message_type)}"
            )
        if len(self.sender_id) != 16:
            raise ValueError(
                f"sender_id must be 16 bytes, got {len(self.sender_id)}"
            )
        if len(self.recipient_id) != 16:
            raise ValueError(
                f"recipient_id must be 16 bytes, "
                f"got {len(self.recipient_id)}"
            )
        if not (0 <= self.timestamp <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("timestamp out of range for uint64")
        if not (0 <= self.sequence_number <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("sequence_number out of range for uint64")
        if not (0 <= self.payload_length <= 0xFFFFFFFF):
            raise ValueError("payload_length out of range for uint32")
        if len(self.payload_hash) != 32:
            raise ValueError(
                f"payload_hash must be 32 bytes, got {len(self.payload_hash)}"
            )

    def to_bytes(self) -> bytes:
        return struct.pack(
            HEADER_FORMAT,
            int(self.message_type),
            self.sender_id,
            self.recipient_id,
            self.timestamp,
            self.sequence_number,
            self.payload_length,
            self.payload_hash,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Header:
        if len(data) < HEADER_SIZE:
            raise ValueError(
                f"need {HEADER_SIZE} bytes for header, got {len(data)}"
            )
        fields = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        (
            msg_type_raw, sender_id, recipient_id,
            timestamp, sequence_number, payload_length, payload_hash,
        ) = fields
        return cls(
            message_type=MessageType(msg_type_raw),
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=timestamp,
            sequence_number=sequence_number,
            payload_length=payload_length,
            payload_hash=payload_hash,
        )


@dataclass(frozen=True)
class Message:
    header:  Header
    payload: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.header, Header):
            raise TypeError("header must be a Header instance")
        if not isinstance(self.payload, (bytes, bytearray)):
            raise TypeError("payload must be bytes")
        # sanity check so a corrupt header doesn't cause weird bugs downstream
        if len(self.payload) != self.header.payload_length:
            raise ValueError(
                f"payload length mismatch: header says "
                f"{self.header.payload_length}, actual is {len(self.payload)}"
            )

    @classmethod
    def build(
        cls,
        message_type: MessageType,
        sender_id: bytes,
        recipient_id: bytes,
        payload: bytes,
        timestamp: int | None = None,
        sequence_number: int = 0,
    ) -> Message:
        # default to now so callers don't have to think about it
        ts = timestamp if timestamp is not None else int(time.time() * 1000)
        payload_bytes = bytes(payload)
        payload_hash = hashlib.sha256(payload_bytes).digest()
        header = Header(
            message_type=message_type,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=ts,
            sequence_number=sequence_number,
            payload_length=len(payload_bytes),
            payload_hash=payload_hash,
        )
        return cls(header=header, payload=payload_bytes)

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Message:
        header = Header.from_bytes(data)
        payload = data[HEADER_SIZE: HEADER_SIZE + header.payload_length]
        if len(payload) != header.payload_length:
            raise ValueError("message was truncated mid-payload")
        computed_hash = hashlib.sha256(payload).digest()
        if computed_hash != header.payload_hash:
            raise ValueError(
                "payload hash mismatch — data integrity check failed"
            )
        return cls(header=header, payload=payload)


# Each payload type knows how to serialize/deserialize itself.
# Using length-prefixed fields so we can handle variable-size data
# without needing delimiters or fixed maximums.


def _read_blob(data: bytes, offset: int) -> tuple[bytes, int]:
    # reads a uint32-length-prefixed blob; returns (blob, new_offset)
    # used by all the payload from_bytes methods to avoid repeating this logic
    if len(data) < offset + 4:
        raise ValueError("data too short to read blob length")
    length, = struct.unpack("!I", data[offset: offset + 4])
    offset += 4
    blob = data[offset: offset + length]
    if len(blob) != length:
        raise ValueError("truncated blob")
    return bytes(blob), offset + length


@dataclass(frozen=True)
class KeyExchangePayload:
    # PEM format so it's easy to pass directly into the crypto layer
    public_key_pem: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.public_key_pem, (bytes, bytearray)):
            raise TypeError("public_key_pem must be bytes")
        if not self.public_key_pem:
            raise ValueError("public_key_pem is empty")

    def to_bytes(self) -> bytes:
        return (
            struct.pack("!I", len(self.public_key_pem)) + self.public_key_pem
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> KeyExchangePayload:
        pem, _ = _read_blob(data, 0)
        return cls(public_key_pem=pem)


@dataclass(frozen=True)
class SessionInitPayload:
    # Joiner's X25519 ephemeral public key (raw 32 bytes) + RSA-PSS signature
    # over that key using the joiner's long-term private key.  The creator
    # verifies the signature before accepting the ECDH handshake.
    ephemeral_pubkey: bytes  # 32-byte raw X25519 public key
    signature:        bytes  # RSA-PSS over ephemeral_pubkey

    def __post_init__(self) -> None:
        if not isinstance(self.ephemeral_pubkey, (bytes, bytearray)):
            raise TypeError("ephemeral_pubkey must be bytes")
        if len(self.ephemeral_pubkey) != 32:
            raise ValueError(
                f"ephemeral_pubkey must be 32 bytes, got {len(self.ephemeral_pubkey)}"
            )
        if not isinstance(self.signature, (bytes, bytearray)):
            raise TypeError("signature must be bytes")
        if not self.signature:
            raise ValueError("signature is empty")

    def to_bytes(self) -> bytes:
        return (
            self.ephemeral_pubkey
            + struct.pack("!I", len(self.signature))
            + self.signature
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SessionInitPayload:
        if len(data) < 32:
            raise ValueError("SessionInitPayload too short")
        ephemeral_pubkey = data[:32]
        sig, _ = _read_blob(data, 32)
        return cls(ephemeral_pubkey=bytes(ephemeral_pubkey), signature=sig)


@dataclass(frozen=True)
class SessionAcceptPayload:
    # Creator's X25519 ephemeral public key (raw 32 bytes) + RSA-PSS signature
    # over that key using the creator's long-term private key.  The joiner
    # verifies the signature, then both sides derive the same session key via
    # HKDF over the ECDH shared secret.
    ephemeral_pubkey: bytes  # 32-byte raw X25519 public key
    signature:        bytes  # RSA-PSS over ephemeral_pubkey

    def __post_init__(self) -> None:
        if not isinstance(self.ephemeral_pubkey, (bytes, bytearray)):
            raise TypeError("ephemeral_pubkey must be bytes")
        if len(self.ephemeral_pubkey) != 32:
            raise ValueError(
                f"ephemeral_pubkey must be 32 bytes, got {len(self.ephemeral_pubkey)}"
            )
        if not isinstance(self.signature, (bytes, bytearray)):
            raise TypeError("signature must be bytes")
        if not self.signature:
            raise ValueError("signature is empty")

    def to_bytes(self) -> bytes:
        return (
            self.ephemeral_pubkey
            + struct.pack("!I", len(self.signature))
            + self.signature
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SessionAcceptPayload:
        if len(data) < 32:
            raise ValueError("SessionAcceptPayload too short")
        ephemeral_pubkey = data[:32]
        sig, _ = _read_blob(data, 32)
        return cls(ephemeral_pubkey=bytes(ephemeral_pubkey), signature=sig)


@dataclass(frozen=True)
class ChatPayload:
    # we sign the ciphertext so the receiver can verify authenticity
    # before decrypting
    ciphertext: bytes  # nonce prepended (first 12 bytes), from AES-GCM
    signature:  bytes  # RSA-PSS over the ciphertext

    def __post_init__(self) -> None:
        if not isinstance(self.ciphertext, (bytes, bytearray)):
            raise TypeError("ciphertext must be bytes")
        if not isinstance(self.signature, (bytes, bytearray)):
            raise TypeError("signature must be bytes")
        # AES-GCM nonce is always 12 bytes, so anything shorter is wrong
        if len(self.ciphertext) < 12:
            raise ValueError("ciphertext too short, missing nonce")
        if not self.signature:
            raise ValueError("signature is empty")

    def to_bytes(self) -> bytes:
        return (
            struct.pack("!I", len(self.ciphertext)) + self.ciphertext
            + struct.pack("!I", len(self.signature)) + self.signature
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> ChatPayload:
        ciphertext, offset = _read_blob(data, 0)
        signature, _ = _read_blob(data, offset)
        return cls(ciphertext=ciphertext, signature=signature)


@dataclass(frozen=True)
class AckPayload:
    # echo back the timestamp of the message being acknowledged
    # so the sender can match it up
    acked_timestamp: int

    def __post_init__(self) -> None:
        if not isinstance(self.acked_timestamp, int):
            raise TypeError("acked_timestamp must be an int")
        if not (0 <= self.acked_timestamp <= 0xFFFFFFFFFFFFFFFF):
            raise ValueError("acked_timestamp out of range for uint64")

    def to_bytes(self) -> bytes:
        return struct.pack("!Q", self.acked_timestamp)

    @classmethod
    def from_bytes(cls, data: bytes) -> AckPayload:
        if len(data) < 8:
            raise ValueError("AckPayload requires 8 bytes")
        ts, = struct.unpack("!Q", data[:8])
        return cls(acked_timestamp=ts)


@dataclass(frozen=True)
class ErrorPayload:
    error_code: int  # uint16
    message:    str

    def __post_init__(self) -> None:
        if not isinstance(self.error_code, int):
            raise TypeError("error_code must be an int")
        if not (0 <= self.error_code <= 0xFFFF):
            raise ValueError("error_code out of range for uint16")
        if not isinstance(self.message, str):
            raise TypeError("message must be a str")

    def to_bytes(self) -> bytes:
        encoded = self.message.encode("utf-8")
        return struct.pack("!HH", self.error_code, len(encoded)) + encoded

    @classmethod
    def from_bytes(cls, data: bytes) -> ErrorPayload:
        if len(data) < 4:
            raise ValueError("ErrorPayload too short")
        error_code, msg_len = struct.unpack("!HH", data[:4])
        message_bytes = data[4: 4 + msg_len]
        if len(message_bytes) != msg_len:
            raise ValueError("truncated error message")
        return cls(
            error_code=error_code,
            message=message_bytes.decode("utf-8"),
        )


@dataclass(frozen=True)
class DisconnectPayload:
    reason: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.reason, str):
            raise TypeError("reason must be a str")

    def to_bytes(self) -> bytes:
        encoded = self.reason.encode("utf-8")
        return struct.pack("!H", len(encoded)) + encoded

    @classmethod
    def from_bytes(cls, data: bytes) -> DisconnectPayload:
        if len(data) < 2:
            return cls(reason="")
        reason_len, = struct.unpack("!H", data[:2])
        reason_bytes = data[2: 2 + reason_len]
        if len(reason_bytes) != reason_len:
            raise ValueError("truncated disconnect reason")
        return cls(reason=reason_bytes.decode("utf-8"))


@dataclass(frozen=True)
class JoinCreatePayload:
    # no data needed — the server generates everything for the new room
    def to_bytes(self) -> bytes:
        return b""

    @classmethod
    def from_bytes(cls, _: bytes) -> JoinCreatePayload:
        return cls()


@dataclass(frozen=True)
class JoinResponsePayload:
    # server sends back the join code so the client can share it
    join_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.join_code, str):
            raise TypeError("join_code must be a str")
        if not self.join_code:
            raise ValueError("join_code is empty")

    def to_bytes(self) -> bytes:
        encoded = self.join_code.encode("utf-8")
        return struct.pack("!H", len(encoded)) + encoded

    @classmethod
    def from_bytes(cls, data: bytes) -> JoinResponsePayload:
        if len(data) < 2:
            raise ValueError("JoinResponsePayload too short")
        code_len, = struct.unpack("!H", data[:2])
        code_bytes = data[2: 2 + code_len]
        if len(code_bytes) != code_len:
            raise ValueError("truncated join_code")
        return cls(join_code=code_bytes.decode("utf-8"))


@dataclass(frozen=True)
class JoinRequestPayload:
    # client sends the code it received out-of-band to get into a room
    join_code: str

    def __post_init__(self) -> None:
        if not isinstance(self.join_code, str):
            raise TypeError("join_code must be a str")
        if not self.join_code:
            raise ValueError("join_code is empty")

    def to_bytes(self) -> bytes:
        encoded = self.join_code.encode("utf-8")
        return struct.pack("!H", len(encoded)) + encoded

    @classmethod
    def from_bytes(cls, data: bytes) -> JoinRequestPayload:
        if len(data) < 2:
            raise ValueError("JoinRequestPayload too short")
        code_len, = struct.unpack("!H", data[:2])
        code_bytes = data[2: 2 + code_len]
        if len(code_bytes) != code_len:
            raise ValueError("truncated join_code")
        return cls(join_code=code_bytes.decode("utf-8"))
