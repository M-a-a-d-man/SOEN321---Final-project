# protocol.py
# Defines the message format for our secure chat protocol.
#
# Every message has a fixed-size header followed by a variable-length payload.
# The header tells you what type of message it is, which tells you how to
# deserialize the payload. Keeping the header fixed-size makes parsing easier
# since you always know exactly how many bytes to read before you know
# anything else about the message.
#
# Header (45 bytes, big-endian):
#   1 byte  - message type
#  16 bytes - sender id
#  16 bytes - recipient id
#   8 bytes - timestamp (ms)
#   4 bytes - payload length

from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from enum import IntEnum


HEADER_FORMAT = "!B16s16sQI"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 45 bytes


class MessageType(IntEnum):
    # client sends its public key so the other side can encrypt the session key
    KEY_EXCHANGE = 0x01
    # server sends the session key, encrypted with the recipient's public key
    SESSION_INIT = 0x02
    CHAT = 0x03       # actual message, encrypted + signed
    ACK = 0x04        # let the sender know the message arrived
    ERROR = 0x05
    DISCONNECT = 0x06


@dataclass(frozen=True)
class Header:
    message_type:   MessageType
    sender_id:      bytes  # 16 bytes
    recipient_id:   bytes  # 16 bytes
    timestamp:      int    # unix ms
    payload_length: int

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
        if not (0 <= self.payload_length <= 0xFFFFFFFF):
            raise ValueError("payload_length out of range for uint32")

    def to_bytes(self) -> bytes:
        return struct.pack(
            HEADER_FORMAT,
            int(self.message_type),
            self.sender_id,
            self.recipient_id,
            self.timestamp,
            self.payload_length,
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> Header:
        if len(data) < HEADER_SIZE:
            raise ValueError(
                f"need {HEADER_SIZE} bytes for header, got {len(data)}"
            )
        fields = struct.unpack(HEADER_FORMAT, data[:HEADER_SIZE])
        msg_type_raw, sender_id, recipient_id, timestamp, payload_length = (
            fields
        )
        return cls(
            message_type=MessageType(msg_type_raw),
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=timestamp,
            payload_length=payload_length,
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
    ) -> Message:
        # default to now so callers don't have to think about it
        ts = timestamp if timestamp is not None else int(time.time() * 1000)
        header = Header(
            message_type=message_type,
            sender_id=sender_id,
            recipient_id=recipient_id,
            timestamp=ts,
            payload_length=len(payload),
        )
        return cls(header=header, payload=bytes(payload))

    def to_bytes(self) -> bytes:
        return self.header.to_bytes() + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> Message:
        header = Header.from_bytes(data)
        payload = data[HEADER_SIZE: HEADER_SIZE + header.payload_length]
        if len(payload) != header.payload_length:
            raise ValueError("message was truncated mid-payload")
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
    # the AES key is encrypted with the recipient's RSA public key
    # so only they can read it
    encrypted_session_key: bytes

    def __post_init__(self) -> None:
        if not isinstance(self.encrypted_session_key, (bytes, bytearray)):
            raise TypeError("encrypted_session_key must be bytes")
        if not self.encrypted_session_key:
            raise ValueError("encrypted_session_key is empty")

    def to_bytes(self) -> bytes:
        return (
            struct.pack("!I", len(self.encrypted_session_key))
            + self.encrypted_session_key
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> SessionInitPayload:
        enc_key, _ = _read_blob(data, 0)
        return cls(encrypted_session_key=enc_key)


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


AnyPayload = (
    KeyExchangePayload
    | SessionInitPayload
    | ChatPayload
    | AckPayload
    | ErrorPayload
    | DisconnectPayload
)

_PAYLOAD_REGISTRY: dict[MessageType, type] = {
    MessageType.KEY_EXCHANGE: KeyExchangePayload,
    MessageType.SESSION_INIT: SessionInitPayload,
    MessageType.CHAT:         ChatPayload,
    MessageType.ACK:          AckPayload,
    MessageType.ERROR:        ErrorPayload,
    MessageType.DISCONNECT:   DisconnectPayload,
}


def parse_payload(message_type: MessageType, payload: bytes) -> AnyPayload:
    """Deserialize payload bytes into the right class for this message type."""
    if not isinstance(message_type, MessageType):
        raise TypeError(
            f"message_type must be a MessageType, got {type(message_type)}"
        )
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError(
            f"payload must be bytes, got {type(payload)}"
        )

    payload_cls = _PAYLOAD_REGISTRY.get(message_type)
    if payload_cls is None:
        raise KeyError(f"unknown message type: {message_type!r}")

    return payload_cls.from_bytes(payload)
