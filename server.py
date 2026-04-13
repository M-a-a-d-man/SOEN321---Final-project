from __future__ import annotations

import socket
import selectors
import time
import types
import secrets
import string

from crypto import CryptoUtils
from protocol import (
    HEADER_SIZE,
    Header,
    Message,
    MessageType,
    KeyExchangePayload,
    AckPayload,
    ErrorPayload,
    JoinResponsePayload,
    JoinRequestPayload,
)

SERVER_ID = b'\x00' * 16

# server state
# Maps user_id to their public key PEM
public_keys: dict[bytes, bytes] = {}
# Maps user_id to their selector key
connections: dict[bytes, selectors.SelectorKey] = {}
# Maps join codes to the user_id that created them
join_codes: dict[str, bytes] = {}
# Set of frozensets containing pairs of linked user_ids
linked_pairs: set[frozenset] = set()
# Per-sender last seen sequence number (replay protection)
last_seq: dict[bytes, int] = {}

sel = selectors.DefaultSelector()

# Lets assume join code is 6 digit alphanumeric string we can discuss further but should be
def generate_join_code() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(6))


def send_to_client(user_id: bytes, msg: Message):
    key = connections.get(user_id)
    if key is None:
        return
    key.data.outb += msg.to_bytes()


def send_error(sender_id: bytes, error_code: int, message: str, key: selectors.SelectorKey | None = None):
    payload = ErrorPayload(error_code=error_code, message=message)
    msg = Message.build(
        message_type=MessageType.ERROR,
        sender_id=SERVER_ID,
        recipient_id=sender_id,
        payload=payload.to_bytes(),
    )
    # if we have a direct key (e.g. the client isn't registered yet), write
    # straight to its outbound buffer instead of routing through the
    # connections dict which only has registered users
    if key is not None:
        key.data.outb += msg.to_bytes()
    else:
        send_to_client(sender_id, msg)


def are_linked(user_a: bytes, user_b: bytes) -> bool:
    return frozenset({user_a, user_b}) in linked_pairs


def handle_message(key: selectors.SelectorKey, message: Message):
    header = message.header
    sender_id = header.sender_id
    recipient_id = header.recipient_id

    # --- Timestamp validation -------------------------------------------
    # Reject messages whose timestamp is more than 60 seconds off from
    # server time to limit the replay window.
    now_ms = int(time.time() * 1000)
    if abs(now_ms - header.timestamp) > 60_000:
        send_error(sender_id, 9, "Timestamp outside acceptable window", key=key)
        return

    # --- Sequence number replay protection --------------------------------
    # Every sender must use strictly increasing sequence numbers.  The check
    # is skipped for the very first message from a sender (no prior record),
    # but once a sequence number is recorded all subsequent ones must exceed it.
    last = last_seq.get(sender_id)
    if last is not None and header.sequence_number <= last:
        send_error(sender_id, 8, "Replay detected: sequence number not increasing", key=key)
        return
    last_seq[sender_id] = header.sequence_number

    if header.message_type == MessageType.KEY_EXCHANGE:
        if recipient_id == SERVER_ID:
            # registration: store public key
            payload = KeyExchangePayload.from_bytes(message.payload)
            # bind user_id to the public key so clients can't claim arbitrary
            # identities
            expected_id = CryptoUtils.KeyExchange.user_id_from_pem(
                payload.public_key_pem
            )
            if sender_id != expected_id:
                send_error(sender_id, 5, "user_id does not match public key", key=key)
                return
            public_keys[sender_id] = payload.public_key_pem
            connections[sender_id] = key
            print(f"Registered user {sender_id.hex()}")

            ack = Message.build(
                message_type=MessageType.ACK,
                sender_id=SERVER_ID,
                recipient_id=sender_id,
                payload=AckPayload(acked_timestamp=header.timestamp).to_bytes(),
            )
            send_to_client(sender_id, ack)
        else:
            # key lookup: return recipient's public key
            if not are_linked(sender_id, recipient_id):
                send_error(sender_id, 3, "Not authorized")
                return
            pem = public_keys.get(recipient_id)
            if pem is None:
                send_error(sender_id, 1, "User not found")
                return
            resp_payload = KeyExchangePayload(public_key_pem=pem)
            resp = Message.build(
                message_type=MessageType.KEY_EXCHANGE,
                sender_id=recipient_id,
                recipient_id=sender_id,
                payload=resp_payload.to_bytes(),
            )
            send_to_client(sender_id, resp)

    elif header.message_type == MessageType.JOIN_CREATE:
        # generate a join code for this user
        code = generate_join_code()
        join_codes[code] = sender_id
        print(f"Created join code {code} for user {sender_id.hex()}")

        resp = Message.build(
            message_type=MessageType.JOIN_RESPONSE,
            sender_id=SERVER_ID,
            recipient_id=sender_id,
            payload=JoinResponsePayload(join_code=code).to_bytes(),
        )
        send_to_client(sender_id, resp)

    elif header.message_type == MessageType.JOIN_REQUEST:
        # client submits a join code to link with another user
        code = JoinRequestPayload.from_bytes(message.payload).join_code
        target_id = join_codes.get(code)
        if target_id is None:
            send_error(sender_id, 4, "Invalid join code")
            return
        linked_pairs.add(frozenset({sender_id, target_id}))
        del join_codes[code]  # one-time use
        print(f"Linked {sender_id.hex()} with {target_id.hex()}")

        ack = Message.build(
            message_type=MessageType.ACK,
            sender_id=SERVER_ID,
            recipient_id=sender_id,
            payload=AckPayload(acked_timestamp=header.timestamp).to_bytes(),
        )
        send_to_client(sender_id, ack)

    elif header.message_type in (
        MessageType.SESSION_INIT, MessageType.SESSION_ACCEPT,
        MessageType.CHAT, MessageType.ACK,
    ):
        # forward to recipient as-is
        if not are_linked(sender_id, recipient_id):
            send_error(sender_id, 3, "Not authorized")
            return
        if recipient_id not in connections:
            send_error(sender_id, 2, "User offline")
            return
        send_to_client(recipient_id, message)

    elif header.message_type == MessageType.DISCONNECT:
        cleanup_user(sender_id)

    elif header.message_type == MessageType.ERROR:
        if recipient_id in connections:
            send_to_client(recipient_id, message)


def cleanup_user(user_id: bytes):
    connections.pop(user_id, None)
    public_keys.pop(user_id, None)
    last_seq.pop(user_id, None)
    codes_to_remove = [code for code, uid in join_codes.items() if uid == user_id]
    for code in codes_to_remove:
        del join_codes[code]
    to_remove = [pair for pair in linked_pairs if user_id in pair]
    for pair in to_remove:
        linked_pairs.discard(pair)


def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)


def service_connection(key, mask):
    sock = key.fileobj
    data = key.data

    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(4096)
        if recv_data:
            data.inb += recv_data

            while True:
                if len(data.inb) < HEADER_SIZE:
                    break

                header = Header.from_bytes(data.inb[:HEADER_SIZE])
                total = HEADER_SIZE + header.payload_length

                if len(data.inb) < total:
                    break

                message = Message.from_bytes(data.inb[:total])
                data.inb = data.inb[total:]

                handle_message(key, message)
        else:
            print(f"Closing connection to {data.addr}")
            user_id = None
            for uid, k in connections.items():
                if k is key:
                    user_id = uid
                    break
            if user_id:
                cleanup_user(user_id)
            sel.unregister(sock)
            sock.close()

    if mask & selectors.EVENT_WRITE:
        if data.outb:
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]


host, port = "localhost", 5000
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((host, port))
lsock.listen()
print(f"Listening on {(host, port)}")
lsock.setblocking(False)
sel.register(lsock, selectors.EVENT_READ, data=None)

try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)
except KeyboardInterrupt:
    print("Caught keyboard interrupt, exiting")
finally:
    sel.close()
