"""Secure chat client.

Interactive REPL. On startup, prompts for a name, loads (or creates) an RSA
keypair under keys/<name>_{private,public}.pem, derives user_id as
sha256(public_key_pem)[:16], connects to the server, registers, and then
either creates a room or joins one with a 6-char code. All chat traffic is
AES-256-GCM encrypted under a per-session key that the joiner generates and
wraps with the creator's RSA public key; every CHAT frame is signed with
RSA-PSS and verified on the other side.
"""

import os
import socket
import sys
import threading
from hashlib import sha256

from protocol import (
    HEADER_SIZE,
    Header,
    Message,
    MessageType,
    KeyExchangePayload,
    SessionInitPayload,
    ChatPayload,
    AckPayload,
    ErrorPayload,
    JoinResponsePayload,
    JoinRequestPayload,
    DisconnectPayload,
)
from crypto import CryptoUtils

SERVER_ID = b"\x00" * 16
SERVER_HOST = "localhost"
SERVER_PORT = 5000
KEYS_DIR = "keys"

_kx = CryptoUtils.KeyExchange()
_sym = CryptoUtils.SymmetricEncryption()
_signer = CryptoUtils.Signing()


class ClientState:
    def __init__(self) -> None:
        self.sock: socket.socket | None = None
        self.priv = None
        self.pub = None
        self.pub_pem: bytes = b""
        self.user_id: bytes = b""

        self.peer_id: bytes | None = None
        self.peer_pubkey = None
        self.session_key: bytes | None = None
        self.join_code: str | None = None

        self.ack_event = threading.Event()
        self.join_code_event = threading.Event()
        self.peer_pubkey_event = threading.Event()
        self.session_init_event = threading.Event()

        self.running = True
        self.error: str | None = None


def load_or_create_keys(name: str):
    os.makedirs(KEYS_DIR, exist_ok=True)
    priv_path = os.path.join(KEYS_DIR, f"{name}_private.pem")
    pub_path = os.path.join(KEYS_DIR, f"{name}_public.pem")
    if os.path.exists(priv_path):
        priv = CryptoUtils.KeyExchange.load_private_key(priv_path)
        pub = priv.public_key()
        print(f"Loaded existing key pair from {priv_path}")
    else:
        priv, pub = _kx.generate_rsa_key_pair()
        CryptoUtils.KeyExchange.save_private_key(priv, priv_path)
        CryptoUtils.KeyExchange.save_public_key(pub, pub_path)
        print(f"Generated new key pair at {priv_path}")
    return priv, pub


def send(state: ClientState, msg_type: MessageType, recipient_id: bytes, payload: bytes) -> None:
    msg = Message.build(
        message_type=msg_type,
        sender_id=state.user_id,
        recipient_id=recipient_id,
        payload=payload,
    )
    state.sock.sendall(msg.to_bytes())


def wait_for(event: threading.Event, state: ClientState, timeout: float = 15.0) -> None:
    if not event.wait(timeout=timeout):
        raise TimeoutError("Server did not respond in time")
    event.clear()
    if state.error is not None:
        err, state.error = state.error, None
        raise RuntimeError(err)


def handle(msg: Message, state: ClientState) -> None:
    h = msg.header
    t = h.message_type

    if t == MessageType.ACK:
        state.ack_event.set()

    elif t == MessageType.ERROR:
        err = ErrorPayload.from_bytes(msg.payload)
        state.error = f"[{err.error_code}] {err.message}"
        print(f"\n[server error] {state.error}")
        # unblock any pending handshake wait
        state.ack_event.set()
        state.join_code_event.set()
        state.peer_pubkey_event.set()
        state.session_init_event.set()

    elif t == MessageType.JOIN_RESPONSE:
        state.join_code = JoinResponsePayload.from_bytes(msg.payload).join_code
        state.join_code_event.set()

    elif t == MessageType.KEY_EXCHANGE:
        pem = KeyExchangePayload.from_bytes(msg.payload).public_key_pem
        state.peer_pubkey = CryptoUtils.KeyExchange.public_key_from_bytes(pem)
        state.peer_pubkey_event.set()

    elif t == MessageType.SESSION_INIT:
        state.peer_id = h.sender_id
        enc_key = SessionInitPayload.from_bytes(msg.payload).encrypted_session_key
        state.session_key = CryptoUtils.KeyExchange.rsa_decrypt_session_key(enc_key, state.priv)
        state.session_init_event.set()

    elif t == MessageType.CHAT:
        if state.peer_pubkey is None or state.session_key is None:
            print("\n[warn] chat before session ready, dropping")
            return
        chat = ChatPayload.from_bytes(msg.payload)
        if not _signer.verify(state.peer_pubkey, chat.ciphertext, chat.signature):
            print("\n[warn] signature verification failed, dropping")
            return
        try:
            plaintext = _sym.decrypt(state.session_key, chat.ciphertext).decode("utf-8")
        except Exception as e:
            print(f"\n[warn] decrypt failed: {e}")
            return
        sys.stdout.write(f"\n[peer] {plaintext}\n> ")
        sys.stdout.flush()
        try:
            send(
                state,
                MessageType.ACK,
                state.peer_id,
                AckPayload(acked_timestamp=h.timestamp).to_bytes(),
            )
        except OSError:
            pass

    elif t == MessageType.DISCONNECT:
        print("\n[peer disconnected]")
        state.running = False


def network_loop(state: ClientState) -> None:
    buf = b""
    while state.running:
        try:
            data = state.sock.recv(4096)
        except OSError:
            break
        if not data:
            break
        buf += data
        while len(buf) >= HEADER_SIZE:
            header = Header.from_bytes(buf[:HEADER_SIZE])
            total = HEADER_SIZE + header.payload_length
            if len(buf) < total:
                break
            msg = Message.from_bytes(buf[:total])
            buf = buf[total:]
            try:
                handle(msg, state)
            except Exception as e:
                print(f"\n[handler error] {e}")
    state.running = False


def register(state: ClientState) -> None:
    send(
        state,
        MessageType.KEY_EXCHANGE,
        SERVER_ID,
        KeyExchangePayload(public_key_pem=state.pub_pem).to_bytes(),
    )
    wait_for(state.ack_event, state)
    print(f"Registered. Your id: {state.user_id.hex()}")


def lookup_peer_pubkey(state: ClientState) -> None:
    # server ignores the payload for a lookup, but the payload class requires
    # non-empty pem, so just resend our own; the server only reads recipient_id
    send(
        state,
        MessageType.KEY_EXCHANGE,
        state.peer_id,
        KeyExchangePayload(public_key_pem=state.pub_pem).to_bytes(),
    )
    wait_for(state.peer_pubkey_event, state)


def create_room(state: ClientState) -> None:
    send(state, MessageType.JOIN_CREATE, SERVER_ID, b"")
    wait_for(state.join_code_event, state)
    print()
    print(f"Join code: {state.join_code}")
    print(f"Your id:   {state.user_id.hex()}")
    print("Share BOTH the code and the id with your peer (out of band).")
    print()
    print("Waiting for peer to connect (up to 10 min)...")
    wait_for(state.session_init_event, state, timeout=600.0)
    lookup_peer_pubkey(state)
    print(f"Session established with {state.peer_id.hex()}")


def join_room(state: ClientState) -> None:
    code = input("Join code: ").strip()
    peer_hex = input("Peer id (hex): ").strip()
    try:
        peer_id = bytes.fromhex(peer_hex)
    except ValueError:
        raise RuntimeError("Invalid peer id (must be hex)")
    if len(peer_id) != 16:
        raise RuntimeError("Peer id must be 16 bytes (32 hex chars)")
    state.peer_id = peer_id

    send(
        state,
        MessageType.JOIN_REQUEST,
        SERVER_ID,
        JoinRequestPayload(join_code=code).to_bytes(),
    )
    wait_for(state.ack_event, state)
    print("Linked.")

    lookup_peer_pubkey(state)

    state.session_key = _sym.generate_aes_key()
    wrapped = CryptoUtils.KeyExchange.rsa_encrypt_session_key(
        state.session_key, state.peer_pubkey
    )
    send(
        state,
        MessageType.SESSION_INIT,
        state.peer_id,
        SessionInitPayload(encrypted_session_key=wrapped).to_bytes(),
    )
    print(f"Session established with {state.peer_id.hex()}")


def chat_loop(state: ClientState) -> None:
    print()
    print("Chat ready. Type messages and hit enter. /quit to exit.")
    print()
    while state.running:
        try:
            line = input("> ")
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not line:
            continue
        if line.strip() == "/quit":
            break
        ciphertext = _sym.encrypt(state.session_key, line.encode("utf-8"))
        signature = _signer.sign(state.priv, ciphertext)
        payload = ChatPayload(ciphertext=ciphertext, signature=signature).to_bytes()
        try:
            send(state, MessageType.CHAT, state.peer_id, payload)
        except OSError:
            print("[disconnected]")
            break


def disconnect(state: ClientState) -> None:
    try:
        send(
            state,
            MessageType.DISCONNECT,
            SERVER_ID,
            DisconnectPayload(reason="user quit").to_bytes(),
        )
    except Exception:
        pass
    state.running = False
    try:
        if state.sock is not None:
            state.sock.close()
    except Exception:
        pass


def main() -> None:
    state = ClientState()

    name = input("name: ").strip() or "default"
    state.priv, state.pub = load_or_create_keys(name)
    state.pub_pem = CryptoUtils.KeyExchange.public_key_to_bytes(state.pub)
    state.user_id = sha256(state.pub_pem).digest()[:16]

    state.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        state.sock.connect((SERVER_HOST, SERVER_PORT))
    except OSError as e:
        print(f"Could not connect to {SERVER_HOST}:{SERVER_PORT}: {e}")
        return
    print(f"Connected to {SERVER_HOST}:{SERVER_PORT}")

    t = threading.Thread(target=network_loop, args=(state,), daemon=True)
    t.start()

    try:
        register(state)
        mode = input("create or join? [create/join]: ").strip().lower()
        if mode == "create":
            create_room(state)
        elif mode == "join":
            join_room(state)
        else:
            print("Unknown option")
            return
        chat_loop(state)
    except (RuntimeError, TimeoutError) as e:
        print(f"[fatal] {e}")
    finally:
        disconnect(state)


if __name__ == "__main__":
    main()
