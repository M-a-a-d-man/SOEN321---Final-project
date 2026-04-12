from __future__ import annotations
"""Comprehensive verification harness.

Runs 7 scenarios against the real server and reports PASS/FAIL for each:

  1. Key persistence across runs (same name -> same user_id)
  2. Bidirectional multi-message chat
  3. Wrong join code error path
  4. Clean /quit disconnect (observes what the peer sees)
  5. Unicode messages round-trip through AES-GCM
  6. Server-side id-binding enforcement (raw socket, wrong id)
  7. Client-side malformed-header guard (socketpair injection)
"""

import os
import re
import select
import socket
import subprocess
import sys
import threading
import time

SERVER_HOST = "localhost"
SERVER_PORT = 5000
KEYS_DIR = "keys"

results: list[tuple[str, bool, str]] = []


def banner(title: str) -> None:
    print(f"\n{'='*70}\n{title}\n{'='*70}")


def record(name: str, ok: bool, note: str = "") -> None:
    results.append((name, ok, note))
    tag = "PASS" if ok else "FAIL"
    print(f"  [{tag}] {name}" + (f" — {note}" if note else ""))


def rm_keys(*names: str) -> None:
    for n in names:
        for suffix in ("_private.pem", "_public.pem"):
            p = os.path.join(KEYS_DIR, n + suffix)
            if os.path.exists(p):
                os.remove(p)


def start_server() -> subprocess.Popen:
    p = subprocess.Popen(
        [sys.executable, "-u", "server.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    for _ in range(50):
        try:
            s = socket.socket()
            s.settimeout(0.1)
            s.connect((SERVER_HOST, SERVER_PORT))
            s.close()
            return p
        except OSError:
            time.sleep(0.1)
    p.kill()
    raise RuntimeError("server never came up")


_buffers: dict[int, str] = {}


def spawn_client() -> subprocess.Popen:
    p = subprocess.Popen(
        [sys.executable, "-u", "client.py"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0,
    )
    _buffers[p.pid] = ""
    return p


def send_line(p: subprocess.Popen, s: str) -> None:
    p.stdin.write((s + "\n").encode("utf-8"))
    p.stdin.flush()


def _drain_once(p: subprocess.Popen, timeout: float) -> None:
    """Pull any available stdout into the per-process buffer."""
    end = time.time() + timeout
    fd = p.stdout.fileno()
    while time.time() < end:
        remaining = max(0.0, end - time.time())
        ready, _, _ = select.select([fd], [], [], remaining)
        if not ready:
            return
        chunk = os.read(fd, 4096)
        if not chunk:
            return
        _buffers[p.pid] += chunk.decode("utf-8", errors="replace")
        # after first read, only keep collecting if more is immediately ready
        ready, _, _ = select.select([fd], [], [], 0.02)
        if not ready:
            return


def read_until(p: subprocess.Popen, needle: str, timeout: float = 10.0) -> str | None:
    """Wait until `needle` appears in the per-process buffer; return the
    portion of the buffer consumed up through and including the needle
    and leave any trailing bytes in the buffer for the next call."""
    end = time.time() + timeout
    while time.time() < end:
        buf = _buffers[p.pid]
        idx = buf.find(needle)
        if idx != -1:
            cut = idx + len(needle)
            consumed, rest = buf[:cut], buf[cut:]
            _buffers[p.pid] = rest
            return consumed
        _drain_once(p, end - time.time())
    # one last look after timeout drain
    buf = _buffers[p.pid]
    idx = buf.find(needle)
    if idx != -1:
        cut = idx + len(needle)
        _buffers[p.pid] = buf[cut:]
        return buf[:cut]
    return None


def read_for(p: subprocess.Popen, seconds: float) -> str:
    _drain_once(p, seconds)
    buf, _buffers[p.pid] = _buffers[p.pid], ""
    return buf


def pair_up(alice_name: str, bob_name: str) -> tuple[subprocess.Popen, subprocess.Popen, str]:
    rm_keys(alice_name, bob_name)
    alice = spawn_client()
    alice.stdin.write(f"{alice_name}\ncreate\n".encode())
    alice.stdin.flush()
    buf = read_until(alice, "Waiting for peer", 10)
    assert buf, "alice never reached waiting-for-peer"
    m_code = re.search(r"Join code:\s+([A-Z0-9]{6})", buf)
    m_id = re.search(r"Your id:\s+([0-9a-f]{32})", buf)
    assert m_code and m_id, f"could not parse create output:\n{buf}"
    code, alice_id = m_code.group(1), m_id.group(1)

    bob = spawn_client()
    bob.stdin.write(f"{bob_name}\njoin\n{code}\n{alice_id}\n".encode())
    bob.stdin.flush()
    assert read_until(bob, "Session established", 10), "bob never saw session"
    assert read_until(alice, "Session established", 10), "alice never saw session"
    assert read_until(bob, "Chat ready", 3), "bob never saw chat ready"
    assert read_until(alice, "Chat ready", 3), "alice never saw chat ready"
    return alice, bob, alice_id


# ---------------------------------------------------------------------------

def test_1_key_persistence() -> None:
    banner("TEST 1: Key persistence across runs")
    rm_keys("persist_test")

    a = spawn_client()
    a.stdin.write(b"persist_test\ncreate\n")
    a.stdin.flush()
    buf1 = read_until(a, "Waiting for peer", 10)
    assert buf1, "first run never reached waiting"
    m = re.search(r"Your id:\s+([0-9a-f]{32})", buf1)
    id1 = m.group(1)
    first_gen = "Generated new key pair" in buf1
    a.kill()
    time.sleep(0.5)

    b = spawn_client()
    b.stdin.write(b"persist_test\ncreate\n")
    b.stdin.flush()
    buf2 = read_until(b, "Waiting for peer", 10)
    assert buf2, "second run never reached waiting"
    m = re.search(r"Your id:\s+([0-9a-f]{32})", buf2)
    id2 = m.group(1)
    second_load = "Loaded existing key pair" in buf2
    b.kill()

    ok = (id1 == id2) and first_gen and second_load
    record(
        "key persistence",
        ok,
        f"id1={id1[:8]}... id2={id2[:8]}... gen={first_gen} load={second_load}",
    )


# ---------------------------------------------------------------------------

def test_2_multi_message() -> None:
    banner("TEST 2: Bidirectional multi-message chat")
    alice, bob, _ = pair_up("alice2", "bob2")

    pairs = [
        (bob, alice, "bob msg 1"),
        (alice, bob, "alice msg 1"),
        (bob, alice, "bob msg 2"),
        (alice, bob, "alice msg 2"),
        (bob, alice, "bob msg 3"),
        (alice, bob, "alice msg 3"),
    ]
    ok = True
    for sender, receiver, text in pairs:
        send_line(sender, text)
        got = read_until(receiver, text, 3)
        if got is None:
            ok = False
            print(f"  did not see {text!r}")
            break

    alice.kill()
    bob.kill()
    record("multi-message bidirectional", ok)


# ---------------------------------------------------------------------------

def test_3_wrong_join_code() -> None:
    banner("TEST 3: Wrong join code error path")
    rm_keys("bob3")
    bob = spawn_client()
    # any valid-looking 32-hex peer id
    bob.stdin.write(f"bob3\njoin\nBADBAD\n{'00'*16}\n".encode())
    bob.stdin.flush()
    buf = read_until(bob, "Invalid join code", 5) or ""
    buf += read_for(bob, 1.0)
    bob.kill()

    saw_error = "Invalid join code" in buf
    record("wrong join code error", saw_error, f"saw 'Invalid join code': {saw_error}")


# ---------------------------------------------------------------------------

def test_4_clean_quit() -> None:
    banner("TEST 4: Clean /quit disconnect (what does the peer see?)")
    alice, bob, _ = pair_up("alice4", "bob4")

    # exchange a message first to confirm session live
    send_line(bob, "ping")
    assert read_until(alice, "ping", 3)

    send_line(alice, "/quit")
    time.sleep(0.5)
    # bob tries to send — what happens?
    send_line(bob, "is alice still there?")
    bob_out = read_for(bob, 1.5)

    alice.kill()
    bob.kill()

    # Note: the server does NOT forward DISCONNECT to the peer. Bob may
    # see a server error ("user offline") on his next send, or nothing.
    # This test records what Bob actually observes so we can document it.
    observed_disconnect = "peer disconnected" in bob_out.lower()
    observed_error = "offline" in bob_out.lower() or "[server error]" in bob_out.lower()
    record(
        "clean /quit notifies peer",
        observed_disconnect or observed_error,
        f"peer_disc={observed_disconnect} server_err={observed_error}",
    )


# ---------------------------------------------------------------------------

def test_5_unicode() -> None:
    banner("TEST 5: Unicode messages")
    alice, bob, _ = pair_up("alice5", "bob5")

    msg = "héllo 🔐 wörld — αβγ"
    send_line(bob, msg)
    got = read_until(alice, msg, 3)
    ok = got is not None

    alice.kill()
    bob.kill()
    record("unicode round-trip", ok, f"matched: {ok}")


# ---------------------------------------------------------------------------

def test_6_id_binding() -> None:
    banner("TEST 6: Server rejects mismatched user_id")
    from protocol import (
        HEADER_SIZE, Header, Message, MessageType,
        KeyExchangePayload, ErrorPayload,
    )
    from crypto import CryptoUtils

    server_id = b"\x00" * 16
    kx = CryptoUtils.KeyExchange()
    priv, pub = kx.generate_rsa_key_pair()
    pem = CryptoUtils.KeyExchange.public_key_to_bytes(pub)
    wrong_id = b"\xff" * 16

    s = socket.socket()
    s.settimeout(3.0)
    s.connect((SERVER_HOST, SERVER_PORT))
    msg = Message.build(
        message_type=MessageType.KEY_EXCHANGE,
        sender_id=wrong_id,
        recipient_id=server_id,
        payload=KeyExchangePayload(public_key_pem=pem).to_bytes(),
    )
    s.sendall(msg.to_bytes())

    data = b""
    try:
        while len(data) < HEADER_SIZE:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        if len(data) >= HEADER_SIZE:
            header = Header.from_bytes(data[:HEADER_SIZE])
            total = HEADER_SIZE + header.payload_length
            while len(data) < total:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
    finally:
        s.close()

    if len(data) < HEADER_SIZE:
        record("id binding enforced", False, "no response")
        return
    header = Header.from_bytes(data[:HEADER_SIZE])
    if header.message_type != MessageType.ERROR:
        record("id binding enforced", False, f"got {header.message_type}")
        return
    err = ErrorPayload.from_bytes(data[HEADER_SIZE:HEADER_SIZE + header.payload_length])
    ok = err.error_code == 5
    record("id binding enforced", ok, f"error_code={err.error_code} msg={err.message!r}")


# ---------------------------------------------------------------------------

def test_7_malformed_header_guard() -> None:
    banner("TEST 7: Client bails on malformed header")
    # Run client.network_loop against a socketpair and feed garbage.
    import importlib
    client_mod = importlib.import_module("client")

    a, b = socket.socketpair()
    state = client_mod.ClientState()
    state.sock = a
    state.running = True

    # Run network_loop in a thread; it reads from a.
    t = threading.Thread(target=client_mod.network_loop, args=(state,), daemon=True)
    t.start()

    # Send a 45-byte blob whose first byte is 0xFF (invalid MessageType)
    garbage = b"\xff" + b"\x00" * (45 - 1)
    b.sendall(garbage)

    # Give the loop time to process and bail
    t.join(timeout=2.0)
    alive = t.is_alive()
    ok = (not alive) and (not state.running)
    record("malformed-header guard", ok, f"thread_alive={alive} running={state.running}")

    a.close()
    b.close()


# ---------------------------------------------------------------------------

def main() -> None:
    # Fresh server
    server = start_server()
    try:
        test_1_key_persistence()
        test_2_multi_message()
        test_3_wrong_join_code()
        test_4_clean_quit()
        test_5_unicode()
        test_6_id_binding()
        test_7_malformed_header_guard()
    finally:
        server.kill()
        server.wait(timeout=2)

    banner("SUMMARY")
    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    for name, ok, note in results:
        tag = "PASS" if ok else "FAIL"
        print(f"  [{tag}] {name}" + (f" — {note}" if note else ""))
    print(f"\n{passed}/{total} passed")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
