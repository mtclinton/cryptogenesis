"""
Phase 5 pins for the P2P engine (cryptogenesis.network.protocol).

Covers the version-handshake fix (correctly-sized fields), the one-shot
getblocks request that drives initial sync, message framing across the recv
buffer, and the DoS bound on attacker-controlled inv/addr counts. These drive
the engine directly over socketpairs without spinning up the listener threads.
"""

import socket
import struct

import pytest

from .context import cryptogenesis  # noqa: F401

from cryptogenesis.network import protocol
from cryptogenesis.network.protocol import NODE_NETWORK, Address, Node


@pytest.fixture
def make_node():
    """Factory for Node objects backed by real socketpairs; auto-closed."""
    socks = []

    def _make(inbound):
        a, b = socket.socketpair()
        socks.extend([a, b])
        return Node(a, Address(0x7F000001, 8333, NODE_NETWORK), inbound=inbound)

    yield _make
    for s in socks:
        try:
            s.close()
        except Exception:
            pass


def _deliver_version(make_node, receiver):
    """Build a real version message from a fresh node and hand it to receiver."""
    sender = make_node(inbound=False)  # __init__ queues a version message
    version_bytes = bytes(sender.v_send.vch)
    receiver.v_send.vch.clear()
    receiver.v_recv.vch = bytearray(version_bytes)


def test_version_handshake_parses_correctly(make_node):
    protocol.f_asked_for_blocks = False
    receiver = make_node(inbound=True)
    _deliver_version(make_node, receiver)

    protocol.process_messages(receiver)

    assert receiver.version == Node.VERSION
    # services/time used to mis-align because version was serialized as 8 bytes.
    assert receiver.services == NODE_NETWORK
    assert receiver.is_client is False
    assert len(receiver.v_recv.vch) == 0  # buffer fully drained


def test_version_triggers_getblocks(make_node):
    protocol.f_asked_for_blocks = False
    receiver = make_node(inbound=True)
    _deliver_version(make_node, receiver)

    protocol.process_messages(receiver)

    assert b"getblocks" in bytes(receiver.v_send.vch)


def test_getblocks_is_one_shot(make_node):
    protocol.f_asked_for_blocks = False

    r1 = make_node(inbound=True)
    _deliver_version(make_node, r1)
    protocol.process_messages(r1)
    assert b"getblocks" in bytes(r1.v_send.vch)

    r2 = make_node(inbound=True)
    _deliver_version(make_node, r2)
    protocol.process_messages(r2)
    assert b"getblocks" not in bytes(r2.v_send.vch)  # already asked one peer


def test_partial_message_is_buffered(make_node):
    receiver = make_node(inbound=True)
    sender = make_node(inbound=False)
    full = bytes(sender.v_send.vch)
    receiver.v_send.vch.clear()
    receiver.v_recv.vch = bytearray(full[:-5])  # 5 bytes short of a full message

    protocol.process_messages(receiver)

    assert receiver.version == 0  # not processed until the rest arrives
    assert len(receiver.v_recv.vch) > 0  # still buffered


def test_inv_count_is_bounded(make_node):
    receiver = make_node(inbound=True)
    receiver.version = Node.VERSION  # bypass the version-first gate
    # Claim ~1e9 inv items but provide no item bytes: must cap to 0, not hang.
    payload = b"\xfe" + struct.pack("<I", 10**9)
    protocol.process_message(receiver, "inv", payload)
    assert b"getdata" not in bytes(receiver.v_send.vch)


def test_addr_count_is_bounded(make_node):
    receiver = make_node(inbound=True)
    receiver.version = Node.VERSION
    payload = b"\xfe" + struct.pack("<I", 10**9)  # huge claimed count, no bytes
    # Must return without over-allocating or iterating a billion times.
    protocol.process_message(receiver, "addr", payload)
