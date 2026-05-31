"""
Network Package

The Bitcoin P2P engine lives in cryptogenesis.network.protocol. This package
re-exports its public surface so callers can keep using `cryptogenesis.network`.

(Previously this module loaded a sibling network.py by file path via importlib,
which created two distinct module objects for the same code -- so e.g.
cryptogenesis.network.Node was not the same class as events.events.Node. The
engine now lives inside the package, eliminating that split-brain.)
"""

from cryptogenesis.network.protocol import (
    Address,
    DEFAULT_PORT,
    Inv,
    MESSAGE_START,
    MSG_BLOCK,
    MSG_PRODUCT,
    MSG_REVIEW,
    MSG_TABLE,
    MSG_TX,
    MessageHeader,
    NODE_NETWORK,
    Node,
    add_address,
    connect_node,
    find_node,
    relay_inventory,
    start_node,
    stop_node,
)

__all__ = [
    "Address",
    "DEFAULT_PORT",
    "Inv",
    "MESSAGE_START",
    "MSG_BLOCK",
    "MSG_PRODUCT",
    "MSG_REVIEW",
    "MSG_TABLE",
    "MSG_TX",
    "MessageHeader",
    "NODE_NETWORK",
    "Node",
    "add_address",
    "connect_node",
    "find_node",
    "relay_inventory",
    "start_node",
    "stop_node",
]
