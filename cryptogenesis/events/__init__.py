"""
Event System

Decoupled communication between components using events.
"""

from cryptogenesis.events.event_bus import EventBus
from cryptogenesis.events.events import (
    BlockAddedEvent,
    BlockMinedEvent,
    Event,
    NetworkPeerConnectedEvent,
    NetworkPeerDisconnectedEvent,
    TransactionAddedEvent,
    WalletUpdatedEvent,
)

__all__ = [
    "Event",
    "EventBus",
    "BlockAddedEvent",
    "BlockMinedEvent",
    "TransactionAddedEvent",
    "WalletUpdatedEvent",
    "NetworkPeerConnectedEvent",
    "NetworkPeerDisconnectedEvent",
]

