"""
Message Sender

Handles sending network messages to peers.
Separated from state management - uses services for business logic.
"""

# Import Inv and Node from main network module file (not package to avoid circular import)
import importlib.util
import os
import sys
import threading
from typing import List, Optional

from cryptogenesis.events import EventBus
from cryptogenesis.state.network_state import NetworkState

network_file_path = os.path.join(os.path.dirname(__file__), "..", "network.py")
network_file_path = os.path.abspath(network_file_path)
spec = importlib.util.spec_from_file_location("network_module", network_file_path)
network_module = importlib.util.module_from_spec(spec)
sys.modules["network_module"] = network_module
spec.loader.exec_module(network_module)
Inv = network_module.Inv
Node = network_module.Node


class MessageSender:
    """
    Message sender for sending messages to peers.

    Handles message sending without managing state directly.
    Uses NetworkState to get peer list.
    """

    def __init__(
        self,
        network_state: Optional[NetworkState] = None,
        event_bus: Optional[EventBus] = None,
    ):
        """
        Initialize message sender.

        Args:
            network_state: Optional NetworkState instance for getting peers
            event_bus: Optional EventBus instance for publishing events
        """
        self.network_state = network_state
        self.event_bus = event_bus
        self._lock = threading.Lock()

    def send_to_peer(self, node: Node, command: str, message_data: bytes) -> bool:
        """
        Send a message to a specific peer.

        Args:
            node: Node to send message to
            command: Message command string
            message_data: Raw message data

        Returns:
            True if sent successfully, False otherwise
        """
        try:
            # TODO: Implement actual message sending
            # This will serialize the message and send via node.socket
            # For now, this is a placeholder
            return True
        except Exception as e:
            print(f"Error sending message to peer: {e}")
            return False

    def broadcast_message(self, command: str, message_data: bytes) -> int:
        """
        Broadcast a message to all connected peers.

        Args:
            command: Message command string
            message_data: Raw message data

        Returns:
            Number of peers the message was sent to
        """
        if not self.network_state:
            return 0

        peers = self.network_state.get_peers()
        sent_count = 0

        for peer in peers:
            if self.send_to_peer(peer, command, message_data):
                sent_count += 1

        return sent_count

    def relay_inventory(self, inv: Inv, exclude_node: Optional[Node] = None) -> int:
        """
        Relay inventory to peers.

        Args:
            inv: Inventory item to relay
            exclude_node: Optional node to exclude from relay

        Returns:
            Number of peers the inventory was relayed to
        """
        if not self.network_state:
            return 0

        peers = self.network_state.get_peers()
        relayed_count = 0

        for peer in peers:
            if exclude_node and peer == exclude_node:
                continue

            # TODO: Check if peer already knows about this inventory
            # TODO: Send inventory message to peer
            relayed_count += 1

        return relayed_count
