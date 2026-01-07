"""
Peer Manager

Manages peer connections and peer state.
Separated from state management - uses NetworkState for state.
"""

import importlib.util
import os
import sys
import threading
from typing import List, Optional

from cryptogenesis.events import EventBus, NetworkPeerConnectedEvent, NetworkPeerDisconnectedEvent
from cryptogenesis.state.network_state import NetworkState

# Import Address and Node from main network module file (not package to avoid circular import)
network_file_path = os.path.join(os.path.dirname(__file__), "..", "network.py")
network_file_path = os.path.abspath(network_file_path)
spec = importlib.util.spec_from_file_location("network_module", network_file_path)
network_module = importlib.util.module_from_spec(spec)
sys.modules["network_module"] = network_module
spec.loader.exec_module(network_module)
Address = network_module.Address
Node = network_module.Node


class PeerManager:
    """
    Peer manager for managing peer connections.

    Handles peer connection/disconnection without managing state directly.
    Uses NetworkState for state management.
    """

    def __init__(
        self,
        network_state: NetworkState,
        event_bus: Optional[EventBus] = None,
    ):
        """
        Initialize peer manager.

        Args:
            network_state: NetworkState instance for state management
            event_bus: Optional EventBus instance for publishing events
        """
        self.network_state = network_state
        self.event_bus = event_bus
        # Ensure NetworkState has the event_bus for publishing events
        if event_bus and hasattr(network_state, "set_event_bus"):
            network_state.set_event_bus(event_bus)
        self._lock = threading.Lock()

    def add_peer(self, node: Node) -> bool:
        """
        Add a peer connection.

        Args:
            node: Node instance to add

        Returns:
            True if added successfully, False otherwise
        """
        try:
            # Add to state (NetworkState will publish the event)
            return self.network_state.add_peer(node)
        except Exception as e:
            print(f"Error adding peer: {e}")
            return False

    def remove_peer(self, node: Node) -> bool:
        """
        Remove a peer connection.

        Args:
            node: Node instance to remove

        Returns:
            True if removed successfully, False otherwise
        """
        try:
            # Remove from state (NetworkState will publish the event)
            return self.network_state.remove_peer(node)
        except Exception as e:
            print(f"Error removing peer: {e}")
            return False

    def get_peers(self) -> List[Node]:
        """
        Get all connected peers.

        Returns:
            List of Node instances
        """
        return self.network_state.get_peers()

    def get_peer_count(self) -> int:
        """
        Get number of connected peers.

        Returns:
            Number of peers
        """
        return self.network_state.get_peer_count()

    def disconnect_all(self):
        """Disconnect all peers"""
        peers = self.get_peers()
        for peer in peers:
            self.remove_peer(peer)

    def find_peer_by_address(self, address: Address) -> Optional[Node]:
        """
        Find peer by address.

        Args:
            address: Address to search for

        Returns:
            Node instance if found, None otherwise
        """
        return self.network_state.get_peer_by_address(address)
