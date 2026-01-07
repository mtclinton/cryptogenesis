"""
Network State Manager

Thread-safe state management for peer connections and network status.
Uses Event system for state change notifications.
"""

# Import Address and Node from main network module file (not package to avoid circular import)
import importlib.util
import os
import sys
import threading
from typing import TYPE_CHECKING, List, Optional

network_file_path = os.path.join(os.path.dirname(__file__), "..", "network.py")
network_file_path = os.path.abspath(network_file_path)
spec = importlib.util.spec_from_file_location("network_module", network_file_path)
network_module = importlib.util.module_from_spec(spec)
sys.modules["network_module"] = network_module
spec.loader.exec_module(network_module)
Address = network_module.Address
Node = network_module.Node

if TYPE_CHECKING:
    from cryptogenesis.events import (
        EventBus,
        NetworkPeerConnectedEvent,
        NetworkPeerDisconnectedEvent,
    )


class NetworkState:
    """Thread-safe network state manager"""

    def __init__(self, event_bus: Optional["EventBus"] = None):
        self._lock = threading.RLock()
        # Store list of connected peers (Node objects)
        self._peers: List[Node] = []
        # Store list of known addresses
        self._addresses: List[Address] = []
        # EventBus for publishing state change events
        self.event_bus = event_bus

    def add_peer(self, node: Node) -> bool:
        """
        Add peer to network - returns True if successful

        Args:
            node: Node object to add
        """
        with self._lock:
            # Check for duplicate by comparing addresses
            # Node objects don't have __eq__, so we compare by address
            for existing_node in self._peers:
                if existing_node.addr == node.addr:
                    return False  # Peer with same address already exists

            # Add peer
            self._peers.append(node)

            # Publish event
            if self.event_bus:
                try:
                    from cryptogenesis.events import NetworkPeerConnectedEvent

                    self.event_bus.publish(NetworkPeerConnectedEvent(node))
                except Exception as e:
                    print(f"Error publishing NetworkPeerConnectedEvent: {e}")

            return True

    def remove_peer(self, node: Node) -> bool:
        """
        Remove peer from network - returns True if successful

        Args:
            node: Node object to remove
        """
        with self._lock:
            # Find and remove peer by comparing addresses
            for i, existing_node in enumerate(self._peers):
                if existing_node.addr == node.addr:
                    removed_node = self._peers.pop(i)

                    # Publish event
                    if self.event_bus:
                        try:
                            from cryptogenesis.events import NetworkPeerDisconnectedEvent

                            self.event_bus.publish(NetworkPeerDisconnectedEvent(removed_node))
                        except Exception as e:
                            print(f"Error publishing NetworkPeerDisconnectedEvent: {e}")

                    return True

            return False  # Peer not found

    def remove_peer_by_address(self, addr: Address) -> bool:
        """
        Remove peer by address - returns True if successful

        Args:
            addr: Address of peer to remove
        """
        with self._lock:
            # Find and remove peer by address
            for i, existing_node in enumerate(self._peers):
                if existing_node.addr == addr:
                    removed_node = self._peers.pop(i)

                    # Publish event
                    if self.event_bus:
                        try:
                            from cryptogenesis.events import NetworkPeerDisconnectedEvent

                            self.event_bus.publish(NetworkPeerDisconnectedEvent(removed_node))
                        except Exception as e:
                            print(f"Error publishing NetworkPeerDisconnectedEvent: {e}")

                    return True

            return False  # Peer not found

    def get_peer_by_address(self, addr: Address) -> Optional[Node]:
        """
        Get peer by address - thread-safe read

        Args:
            addr: Address of peer to find
        """
        with self._lock:
            for node in self._peers:
                if node.addr == addr:
                    return node
            return None

    def has_peer(self, node: Node) -> bool:
        """
        Check if peer exists - thread-safe read

        Args:
            node: Node object to check
        """
        with self._lock:
            for existing_node in self._peers:
                if existing_node.addr == node.addr:
                    return True
            return False

    def has_peer_by_address(self, addr: Address) -> bool:
        """
        Check if peer exists by address - thread-safe read

        Args:
            addr: Address to check
        """
        with self._lock:
            for node in self._peers:
                if node.addr == addr:
                    return True
            return False

    def get_peers(self) -> List[Node]:
        """
        Get all connected peers - thread-safe read

        Returns a copy of the peers list
        """
        with self._lock:
            return self._peers.copy()

    def get_peer_count(self) -> int:
        """Get number of connected peers - thread-safe read"""
        with self._lock:
            return len(self._peers)

    def add_address(self, addr: Address) -> bool:
        """
        Add address to known addresses - returns True if successful

        Args:
            addr: Address to add
        """
        with self._lock:
            # Check for duplicate (Address has __eq__ and __hash__)
            if addr in self._addresses:
                return False  # Address already exists

            # Add address
            self._addresses.append(addr)

            # Notify observers
            self._notify_observers("address_added", addr)

            return True

    def remove_address(self, addr: Address) -> bool:
        """
        Remove address from known addresses - returns True if successful

        Args:
            addr: Address to remove
        """
        with self._lock:
            if addr not in self._addresses:
                return False  # Address not found

            # Remove address
            self._addresses.remove(addr)

            # Notify observers
            self._notify_observers("address_removed", addr)

            return True

    def has_address(self, addr: Address) -> bool:
        """
        Check if address exists - thread-safe read

        Args:
            addr: Address to check
        """
        with self._lock:
            return addr in self._addresses

    def get_addresses(self) -> List[Address]:
        """
        Get all known addresses - thread-safe read

        Returns a copy of the addresses list
        """
        with self._lock:
            return self._addresses.copy()

    def get_address_count(self) -> int:
        """Get number of known addresses - thread-safe read"""
        with self._lock:
            return len(self._addresses)

    def set_event_bus(self, event_bus: "EventBus"):
        """
        Set the EventBus for publishing state change events.
        This allows the NetworkState to be created before the EventBus.

        Args:
            event_bus: EventBus instance for publishing events
        """
        self.event_bus = event_bus
