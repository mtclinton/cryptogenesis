"""
Network State Manager

Thread-safe state management for peer connections and network status.
"""

import threading
from typing import Callable, List, Optional

from cryptogenesis.network import Address, Node


class NetworkState:
    """Thread-safe network state manager"""

    def __init__(self):
        self._lock = threading.RLock()
        # Store list of connected peers (Node objects)
        self._peers: List[Node] = []
        # Store list of known addresses
        self._addresses: List[Address] = []
        # Observers for state change notifications
        self._observers: List[Callable] = []

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

            # Notify observers
            self._notify_observers("peer_added", node.addr)

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

                    # Notify observers
                    self._notify_observers("peer_removed", removed_node.addr)

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

                    # Notify observers
                    self._notify_observers("peer_removed", removed_node.addr)

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

    def subscribe(self, observer: Callable):
        """
        Subscribe to state change events

        Observer will be called with (event_type, *args) where event_type is:
        - "peer_added": (addr)
        - "peer_removed": (addr)
        - "address_added": (addr)
        - "address_removed": (addr)
        """
        with self._lock:
            if observer not in self._observers:
                self._observers.append(observer)

    def unsubscribe(self, observer: Callable):
        """Unsubscribe from state change events"""
        with self._lock:
            if observer in self._observers:
                self._observers.remove(observer)

    def _notify_observers(self, event_type: str, *args):
        """Notify all observers of a state change"""
        # Create a copy of observers list to avoid issues if observers modify the list
        observers_copy = list(self._observers)
        for observer in observers_copy:
            try:
                observer(event_type, *args)
            except Exception:
                # Don't let observer errors break state management
                pass
