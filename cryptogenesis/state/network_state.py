"""
Network State Manager

Thread-safe state management for peer connections and network status.
"""

import threading
from typing import Callable, List

from cryptogenesis.network import Address, Node


class NetworkState:
    """Thread-safe network state manager"""

    def __init__(self):
        self._lock = threading.RLock()
        self._peers: List[Node] = []
        self._addresses: List[Address] = []
        self._observers: List[Callable] = []

    def add_peer(self, node: Node) -> bool:
        """Add peer to network - returns True if successful"""
        with self._lock:
            # TODO: Add peer logic
            return False

    def remove_peer(self, node: Node) -> bool:
        """Remove peer from network - returns True if successful"""
        with self._lock:
            # TODO: Remove peer logic
            return False

    def get_peers(self) -> List[Node]:
        """Get all connected peers - thread-safe read"""
        with self._lock:
            return self._peers.copy()

    def add_address(self, addr: Address) -> bool:
        """Add address to known addresses - returns True if successful"""
        with self._lock:
            # TODO: Add address logic
            return False

    def get_addresses(self) -> List[Address]:
        """Get all known addresses - thread-safe read"""
        with self._lock:
            return self._addresses.copy()

    def subscribe(self, observer: Callable):
        """Subscribe to state change events"""
        with self._lock:
            self._observers.append(observer)
