"""
Mempool State Manager

Thread-safe state management for pending transactions.
"""

import threading
from typing import Callable, Dict, List, Optional

from cryptogenesis.transaction import Transaction
from cryptogenesis.uint256 import uint256


class MempoolState:
    """Thread-safe mempool state manager"""

    def __init__(self):
        self._lock = threading.RLock()
        self._transactions: Dict[uint256, Transaction] = {}
        self._observers: List[Callable] = []

    def add_transaction(self, tx: Transaction) -> bool:
        """Add transaction to mempool - returns True if successful"""
        with self._lock:
            # TODO: Add transaction logic
            return False

    def remove_transaction(self, tx_hash: uint256) -> bool:
        """Remove transaction from mempool - returns True if successful"""
        with self._lock:
            # TODO: Remove transaction logic
            return False

    def get_transaction(self, tx_hash: uint256) -> Optional[Transaction]:
        """Get transaction by hash - thread-safe read"""
        with self._lock:
            return self._transactions.get(tx_hash)

    def get_all_transactions(self) -> Dict[uint256, Transaction]:
        """Get all mempool transactions - thread-safe read"""
        with self._lock:
            return self._transactions.copy()

    def contains(self, tx_hash: uint256) -> bool:
        """Check if transaction is in mempool - thread-safe read"""
        with self._lock:
            return tx_hash in self._transactions

    def subscribe(self, observer: Callable):
        """Subscribe to state change events"""
        with self._lock:
            self._observers.append(observer)
