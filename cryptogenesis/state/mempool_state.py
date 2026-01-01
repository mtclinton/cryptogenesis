"""
Mempool State Manager

Thread-safe state management for pending transactions.
"""

import threading
from typing import Callable, Dict, List, Optional

from cryptogenesis.events import Event, TransactionAddedEvent
from cryptogenesis.transaction import Transaction
from cryptogenesis.uint256 import uint256


class MempoolState:
    """Thread-safe mempool state manager"""

    def __init__(self):
        self._lock = threading.RLock()
        # Store transactions in a dictionary keyed by tx hash
        self._transactions: Dict[uint256, Transaction] = {}
        # Observers for state change notifications
        self._observers: List[Callable] = []

    def add_transaction(self, tx: Transaction) -> bool:
        """
        Add transaction to mempool - returns True if successful

        Args:
            tx: Transaction to add
        """
        with self._lock:
            tx_hash = tx.get_hash()

            # Check for duplicate
            if tx_hash in self._transactions:
                return False  # Transaction already exists

            # Store transaction
            self._transactions[tx_hash] = tx

            # Notify observers with Event object
            event = TransactionAddedEvent(tx)
            self.notify_observers(event)

            return True

    def remove_transaction(self, tx_hash: uint256) -> bool:
        """
        Remove transaction from mempool - returns True if successful

        Args:
            tx_hash: Transaction hash
        """
        with self._lock:
            if tx_hash not in self._transactions:
                return False  # Transaction not found

            # Remove transaction
            del self._transactions[tx_hash]

            # Notify observers
            self._notify_observers("transaction_removed", tx_hash)

            return True

    def get_transaction(self, tx_hash: uint256) -> Optional[Transaction]:
        """
        Get transaction by hash - thread-safe read

        Args:
            tx_hash: Transaction hash
        """
        with self._lock:
            return self._transactions.get(tx_hash)

    def get_all_transactions(self) -> Dict[uint256, Transaction]:
        """
        Get all mempool transactions - thread-safe read

        Returns a copy of the transactions dictionary
        """
        with self._lock:
            return self._transactions.copy()

    def contains(self, tx_hash: uint256) -> bool:
        """
        Check if transaction is in mempool - thread-safe read

        Args:
            tx_hash: Transaction hash
        """
        with self._lock:
            return tx_hash in self._transactions

    def get_transaction_count(self) -> int:
        """Get number of transactions in mempool - thread-safe read"""
        with self._lock:
            return len(self._transactions)

    def clear(self) -> int:
        """
        Clear all transactions from mempool - returns count of removed transactions

        Note: This is useful for testing or reset scenarios
        """
        with self._lock:
            count = len(self._transactions)
            removed_hashes = list(self._transactions.keys())
            self._transactions.clear()

            # Notify observers for each removed transaction
            for tx_hash in removed_hashes:
                self._notify_observers("transaction_removed", tx_hash)

            return count

    def subscribe(self, observer: Callable):
        """
        Subscribe to state change events

        Observer will be called with (event_type, *args) where event_type is:
        - "transaction_added": (tx_hash)
        - "transaction_removed": (tx_hash)
        """
        with self._lock:
            if observer not in self._observers:
                self._observers.append(observer)

    def unsubscribe(self, observer: Callable):
        """Unsubscribe from state change events"""
        with self._lock:
            if observer in self._observers:
                self._observers.remove(observer)

    def notify_observers(self, event: Event):
        """
        Notify all observers of a state change with an Event object.
        
        Args:
            event: Event object to pass to observers
        """
        # Create a copy of observers list to avoid issues if observers modify the list
        observers_copy = list(self._observers)
        for observer in observers_copy:
            try:
                observer(event)
            except Exception:
                # Don't let observer errors break state management
                pass
    
    def _notify_observers(self, event_type: str, *args):
        """
        Legacy method for backward compatibility.
        
        Notify all observers of a state change (old format).
        New code should use notify_observers(event: Event) instead.
        """
        # Create a copy of observers list to avoid issues if observers modify the list
        observers_copy = list(self._observers)
        for observer in observers_copy:
            try:
                observer(event_type, *args)
            except Exception:
                # Don't let observer errors break state management
                pass
