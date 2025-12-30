"""
Wallet State Manager

Thread-safe state management for wallet data (keys, transactions, balances).
"""

import threading
from typing import Callable, Dict, List, Optional

from cryptogenesis.crypto import Key, hash160
from cryptogenesis.uint256 import uint160, uint256
from cryptogenesis.wallet import WalletTx


class WalletState:
    """Thread-safe wallet state manager"""

    def __init__(self):
        self._lock = threading.RLock()
        # Map of public key hashes to keys (map_pub_keys equivalent)
        # Stores uint160(pubkey_hash) -> Key object
        self._keys: Dict[uint160, Key] = {}
        # Map of transaction hashes to wallet transactions (map_wallet equivalent)
        self._transactions: Dict[uint256, WalletTx] = {}
        # Observers for state change notifications
        self._observers: List[Callable] = []

    def add_key(self, key: Key) -> bool:
        """
        Add key to wallet - returns True if successful

        Args:
            key: Key object to add
        """
        with self._lock:
            try:
                pubkey = key.get_pubkey()
                pubkey_hash = hash160(pubkey)
                pubkey_hash_uint160 = uint160(pubkey_hash)

                # Check for duplicate
                if pubkey_hash_uint160 in self._keys:
                    return False  # Key already exists

                # Store key
                self._keys[pubkey_hash_uint160] = key

                # Notify observers
                self._notify_observers("key_added", pubkey_hash_uint160)

                return True
            except Exception:
                return False

    def get_key(self, pubkey_hash: bytes) -> Optional[Key]:
        """
        Get key by public key hash - thread-safe read

        Args:
            pubkey_hash: Public key hash (20 bytes from hash160)
        """
        with self._lock:
            pubkey_hash_uint160 = uint160(pubkey_hash)
            return self._keys.get(pubkey_hash_uint160)

    def has_key(self, pubkey_hash: bytes) -> bool:
        """
        Check if key exists - thread-safe read

        Args:
            pubkey_hash: Public key hash (20 bytes from hash160)
        """
        with self._lock:
            pubkey_hash_uint160 = uint160(pubkey_hash)
            return pubkey_hash_uint160 in self._keys

    def get_all_keys(self) -> Dict[uint160, Key]:
        """Get all keys - thread-safe read"""
        with self._lock:
            return self._keys.copy()

    def add_transaction(self, wtx: WalletTx) -> bool:
        """
        Add transaction to wallet - returns True if successful

        Args:
            wtx: WalletTx object to add
        """
        with self._lock:
            tx_hash = wtx.get_hash()

            # Check for duplicate
            if tx_hash in self._transactions:
                return False  # Transaction already exists

            # Store transaction
            self._transactions[tx_hash] = wtx

            # Notify observers
            self._notify_observers("transaction_added", tx_hash)

            return True

    def remove_transaction(self, tx_hash: uint256) -> bool:
        """
        Remove transaction from wallet - returns True if successful

        Args:
            tx_hash: Transaction hash
        """
        with self._lock:
            if tx_hash not in self._transactions:
                return False

            del self._transactions[tx_hash]

            # Notify observers
            self._notify_observers("transaction_removed", tx_hash)

            return True

    def get_transaction(self, tx_hash: uint256) -> Optional[WalletTx]:
        """
        Get transaction by hash - thread-safe read

        Args:
            tx_hash: Transaction hash
        """
        with self._lock:
            return self._transactions.get(tx_hash)

    def has_transaction(self, tx_hash: uint256) -> bool:
        """
        Check if transaction exists - thread-safe read

        Args:
            tx_hash: Transaction hash
        """
        with self._lock:
            return tx_hash in self._transactions

    def get_all_transactions(self) -> Dict[uint256, WalletTx]:
        """Get all wallet transactions - thread-safe read"""
        with self._lock:
            return self._transactions.copy()

    def subscribe(self, observer: Callable):
        """
        Subscribe to state change events

        Observer will be called with (event_type, *args) where event_type is:
        - "key_added": (pubkey_hash_uint160)
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
