"""
Wallet State Manager

Thread-safe state management for wallet data (keys, transactions, balances).
"""

import threading
from typing import Callable, Dict, List, Optional

from cryptogenesis.crypto import Key
from cryptogenesis.uint256 import uint256
from cryptogenesis.wallet import WalletTx


class WalletState:
    """Thread-safe wallet state manager"""

    def __init__(self):
        self._lock = threading.RLock()
        self._keys: Dict[bytes, Key] = {}  # pubkey_hash -> Key
        self._transactions: Dict[uint256, WalletTx] = {}
        self._observers: List[Callable] = []

    def add_key(self, key: Key) -> bool:
        """Add key to wallet - returns True if successful"""
        with self._lock:
            # TODO: Add key logic
            return False

    def get_key(self, pubkey_hash: bytes) -> Optional[Key]:
        """Get key by public key hash - thread-safe read"""
        with self._lock:
            return self._keys.get(pubkey_hash)

    def add_transaction(self, wtx: WalletTx) -> bool:
        """Add transaction to wallet - returns True if successful"""
        with self._lock:
            # TODO: Add transaction logic
            return False

    def get_transaction(self, tx_hash: uint256) -> Optional[WalletTx]:
        """Get transaction by hash - thread-safe read"""
        with self._lock:
            return self._transactions.get(tx_hash)

    def get_all_transactions(self) -> Dict[uint256, WalletTx]:
        """Get all wallet transactions - thread-safe read"""
        with self._lock:
            return self._transactions.copy()

    def subscribe(self, observer: Callable):
        """Subscribe to state change events"""
        with self._lock:
            self._observers.append(observer)
