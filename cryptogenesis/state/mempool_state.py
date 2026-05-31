"""
Mempool State Manager

Single source of truth for pending transactions: a thin thread-safe facade over
the one Mempool engine (cryptogenesis.mempool). The previous parallel
_transactions dict was a second store the live path never wrote (mining and the
network use the global mempool directly), so facading the one engine keeps them
from diverging and removes the notify-observers-under-lock pattern.
"""

import threading
from typing import List, Optional

from cryptogenesis.transaction import Transaction
from cryptogenesis.uint256 import uint256


class MempoolState:
    """Thread-safe facade over the single Mempool engine."""

    def __init__(self, mempool=None):
        self._lock = threading.RLock()
        if mempool is None:
            from cryptogenesis.mempool import get_mempool

            mempool = get_mempool()
        self._mempool = mempool

    @property
    def mempool(self):
        """The underlying Mempool engine (single source of truth)."""
        return self._mempool

    def add_transaction(self, tx: Transaction) -> bool:
        with self._lock:
            return self._mempool.add_transaction(tx)

    def remove_transaction(self, tx_hash: uint256) -> bool:
        with self._lock:
            return self._mempool.remove_transaction(tx_hash)

    def get_transaction(self, tx_hash: uint256) -> Optional[Transaction]:
        return self._mempool.get_transaction(tx_hash)

    def contains(self, tx_hash: uint256) -> bool:
        return self._mempool.has_transaction(tx_hash)

    def get_all_transactions(self) -> List[Transaction]:
        return self._mempool.get_all_transactions()

    def get_transaction_count(self) -> int:
        return self._mempool.get_transaction_count()

    def clear(self):
        with self._lock:
            return self._mempool.clear()
