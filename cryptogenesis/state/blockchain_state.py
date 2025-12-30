"""
Blockchain State Manager

Thread-safe state management for blockchain data (blocks, chain state, UTXO set).
"""

import threading
from typing import Callable, Dict, List, Optional

from cryptogenesis.block import Block
from cryptogenesis.transaction import TxOut
from cryptogenesis.uint256 import uint256


class BlockchainState:
    """Thread-safe blockchain state manager"""

    def __init__(self):
        self._lock = threading.RLock()
        self._blocks: Dict[uint256, Block] = {}
        self._best_block: Optional[Block] = None
        self._utxo_set: Dict[tuple, TxOut] = {}  # (tx_hash, n) -> TxOut
        self._observers: List[Callable] = []

    def add_block(self, block: Block) -> bool:
        """Add block to chain - returns True if successful"""
        with self._lock:
            # TODO: Validation and state update
            # TODO: Notify observers
            return False

    def get_best_height(self) -> int:
        """Get current chain height - thread-safe read"""
        with self._lock:
            # TODO: Track height separately (Block doesn't have height, BlockIndex does)
            return -1 if self._best_block is None else 0

    def get_block(self, block_hash: uint256) -> Optional[Block]:
        """Get block by hash - thread-safe read"""
        with self._lock:
            return self._blocks.get(block_hash)

    def get_utxo(self, tx_hash: uint256, n: int) -> Optional[TxOut]:
        """Get UTXO by outpoint - thread-safe read"""
        with self._lock:
            return self._utxo_set.get((tx_hash, n))

    def subscribe(self, observer: Callable):
        """Subscribe to state change events"""
        with self._lock:
            self._observers.append(observer)
