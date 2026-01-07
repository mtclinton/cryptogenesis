"""
Blockchain State Manager

Thread-safe state management for blockchain data (blocks, chain state, UTXO set).
"""

import threading
from typing import Callable, Dict, List, Optional, Tuple

from cryptogenesis.block import Block
from cryptogenesis.events import BlockAddedEvent, Event
from cryptogenesis.transaction import TxOut
from cryptogenesis.uint256 import uint256


class BlockchainState:
    """Thread-safe blockchain state manager"""

    def __init__(self):
        self._lock = threading.RLock()
        # Store blocks by hash
        self._blocks: Dict[uint256, Block] = {}
        # Best block reference
        self._best_block: Optional[Block] = None
        # Best block hash for quick lookup
        self._best_hash: uint256 = uint256(0)
        # Track height separately (Block doesn't have height, BlockIndex does)
        self._best_height: int = -1
        # UTXO set: (tx_hash, output_index) -> TxOut
        self._utxo_set: Dict[Tuple[uint256, int], TxOut] = {}
        # Observers for state change notifications
        self._observers: List[Callable] = []

    def add_block(self, block: Block, height: int = -1) -> bool:
        """
        Add block to chain - returns True if successful

        Args:
            block: Block to add
            height: Height of the block (required if this is the new best block)
        """
        with self._lock:
            block_hash = block.get_hash()

            # Check for duplicate
            if block_hash in self._blocks:
                return False

            # Store block
            self._blocks[block_hash] = block

            # Update best block if this is a new best (height > current best)
            if height > self._best_height:
                self._best_block = block
                self._best_hash = block_hash
                self._best_height = height

                # Notify observers with Event object
                event = BlockAddedEvent(block)
                self.notify_observers(event)

            return True

    def get_best_height(self) -> int:
        """Get current chain height - thread-safe read"""
        with self._lock:
            return self._best_height

    def get_best_block(self) -> Optional[Block]:
        """Get best block - thread-safe read"""
        with self._lock:
            return self._best_block

    def get_best_hash(self) -> uint256:
        """Get best block hash - thread-safe read"""
        with self._lock:
            return self._best_hash

    def get_block(self, block_hash: uint256) -> Optional[Block]:
        """Get block by hash - thread-safe read"""
        with self._lock:
            return self._blocks.get(block_hash)

    def has_block(self, block_hash: uint256) -> bool:
        """Check if block exists - thread-safe read"""
        with self._lock:
            return block_hash in self._blocks

    def get_utxo(self, tx_hash: uint256, n: int) -> Optional[TxOut]:
        """
        Get UTXO by outpoint - thread-safe read

        Args:
            tx_hash: Transaction hash
            n: Output index
        """
        with self._lock:
            return self._utxo_set.get((tx_hash, n))

    def add_utxo(self, tx_hash: uint256, n: int, txout: TxOut) -> bool:
        """
        Add UTXO to set - thread-safe write

        Args:
            tx_hash: Transaction hash
            n: Output index
            txout: Transaction output
        """
        with self._lock:
            outpoint = (tx_hash, n)
            if outpoint in self._utxo_set:
                return False  # Already exists
            self._utxo_set[outpoint] = txout
            self._notify_observers("utxo_added", tx_hash, n)
            return True

    def remove_utxo(self, tx_hash: uint256, n: int) -> bool:
        """
        Remove UTXO from set - thread-safe write

        Args:
            tx_hash: Transaction hash
            n: Output index
        """
        with self._lock:
            outpoint = (tx_hash, n)
            if outpoint not in self._utxo_set:
                return False
            del self._utxo_set[outpoint]
            self._notify_observers("utxo_removed", tx_hash, n)
            return True

    def has_utxo(self, tx_hash: uint256, n: int) -> bool:
        """Check if UTXO exists - thread-safe read"""
        with self._lock:
            return (tx_hash, n) in self._utxo_set

    def subscribe(self, observer: Callable):
        """
        Subscribe to state change events

        Observer will be called with (event_type, *args) where event_type is:
        - "block_added": (block_hash, height)
        - "utxo_added": (tx_hash, n)
        - "utxo_removed": (tx_hash, n)
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
