"""
Blockchain State Manager

Single source of truth for blockchain data. This is a thin, thread-safe facade
over the one BlockChain engine (cryptogenesis.chain) -- the linked, height-aware
block index, block bodies, the best tip, orphans, and the TxDB/UTXO model all
live in that single instance. Previously this class kept its own parallel
dicts that only ever received the genesis block (mining/network write straight
to the chain), so the two stores could silently diverge; facading the one
engine removes that hazard.
"""

import threading
from typing import Optional

from cryptogenesis.block import Block, BlockIndex
from cryptogenesis.uint256 import uint256


class BlockchainState:
    """Thread-safe facade over the single BlockChain engine."""

    def __init__(self, chain=None):
        # One shared lock around mutating operations; reads delegate straight
        # to the engine (which has its own fine-grained locks).
        self._lock = threading.RLock()
        if chain is None:
            from cryptogenesis.chain import get_chain

            chain = get_chain()
        self._chain = chain

    @property
    def chain(self):
        """The underlying BlockChain engine (single source of truth)."""
        return self._chain

    def add_block(self, block: Block, height: int = -1) -> bool:
        """Accept and connect a block. Returns True on success.

        Uses accept_block (not process_block) because that path special-cases
        the genesis block; non-genesis blocks must have their parent already in
        the index (mining/network deliver connected blocks via process_block).
        The `height` argument is accepted for backwards compatibility and
        ignored -- the engine derives height from the block's parent.
        """
        with self._lock:
            return self._chain.accept_block(block)

    def get_best_height(self) -> int:
        return self._chain.best_height

    def get_best_hash(self) -> uint256:
        return self._chain.get_best_hash()

    def get_best_index(self) -> Optional[BlockIndex]:
        return self._chain.get_best_index()

    def get_block(self, block_hash: uint256) -> Optional[Block]:
        return self._chain.get_block(block_hash)

    def has_block(self, block_hash: uint256) -> bool:
        return self._chain.has_block(block_hash)
