"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Block chain storage and management
"""

import threading
from collections import defaultdict
from typing import Dict, List, Optional

from cryptogenesis.block import HASH_GENESIS_BLOCK, Block, BlockIndex, get_next_work_required
from cryptogenesis.transaction import Transaction
from cryptogenesis.uint256 import uint256
from cryptogenesis.util import error


class BlockChain:
    """Block chain storage and management"""

    def __init__(self):
        # Map of block hash to BlockIndex
        self.block_index: Dict[uint256, BlockIndex] = {}
        self.block_index_lock = threading.Lock()

        # Best chain tip
        self.best_index: Optional[BlockIndex] = None
        self.best_height: int = -1
        self.best_hash: uint256 = uint256(0)

        # Genesis block
        self.genesis_index: Optional[BlockIndex] = None

        # Block storage (in-memory for now, can be extended to disk)
        self.blocks: Dict[uint256, Block] = {}
        self.blocks_lock = threading.Lock()

        # Orphan blocks (blocks with missing parents)
        self.orphan_blocks: Dict[uint256, Block] = {}
        self.orphan_blocks_by_prev: Dict[uint256, List[Block]] = defaultdict(list)
        self.orphan_lock = threading.Lock()

        # Transaction update counter
        self.transactions_updated = 0

    def has_block(self, block_hash: uint256) -> bool:
        """Check if block is in index"""
        with self.block_index_lock:
            return block_hash in self.block_index

    def get_block_index(self, block_hash: uint256) -> Optional[BlockIndex]:
        """Get block index by hash"""
        with self.block_index_lock:
            return self.block_index.get(block_hash)

    def get_block(self, block_hash: uint256) -> Optional[Block]:
        """Get block by hash"""
        with self.blocks_lock:
            return self.blocks.get(block_hash)

    def store_block(self, block: Block):
        """Store block in memory"""
        block_hash = block.get_hash()
        print(f"store_block: Acquiring blocks_lock for block {block_hash.get_hex()[:16]}...")
        with self.blocks_lock:
            print("store_block: Got blocks_lock, storing block...")
            self.blocks[block_hash] = block
            print("store_block: Block stored, releasing lock")

    def add_orphan_block(self, block: Block):
        """Add orphan block (block with missing parent)"""
        block_hash = block.get_hash()
        with self.orphan_lock:
            if block_hash in self.orphan_blocks:
                return

            self.orphan_blocks[block_hash] = block
            self.orphan_blocks_by_prev[block.prev_block_hash].append(block)

    def erase_orphan_block(self, block_hash: uint256):
        """Remove orphan block"""
        with self.orphan_lock:
            if block_hash not in self.orphan_blocks:
                return

            block = self.orphan_blocks[block_hash]
            prev_hash = block.prev_block_hash

            if prev_hash in self.orphan_blocks_by_prev:
                if block in self.orphan_blocks_by_prev[prev_hash]:
                    self.orphan_blocks_by_prev[prev_hash].remove(block)
                if not self.orphan_blocks_by_prev[prev_hash]:
                    del self.orphan_blocks_by_prev[prev_hash]

            del self.orphan_blocks[block_hash]

    def get_orphan_blocks_by_prev(self, prev_hash: uint256) -> List[Block]:
        """Get orphan blocks that depend on a previous block"""
        with self.orphan_lock:
            return list(self.orphan_blocks_by_prev.get(prev_hash, []))

    def has_orphan_block(self, block_hash: uint256) -> bool:
        """Check if block is an orphan"""
        with self.orphan_lock:
            return block_hash in self.orphan_blocks

    def get_orphan_root(self, block: Block) -> uint256:
        """Get root of orphan chain (oldest missing ancestor)"""
        # Walk back to find the oldest missing block
        current = block
        while True:
            if not self.has_block(current.prev_block_hash):
                if not self.has_orphan_block(current.prev_block_hash):
                    return current.prev_block_hash
                # Find the orphan block
                with self.orphan_lock:
                    for orphan in self.orphan_blocks.values():
                        if orphan.get_hash() == current.prev_block_hash:
                            current = orphan
                            break
                    else:
                        return current.prev_block_hash
            else:
                return current.prev_block_hash

    def add_to_block_index(self, block: Block, file_num: int = 0, block_pos: int = 0) -> bool:
        """Add block to block index"""
        block_hash = block.get_hash()
        print(f"AddToBlockIndex: Starting for block {block_hash.get_hex()[:16]}...")

        with self.block_index_lock:
            # Check for duplicate
            if block_hash in self.block_index:
                print(f"AddToBlockIndex() : {block_hash.get_hex()[:14]} already exists")
                return False

            # Construct new block index
            index_new = BlockIndex(file_num, block_pos, block)
            index_new.block_hash = block_hash

            # Link to previous block
            prev_index = self.block_index.get(block.prev_block_hash)
            if prev_index:
                index_new.prev = prev_index
                index_new.height = prev_index.height + 1
                prev_index.next = index_new

            # Add to index
            self.block_index[block_hash] = index_new

            # Handle genesis block
            if block_hash == HASH_GENESIS_BLOCK and self.genesis_index is None:
                self.genesis_index = index_new
                if self.best_index is None:
                    self.best_index = index_new
                    self.best_height = 0
                    self.best_hash = block_hash

            # New best block
            print(
                f"AddToBlockIndex: Checking if new best - "
                f"index_new.height={index_new.height}, "
                f"best_height={self.best_height}"
            )
            should_connect = False
            if index_new.height > self.best_height:
                print("AddToBlockIndex: This is a new best block!")
                print(
                    f"AddToBlockIndex: Checking prev_hash match - "
                    f"block.prev_block_hash={block.prev_block_hash.get_hex()[:16]}, "
                    f"self.best_hash={self.best_hash.get_hex()[:16]}"
                )
                if block.prev_block_hash == self.best_hash:
                    # Adding to current best branch - need to connect
                    print("AddToBlockIndex: prev_hash matches best_hash, will connect")
                    should_connect = True
                else:
                    print(
                        "AddToBlockIndex: prev_hash does NOT match best_hash! "
                        "This might be a reorganization or timing issue."
                    )

        # Release lock before calling _connect_block to avoid deadlock
        # (_connect_block may call set_merkle_branch which needs get_block_index)
        if should_connect:
            print("AddToBlockIndex: Releasing lock, calling _connect_block()...")
            if not self._connect_block(block, index_new):
                # Failed to connect, remove from index
                with self.block_index_lock:
                    del self.block_index[block_hash]
                    if prev_index:
                        prev_index.next = None
                return False

            # Re-acquire lock to update best chain
            with self.block_index_lock:
                # Remove transactions from mempool
                from cryptogenesis.mempool import get_mempool

                mempool = get_mempool()
                for tx in block.transactions:
                    if not tx.is_coinbase():
                        mempool.remove_transaction(tx.get_hash())

                # Update best chain
                self.best_hash = block_hash
                self.best_index = index_new
                self.best_height = index_new.height
                self.transactions_updated += 1
                print(
                    f"AddToBlockIndex: new best={self.best_hash.get_hex()[:14]}  "
                    f"height={self.best_height}"
                )
        elif index_new.height > self.best_height and block.prev_block_hash != self.best_hash:
            # New best branch - reorganize
            if not self._reorganize(index_new):
                return False
            with self.block_index_lock:
                self.best_hash = block_hash
                self.best_index = index_new
                self.best_height = index_new.height
                self.transactions_updated += 1
                print(
                    f"AddToBlockIndex: new best={self.best_hash.get_hex()[:14]}  "
                    f"height={self.best_height}"
                )

        return True

    def _connect_block(self, block: Block, index: BlockIndex) -> bool:
        """
        Connect block to chain

        Validates all transaction inputs against UTXO set,
        updates UTXO set, calculates fees, and stores transaction indexes.
        """
        print(f"ConnectBlock: Starting for block at height {index.height}...")
        from cryptogenesis.utxo import DiskTxPos, get_txdb

        # Basic validation
        print("ConnectBlock: Calling check_block()...")
        if not block.check_block():
            print("ConnectBlock: check_block() returned False")
            return False
        print("ConnectBlock: check_block() returned True")

        # Store block
        print("ConnectBlock: About to call store_block()...")
        print(f"ConnectBlock: Block hash: {block.get_hash().get_hex()[:16]}")
        try:
            print("ConnectBlock: Acquiring blocks_lock...")
            self.store_block(block)
            print("ConnectBlock: store_block() completed successfully")
        except Exception as e:
            print(f"ConnectBlock: ERROR in store_block(): {e}")
            import traceback

            traceback.print_exc()
            return False

        # Connect all transactions
        print(f"ConnectBlock: About to connect {len(block.transactions)} transactions...")
        print("ConnectBlock: Getting txdb...")
        txdb = get_txdb()
        total_fees = 0
        n_tx_pos = 0  # Transaction position within block

        for i, tx in enumerate(block.transactions):
            print(f"ConnectBlock: Processing transaction {i+1}/{len(block.transactions)}...")
            # Calculate transaction position
            from cryptogenesis.serialize import get_serialize_size

            pos_this_tx = DiskTxPos(index.file_num, index.block_pos, n_tx_pos)
            n_tx_pos += get_serialize_size(tx)

            # Connect inputs
            success, fees = tx.connect_inputs(  # type: ignore[attr-defined]
                txdb,
                map_test_pool={},
                pos_this_tx=pos_this_tx,
                height=index.height,
                fees=0,
                is_block=True,
                is_miner=False,
                min_fee=0,
            )

            if not success:
                print(f"ConnectBlock: ERROR - ConnectInputs failed for transaction {i+1}")
                return error(
                    "ConnectBlock() : ConnectInputs failed for %s",
                    tx.get_hash().get_hex()[:6],
                )
            print(f"ConnectBlock: Transaction {i+1} connected successfully, fees={fees}")

            total_fees += fees

            # Add transaction to wallet if it belongs to us
            from cryptogenesis.wallet import add_to_wallet_if_mine

            tx_num = i + 1
            print(f"ConnectBlock: Adding transaction {tx_num} to wallet if mine...")
            print("ConnectBlock: About to call add_to_wallet_if_mine()...")
            try:
                result = add_to_wallet_if_mine(tx, block=block)
                print(f"ConnectBlock: add_to_wallet_if_mine() returned {result}")
            except Exception as e:
                print(f"ConnectBlock: ERROR in add_to_wallet_if_mine(): {e}")
                import traceback

                traceback.print_exc()
                # Continue processing - don't fail the block due to wallet error

        # Verify coinbase value against block reward
        print("ConnectBlock: Verifying coinbase value...")
        if block.transactions and block.transactions[0].is_coinbase():
            coinbase_value = block.transactions[0].get_value_out()
            # Get block value (subsidy + fees) for this height
            # Note: index.height is the height of the block being connected
            block_value = block.get_block_value(total_fees, index.height)
            print(f"ConnectBlock: coinbase_value={coinbase_value}, block_value={block_value}")
            if coinbase_value > block_value:
                print(
                    f"ConnectBlock() : coinbase value {coinbase_value} exceeds "
                    f"block value {block_value} (subsidy + fees) at height {index.height}"
                )
                return False

        print("ConnectBlock: SUCCESS - returning True")
        return True

    def _disconnect_block(self, block: Block, index: BlockIndex) -> bool:
        """
        Disconnect block from chain

        Disconnects all transaction inputs, restores UTXO set,
        and removes transaction indexes.
        """
        from cryptogenesis.utxo import get_txdb

        txdb = get_txdb()

        # Disconnect in reverse order
        for tx in reversed(block.transactions):
            if not tx.disconnect_inputs(txdb):  # type: ignore[attr-defined]
                print(
                    f"DisconnectBlock() : DisconnectInputs failed for {tx.get_hash().get_hex()[:6]}"
                )
                return False

        return True

    def _reorganize(self, index_new: BlockIndex) -> bool:
        """Reorganize chain to new best branch"""
        print("*** REORGANIZE ***")

        if self.best_index is None:
            return False

        # Find the fork (common ancestor)
        fork = self.best_index
        longer = index_new

        while fork != longer:
            if fork.prev is None:
                return False
            fork = fork.prev
            while longer.height > fork.height:
                if longer.prev is None:
                    return False
                longer = longer.prev

        # List of blocks to disconnect (shorter branch)
        disconnect: List[BlockIndex] = []
        pindex = self.best_index
        while pindex != fork:
            disconnect.append(pindex)
            if pindex.prev is None:
                break
            pindex = pindex.prev

        # List of blocks to connect (longer branch)
        connect: List[BlockIndex] = []
        pindex = index_new
        while pindex != fork:
            connect.append(pindex)
            if pindex.prev is None:
                break
            pindex = pindex.prev
        connect.reverse()

        # Disconnect shorter branch
        resurrect: List[Transaction] = []
        for pindex in disconnect:
            block = self.get_block(pindex.block_hash) if pindex.block_hash else None
            if block:
                self._disconnect_block(block, pindex)

                # Queue transactions to resurrect (add back to mempool)
                for tx in block.transactions:
                    if not tx.is_coinbase():
                        resurrect.append(tx)

        # Connect longer branch
        delete: List[Transaction] = []
        for pindex in connect:
            block = self.get_block(pindex.block_hash) if pindex.block_hash else None
            if not block:
                # Need to load block - for now, this is an error
                return error(
                    "Reorganize() : block %s not found",
                    pindex.block_hash.get_hex()[:14],
                )

            if not self._connect_block(block, pindex):
                return error(
                    "Reorganize() : ConnectBlock failed for %s",
                    pindex.block_hash.get_hex()[:14],
                )
                # Delete the rest of this branch
                for j in range(connect.index(pindex), len(connect)):
                    pindex_del = connect[j]
                    if pindex_del.block_hash:
                        with self.block_index_lock:
                            if pindex_del.block_hash in self.block_index:
                                del self.block_index[pindex_del.block_hash]
                return False

            # Queue transactions to delete from mempool
            for tx in block.transactions:
                delete.append(tx)

        # Resurrect transactions (add back to mempool)
        from cryptogenesis.mempool import accept_transaction

        for tx in resurrect:
            accept_transaction(tx, check_inputs=False)

        # Remove transactions from mempool
        from cryptogenesis.mempool import get_mempool

        mempool = get_mempool()
        for tx in delete:
            if not tx.is_coinbase():
                mempool.remove_transaction(tx.get_hash())

        return True

    def accept_block(self, block: Block) -> bool:
        """Accept a block into the chain"""
        block_hash = block.get_hash()
        print(f"AcceptBlock: Starting for block {block_hash.get_hex()[:16]}...")

        # Check for duplicate in block index (matches Bitcoin v0.1 AcceptBlock)
        if self.has_block(block_hash):
            print("AcceptBlock: Block already in mapBlockIndex")
            return error("AcceptBlock() : block already in mapBlockIndex")

        # Note: We don't check orphan_blocks here because:
        # 1. ProcessBlock() already checks both mapBlockIndex and mapOrphanBlocks
        # 2. When accept_block() is called from orphan processing, the block
        #    is still in orphan_blocks but will be erased after acceptance
        # This matches Bitcoin v0.1 behavior where AcceptBlock() only checks mapBlockIndex

        # Handle genesis block specially (no previous block)
        if block_hash == HASH_GENESIS_BLOCK:
            print("AcceptBlock: Processing genesis block")
            if block.prev_block_hash != uint256(0):
                return error("AcceptBlock() : genesis block must have null prev hash")
            # Genesis block doesn't need a previous block
            # Add to index and set as best if chain is empty
            if not self.add_to_block_index(block):
                return False
            # Store block
            self.store_block(block)
            return True

        # Get previous block index (for non-genesis blocks)
        print(f"AcceptBlock: Getting prev block index for {block.prev_block_hash.get_hex()[:16]}")
        prev_index = self.get_block_index(block.prev_block_hash)
        if not prev_index:
            print("AcceptBlock: ERROR - prev block not found")
            return error("AcceptBlock() : prev block not found")
        print(f"AcceptBlock: Found prev block at height {prev_index.height}")

        # Check timestamp against previous block's median time past
        # Blocks must have timestamp > median of last 11 blocks (matches Bitcoin v0.1)
        print(f"AcceptBlock: Checking timestamp - block.time={block.time}")
        median_time = prev_index.get_median_time_past()
        print(f"AcceptBlock: median_time={median_time}")
        if block.time <= median_time:
            print(
                f"AcceptBlock: ERROR - block timestamp too early "
                f"(block={block.time}, median={median_time})"
            )
            return error("AcceptBlock() : block's timestamp is too early")

        # Check proof of work
        print(f"AcceptBlock: Checking proof of work - block.bits={block.bits:08x}")
        expected_bits = get_next_work_required(prev_index)
        print(f"AcceptBlock: expected_bits={expected_bits:08x}")
        if block.bits != expected_bits:
            print("AcceptBlock: ERROR - incorrect proof of work")
            return error(
                "AcceptBlock() : incorrect proof of work " "(expected %x, got %x)",
                expected_bits,
                block.bits,
            )

        # Store block (in-memory for now)
        # In full implementation, would write to disk here
        print("AcceptBlock: Storing block...")
        self.store_block(block)

        # Add to block index
        print("AcceptBlock: Adding to block index...")
        if not self.add_to_block_index(block, file_num=0, block_pos=0):
            print("AcceptBlock: ERROR - AddToBlockIndex failed")
            return error("AcceptBlock() : AddToBlockIndex failed")
        print("AcceptBlock: Successfully added to block index")

        # Relay if it's the new best
        best_hash_hex = self.best_hash.get_hex()[:16]
        block_hash_hex = block_hash.get_hex()[:16]
        print(
            f"AcceptBlock: Checking if new best - "
            f"best_hash={best_hash_hex}, block_hash={block_hash_hex}"
        )
        if self.best_hash == block_hash:
            print("AcceptBlock: This is the new best block, relaying...")
            # Import here to avoid circular dependency
            from cryptogenesis.network import MSG_BLOCK, Inv, relay_inventory

            inv = Inv(MSG_BLOCK, block_hash)
            relay_inventory(inv)

        print("AcceptBlock: SUCCESS - returning True")
        return True

    def process_block(self, block: Block) -> bool:
        """
        Process a block (main entry point)
        Matches Bitcoin v0.1 ProcessBlock()
        """
        block_hash = block.get_hash()

        # Check for duplicate in block index (matches Bitcoin v0.1)
        if self.has_block(block_hash):
            index = self.get_block_index(block_hash)
            height = index.height if index else -1
            return error(
                "ProcessBlock() : already have block %d %s",
                height,
                block_hash.get_hex()[:14],
            )

        # Check for duplicate in orphan blocks (matches Bitcoin v0.1)
        if self.has_orphan_block(block_hash):
            return error(
                "ProcessBlock() : already have block (orphan) %s",
                block_hash.get_hex()[:14],
            )

        # Preliminary checks
        print(f"ProcessBlock: Calling check_block() for {block_hash.get_hex()[:16]}...")
        check_result = block.check_block()
        print(f"ProcessBlock: check_block() returned {check_result}")
        if not check_result:
            print(f"ProcessBlock() : CheckBlock FAILED for block {block_hash.get_hex()[:16]}")
            # Print block details for debugging
            print(f"  Block version: {block.version}")
            print(f"  Block time: {block.time}")
            print(f"  Block bits: {block.bits:08x}")
            print(f"  Block nonce: {block.nonce}")
            print(f"  Block prev_hash: {block.prev_block_hash.get_hex()[:16]}")
            print(f"  Block merkle_root: {block.merkle_root.get_hex()[:16]}")
            print(f"  Block hash: {block_hash.get_hex()[:16]}")
            return error("ProcessBlock() : CheckBlock FAILED")

        # If we don't have the previous block, store as orphan
        print(
            f"ProcessBlock: Checking if prev block exists: {block.prev_block_hash.get_hex()[:16]}"
        )
        has_prev = self.has_block(block.prev_block_hash)
        print(f"ProcessBlock: has_block(prev) returned {has_prev}")
        if not has_prev:
            print(f"ProcessBlock: ORPHAN BLOCK, prev={block.prev_block_hash.get_hex()[:14]}")
            self.add_orphan_block(block)
            return True

        # Accept block
        print(f"ProcessBlock: Calling accept_block() for {block_hash.get_hex()[:16]}...")
        accept_result = self.accept_block(block)
        print(f"ProcessBlock: accept_block() returned {accept_result}")
        if not accept_result:
            print(f"ProcessBlock() : AcceptBlock FAILED for block {block_hash.get_hex()[:16]}")
            return error("ProcessBlock() : AcceptBlock FAILED")

        # Recursively process any orphan blocks that depended on this one
        work_queue = [block_hash]
        for i in range(len(work_queue)):
            hash_prev = work_queue[i]
            orphan_blocks = self.get_orphan_blocks_by_prev(hash_prev)

            for orphan_block in orphan_blocks:
                if self.accept_block(orphan_block):
                    print(f"   accepted orphan block {orphan_block.get_hash().get_hex()[:6]}")
                    work_queue.append(orphan_block.get_hash())
                self.erase_orphan_block(orphan_block.get_hash())

        print(
            f"ProcessBlock: ACCEPTED block {block_hash.get_hex()[:16]}, height: {self.best_height}"
        )
        return True

    def get_best_height(self) -> int:
        """Get best chain height"""
        return self.best_height

    def get_best_hash(self) -> uint256:
        """Get best chain hash"""
        return self.best_hash

    def get_best_index(self) -> Optional[BlockIndex]:
        """Get best chain index"""
        return self.best_index

    def get_block_count(self) -> int:
        """Get number of blocks in index"""
        with self.block_index_lock:
            return len(self.block_index)

    def get_orphan_count(self) -> int:
        """Get number of orphan blocks"""
        with self.orphan_lock:
            return len(self.orphan_blocks)

    def get_genesis_index(self) -> Optional[BlockIndex]:
        """Get genesis block index"""
        return self.genesis_index


# Global chain instance
_chain: Optional[BlockChain] = None
_chain_lock = threading.Lock()


def get_chain() -> BlockChain:
    """Get the global chain instance"""
    global _chain
    with _chain_lock:
        if _chain is None:
            _chain = BlockChain()
        return _chain
