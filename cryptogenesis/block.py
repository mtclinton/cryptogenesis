"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Block and blockchain structures
"""

import struct
import time
from typing import List, Optional

from cryptogenesis.crypto import double_sha256, hash_to_uint256
from cryptogenesis.serialize import (
    DataStream,
    get_size_of_compact_size,
    read_compact_size,
    write_compact_size,
)
from cryptogenesis.transaction import COIN, Transaction
from cryptogenesis.uint256 import uint256

# Genesis block hash
HASH_GENESIS_BLOCK = uint256("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")

# Proof of work limit
PROOF_OF_WORK_LIMIT = uint256("0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff")


class BlockIndex:
    """Block index entry"""

    def __init__(self, file_num: int = 0, block_pos: int = 0, block=None):
        self.block_hash: Optional[uint256] = None
        self.prev: Optional["BlockIndex"] = None
        self.next: Optional["BlockIndex"] = None
        self.file_num = file_num
        self.block_pos = block_pos
        self.height = 0

        # Block header
        self.version = 0
        self.merkle_root = uint256(0)
        self.time = 0
        self.bits = 0
        self.nonce = 0

        if block:
            self.version = block.version
            self.merkle_root = block.merkle_root
            self.time = block.time
            self.bits = block.bits
            self.nonce = block.nonce

    def get_block_hash(self) -> uint256:
        """Get block hash"""
        if self.block_hash:
            return self.block_hash
        # Reconstruct from header
        block = Block()
        block.version = self.version
        block.prev_block_hash = self.prev.get_block_hash() if self.prev else uint256(0)
        block.merkle_root = self.merkle_root
        block.time = self.time
        block.bits = self.bits
        block.nonce = self.nonce
        return block.get_hash()

    def is_in_main_chain(self, best_index: Optional["BlockIndex"]) -> bool:
        """Check if block is in main chain"""
        return self.next is not None or self == best_index

    def get_median_time_past(self) -> int:
        """Get median time past (11 blocks)"""
        median_time_span = 11
        times = []
        index = self
        for _ in range(median_time_span):
            if index:
                times.append(index.time)
                index = index.prev
            else:
                break
        times.sort()
        if len(times) == 0:
            return self.time
        return times[len(times) // 2]


class Block:
    """Bitcoin block"""

    def __init__(self):
        # Header
        self.version = 1
        self.prev_block_hash = uint256(0)
        self.merkle_root = uint256(0)
        self.time = 0
        self.bits = 0
        self.nonce = 0

        # Transactions
        self.transactions: List["Transaction"] = []

        # Memory only
        self.merkle_tree: List[uint256] = []

    @property
    def block_hash(self) -> uint256:
        """Block hash as property"""
        return self.get_hash()

    def get_hash(self) -> uint256:
        """Get block hash (header hash)"""
        header = struct.pack("<i", self.version)
        header += self.prev_block_hash.to_bytes()
        header += self.merkle_root.to_bytes()
        header += struct.pack("<III", self.time, self.bits, self.nonce)
        return hash_to_uint256(double_sha256(header))

    def build_merkle_tree(self) -> uint256:
        """Build merkle tree and return root"""
        self.merkle_tree.clear()

        # Add transaction hashes
        for tx in self.transactions:
            self.merkle_tree.append(tx.get_hash())

        if len(self.merkle_tree) == 0:
            return uint256(0)

        # Build tree
        j = 0
        size = len(self.transactions)
        while size > 1:
            for i in range(0, size, 2):
                i2 = min(i + 1, size - 1)
                hash1 = self.merkle_tree[j + i]
                hash2 = self.merkle_tree[j + i2]
                combined = hash1.to_bytes() + hash2.to_bytes()
                self.merkle_tree.append(hash_to_uint256(double_sha256(combined)))
            j += size
            size = (size + 1) // 2

        return self.merkle_tree[-1] if self.merkle_tree else uint256(0)

    def get_merkle_branch(self, index: int) -> List[uint256]:
        """Get merkle branch for transaction at index"""
        if len(self.merkle_tree) == 0:
            self.build_merkle_tree()

        merkle_branch = []
        j = 0
        size = len(self.transactions)
        idx = index

        while size > 1:
            i = min(idx ^ 1, size - 1)
            merkle_branch.append(self.merkle_tree[j + i])
            idx >>= 1
            j += size
            size = (size + 1) // 2

        return merkle_branch

    @staticmethod
    def check_merkle_branch(tx_hash: uint256, merkle_branch: List[uint256], index: int) -> uint256:
        """Check merkle branch and return root"""
        if index == -1:
            return uint256(0)

        hash_result = tx_hash
        idx = index

        for other_side in merkle_branch:
            if idx & 1:
                combined = other_side.to_bytes() + hash_result.to_bytes()
            else:
                combined = hash_result.to_bytes() + other_side.to_bytes()
            hash_result = hash_to_uint256(double_sha256(combined))
            idx >>= 1

        return hash_result

    def serialize(self, stream: "DataStream", stream_type: int = 0, version: int = 101):
        """Serialize block to stream"""

        stream.write(struct.pack("<i", self.version))
        stream.write(self.prev_block_hash.to_bytes())
        stream.write(self.merkle_root.to_bytes())
        stream.write(struct.pack("<III", self.time, self.bits, self.nonce))

        if not (stream_type & 0x20000):  # SER_BLOCKHEADERONLY
            write_compact_size(stream.vch, len(self.transactions))
            for tx in self.transactions:
                tx.serialize(stream, stream_type, version)

    def unserialize(self, stream: "DataStream", stream_type: int = 0, version: int = 101):
        """Unserialize block from stream"""
        from cryptogenesis.transaction import Transaction

        self.version = struct.unpack("<i", stream.read(4))[0]
        self.prev_block_hash = hash_to_uint256(stream.read(32))
        self.merkle_root = hash_to_uint256(stream.read(32))
        time_bits_nonce = struct.unpack("<III", stream.read(12))
        self.time = time_bits_nonce[0]
        self.bits = time_bits_nonce[1]
        self.nonce = time_bits_nonce[2]

        if not (stream_type & 0x20000):  # SER_BLOCKHEADERONLY
            tx_size, _ = read_compact_size(stream.vch, stream.n_read_pos)
            stream.n_read_pos += get_size_of_compact_size(tx_size)
            self.transactions = []
            for _ in range(tx_size):
                tx = Transaction()
                tx.unserialize(stream, stream_type, version)
                self.transactions.append(tx)
        else:
            self.transactions = []

    def check_block(self) -> bool:
        """Check block validity"""
        # Size limits
        if len(self.transactions) == 0:
            return False

        # Check timestamp
        current_time = int(time.time())
        if self.time > current_time + 2 * 60 * 60:
            return False

        # First transaction must be coinbase
        if len(self.transactions) == 0 or not self.transactions[0].is_coinbase():
            return False

        # Rest must not be coinbase
        for i in range(1, len(self.transactions)):
            if self.transactions[i].is_coinbase():
                return False

        # Check transactions
        for tx in self.transactions:
            if not tx.check_transaction():
                return False

        # Check proof of work
        # (Simplified - would need BigNum for full check)
        block_hash = self.get_hash()
        target = self.get_target()
        if block_hash > target:
            return False

        # Check merkle root
        if self.merkle_root != self.build_merkle_tree():
            return False

        return True

    def get_target(self) -> uint256:
        """Get proof of work target from bits"""
        # Compact format: first byte is exponent, next 3 bytes are mantissa
        exponent = (self.bits >> 24) & 0xFF
        mantissa = self.bits & 0xFFFFFF

        if exponent <= 3:
            target = uint256(mantissa)
            target = target >> (8 * (3 - exponent))
        else:
            target = uint256(mantissa)
            target = target << (8 * (exponent - 3))

        return target

    def get_block_value(self, fees: int, best_height: int = 0) -> int:
        """Get block reward value"""
        subsidy = 50 * COIN

        # Subsidy is cut in half every 210000 blocks
        subsidy >>= best_height // 210000

        return subsidy + fees

    def set_null(self):
        """Set block to null"""
        self.version = 1
        self.prev_block_hash = uint256(0)
        self.merkle_root = uint256(0)
        self.time = 0
        self.bits = 0
        self.nonce = 0
        self.transactions.clear()
        self.merkle_tree.clear()

    def is_null(self) -> bool:
        """Check if block is null"""
        return self.bits == 0

    def __str__(self):
        return (
            f"Block(hash={self.get_hash().get_hex()[:14]}, "
            f"version={self.version}, prev={self.prev_block_hash.get_hex()[:14]}, "
            f"merkle={self.merkle_root.get_hex()[:6]}, "
            f"time={self.time}, bits={self.bits:08x}, nonce={self.nonce}, "
            f"transactions={len(self.transactions)})"
        )

    def __repr__(self):
        return (
            f"Block(version={self.version}, height={getattr(self, 'height', '?')}, "
            f"hash={self.get_hash().get_hex()[:12]}...)"
        )


def get_next_work_required(index_last: Optional[BlockIndex]) -> int:
    """Calculate next proof of work target"""
    target_timespan = 14 * 24 * 60 * 60  # two weeks
    target_spacing = 10 * 60  # 10 minutes
    interval = target_timespan // target_spacing

    # Genesis block
    if index_last is None:
        return 0x1D00FFFF  # Initial difficulty

    # Only change once per interval
    if (index_last.height + 1) % interval != 0:
        return index_last.bits

    # Go back by what we want to be 14 days worth of blocks
    index_first = index_last
    for _ in range(interval - 1):
        if index_first.prev:
            index_first = index_first.prev
        else:
            break

    # Limit adjustment step
    actual_timespan = index_last.time - index_first.time
    if actual_timespan < target_timespan // 4:
        actual_timespan = target_timespan // 4
    if actual_timespan > target_timespan * 4:
        actual_timespan = target_timespan * 4

    # Retarget (simplified - would need BigNum for full implementation)
    # For now, return the same difficulty
    return index_last.bits
