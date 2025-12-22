"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

UTXO management and transaction database
"""

import struct
import threading
from typing import Dict, List, Optional

from cryptogenesis.serialize import SER_DISK, DataStream
from cryptogenesis.transaction import Transaction
from cryptogenesis.uint256 import uint256


class DiskTxPos:
    """Transaction position on disk"""

    def __init__(self, file_num: int = -1, block_pos: int = 0, tx_pos: int = 0):
        self.file_num = file_num
        self.block_pos = block_pos
        self.tx_pos = tx_pos

    def set_null(self):
        """Set to null position"""
        self.file_num = -1
        self.block_pos = 0
        self.tx_pos = 0

    def is_null(self) -> bool:
        """Check if position is null"""
        return self.file_num == -1

    def serialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Serialize to stream"""
        stream.write(struct.pack("<III", self.file_num, self.block_pos, self.tx_pos))

    def unserialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Unserialize from stream"""
        data = stream.read(12)
        if len(data) < 12:
            raise ValueError("Not enough data for DiskTxPos")
        self.file_num, self.block_pos, self.tx_pos = struct.unpack("<III", data)

    def __eq__(self, other) -> bool:
        """Equality comparison"""
        if not isinstance(other, DiskTxPos):
            return False
        return (
            self.file_num == other.file_num
            and self.block_pos == other.block_pos
            and self.tx_pos == other.tx_pos
        )

    def __ne__(self, other) -> bool:
        """Inequality comparison"""
        return not self.__eq__(other)

    def __str__(self) -> str:
        """String representation"""
        if self.is_null():
            return "DiskTxPos(null)"
        return f"DiskTxPos(file={self.file_num}, block={self.block_pos}, tx={self.tx_pos})"


class TxIndex:
    """Transaction index - tracks transaction position and spent outputs"""

    def __init__(self, pos: Optional[DiskTxPos] = None, n_outputs: int = 0):
        self.pos = pos if pos else DiskTxPos()
        self.spent: List[DiskTxPos] = []
        if n_outputs > 0:
            self.spent = [DiskTxPos() for _ in range(n_outputs)]

    def set_null(self):
        """Set to null"""
        self.pos.set_null()
        self.spent.clear()

    def is_null(self) -> bool:
        """Check if index is null"""
        return self.pos.is_null()

    def serialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Serialize to stream"""
        if not (n_type & SER_DISK):
            # Write version if not hashing
            stream.write(struct.pack("<i", n_version))
        self.pos.serialize(stream, n_type, n_version)
        # Write spent array
        from cryptogenesis.serialize import write_compact_size

        write_compact_size(stream.vch, len(self.spent))  # type: ignore
        for spent_pos in self.spent:
            spent_pos.serialize(stream, n_type, n_version)

    def unserialize(self, stream: DataStream, n_type: int = 0, n_version: int = 101):
        """Unserialize from stream"""
        if not (n_type & SER_DISK):
            # Read version if present
            data = stream.read(4)
            if len(data) < 4:
                raise ValueError("Not enough data for version")
            struct.unpack("<i", data)[0]  # Read and discard version
        self.pos.unserialize(stream, n_type, n_version)
        # Read spent array
        from cryptogenesis.serialize import read_compact_size

        size, _ = read_compact_size(stream.vch, stream.n_read_pos)
        stream.n_read_pos += (
            1 if size < 253 else (3 if size <= 0xFFFF else (5 if size <= 0xFFFFFFFF else 9))
        )
        self.spent = []
        for _ in range(size):
            spent_pos = DiskTxPos()
            spent_pos.unserialize(stream, n_type, n_version)
            self.spent.append(spent_pos)

    def __eq__(self, other) -> bool:
        """Equality comparison"""
        if not isinstance(other, TxIndex):
            return False
        if self.pos != other.pos or len(self.spent) != len(other.spent):
            return False
        for i, spent_pos in enumerate(self.spent):
            if spent_pos != other.spent[i]:
                return False
        return True


class TxDB:
    """Transaction database (in-memory implementation)"""

    def __init__(self):
        # Map of transaction hash to TxIndex
        self.tx_index: Dict[uint256, TxIndex] = {}
        self.lock = threading.Lock()

        # Map of transaction hash to Transaction (for quick lookup)
        self.transactions: Dict[uint256, Transaction] = {}

    def read_tx_index(self, tx_hash: uint256) -> Optional[TxIndex]:
        """Read transaction index"""
        with self.lock:
            return self.tx_index.get(tx_hash)

    def update_tx_index(self, tx_hash: uint256, txindex: TxIndex) -> bool:
        """Update transaction index"""
        with self.lock:
            self.tx_index[tx_hash] = txindex
            return True

    def add_tx_index(self, tx: Transaction, pos: DiskTxPos, height: int) -> bool:
        """Add transaction index"""
        with self.lock:
            tx_hash = tx.get_hash()
            txindex = TxIndex(pos, len(tx.vout))
            self.tx_index[tx_hash] = txindex
            self.transactions[tx_hash] = tx
            return True

    def erase_tx_index(self, tx: Transaction) -> bool:
        """Erase transaction index"""
        with self.lock:
            tx_hash = tx.get_hash()
            if tx_hash in self.tx_index:
                del self.tx_index[tx_hash]
            if tx_hash in self.transactions:
                del self.transactions[tx_hash]
            return True

    def contains_tx(self, tx_hash: uint256) -> bool:
        """Check if transaction exists in database"""
        with self.lock:
            return tx_hash in self.tx_index

    def read_disk_tx(self, tx_hash: uint256) -> Optional[Transaction]:
        """Read transaction from database"""
        with self.lock:
            return self.transactions.get(tx_hash)

    def read_disk_tx_by_outpoint(self, outpoint) -> Optional[Transaction]:
        """Read transaction by outpoint"""
        return self.read_disk_tx(outpoint.hash)


# Global transaction database instance
_txdb: Optional[TxDB] = None
_txdb_lock = threading.Lock()


def get_txdb() -> TxDB:
    """Get the global transaction database instance"""
    global _txdb
    with _txdb_lock:
        if _txdb is None:
            _txdb = TxDB()
        return _txdb
