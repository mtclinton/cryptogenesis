"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Transaction pool (mempool) management
"""

import threading
from collections import OrderedDict, defaultdict
from typing import Dict, List, Optional

from cryptogenesis.serialize import SER_NETWORK, DataStream
from cryptogenesis.transaction import OutPoint, Transaction
from cryptogenesis.uint256 import uint256
from cryptogenesis.util import error

# Maximum number of orphan transactions to keep in memory
# Prevents unbounded growth of orphan pool
MAX_ORPHAN_TRANSACTIONS = 1000


class InPoint:
    """Input point - tracks which transaction and input index spends an output"""

    def __init__(self, tx: Optional[Transaction] = None, n: int = -1):
        self.tx = tx
        self.n = n

    def set_null(self):
        """Set to null"""
        self.tx = None
        self.n = -1

    def is_null(self) -> bool:
        """Check if null"""
        return self.tx is None and self.n == -1


class Mempool:
    """Transaction memory pool"""

    def __init__(self):
        # Map of transaction hash to Transaction
        self.transactions: Dict[uint256, Transaction] = {}
        self.transactions_lock = threading.Lock()

        # Map of OutPoint to InPoint (which tx/input spends this output)
        self.next_tx: Dict[OutPoint, InPoint] = {}
        self.next_tx_lock = threading.Lock()

        # Orphan transactions (transactions with missing inputs)
        # Use OrderedDict to track insertion order for FIFO eviction
        # Map of tx hash to serialized transaction data
        self.orphan_transactions: OrderedDict[uint256, bytes] = OrderedDict()
        # Map of prevout hash to list of orphan transaction hashes
        self.orphan_transactions_by_prev: Dict[uint256, List[uint256]] = defaultdict(list)
        self.orphan_lock = threading.Lock()

        # Transaction update counter
        self.transactions_updated = 0

    def add_transaction(self, tx: Transaction) -> bool:
        """Add transaction to memory pool without checking"""
        with self.transactions_lock:
            tx_hash = tx.get_hash()
            self.transactions[tx_hash] = tx

            # Update mapNextTx - track which inputs spend which outputs
            with self.next_tx_lock:
                for i, txin in enumerate(tx.vin):
                    self.next_tx[txin.prevout] = InPoint(tx, i)

            self.transactions_updated += 1
        return True

    def remove_transaction(self, tx_hash: uint256) -> bool:
        """Remove transaction from memory pool"""
        with self.transactions_lock:
            if tx_hash not in self.transactions:
                return False

            tx = self.transactions[tx_hash]

            # Remove from mapNextTx
            with self.next_tx_lock:
                for txin in tx.vin:
                    if txin.prevout in self.next_tx:
                        del self.next_tx[txin.prevout]

            del self.transactions[tx_hash]
            self.transactions_updated += 1
        return True

    def get_transaction(self, tx_hash: uint256) -> Optional[Transaction]:
        """Get transaction from pool"""
        with self.transactions_lock:
            return self.transactions.get(tx_hash)

    def has_transaction(self, tx_hash: uint256) -> bool:
        """Check if transaction is in pool"""
        with self.transactions_lock:
            return tx_hash in self.transactions

    def get_next_tx(self, outpoint: OutPoint) -> Optional[InPoint]:
        """Get which transaction spends this output"""
        with self.next_tx_lock:
            return self.next_tx.get(outpoint)

    def is_output_spent(self, outpoint: OutPoint) -> bool:
        """Check if an output is spent by a transaction in the pool"""
        with self.next_tx_lock:
            return outpoint in self.next_tx

    def add_orphan_transaction(self, tx_data: bytes):
        """
        Add orphan transaction (transaction with missing inputs)
        Enforces MAX_ORPHAN_TRANSACTIONS limit by evicting oldest entries
        """
        # Deserialize to get the transaction
        stream = DataStream(SER_NETWORK)
        stream.vch = bytearray(tx_data)
        tx = Transaction()
        try:
            tx.unserialize(stream, SER_NETWORK)
        except Exception:
            return

        tx_hash = tx.get_hash()

        with self.orphan_lock:
            if tx_hash in self.orphan_transactions:
                # Move to end (most recently used)
                self.orphan_transactions.move_to_end(tx_hash)
                return

            # Enforce orphan transaction limit (evict oldest if needed)
            while len(self.orphan_transactions) >= MAX_ORPHAN_TRANSACTIONS:
                # Evict oldest orphan transaction (FIFO)
                oldest_hash, _ = self.orphan_transactions.popitem(last=False)
                self._erase_orphan_transaction_internal(oldest_hash)

            # Add new orphan transaction
            self.orphan_transactions[tx_hash] = tx_data

            # Index by previous transaction hashes
            for txin in tx.vin:
                if not txin.prevout.is_null():
                    self.orphan_transactions_by_prev[txin.prevout.hash].append(tx_hash)

    def _erase_orphan_transaction_internal(self, tx_hash: uint256):
        """
        Internal method to erase orphan transaction (assumes lock is held)
        """
        if tx_hash not in self.orphan_transactions:
            return

        tx_data = self.orphan_transactions[tx_hash]

        # Deserialize to get transaction
        stream = DataStream(SER_NETWORK)
        stream.vch = bytearray(tx_data)
        tx = Transaction()
        try:
            tx.unserialize(stream, SER_NETWORK)
        except Exception:
            pass
        else:
            # Remove from index
            for txin in tx.vin:
                if not txin.prevout.is_null():
                    prev_hash = txin.prevout.hash
                    if prev_hash in self.orphan_transactions_by_prev:
                        if tx_hash in self.orphan_transactions_by_prev[prev_hash]:
                            self.orphan_transactions_by_prev[prev_hash].remove(tx_hash)
                        if not self.orphan_transactions_by_prev[prev_hash]:
                            del self.orphan_transactions_by_prev[prev_hash]

        del self.orphan_transactions[tx_hash]

    def erase_orphan_transaction(self, tx_hash: uint256):
        """Remove orphan transaction"""
        with self.orphan_lock:
            self._erase_orphan_transaction_internal(tx_hash)

    def get_orphan_transactions_by_prev(self, prev_hash: uint256) -> List[uint256]:
        """Get orphan transactions that depend on a previous transaction"""
        with self.orphan_lock:
            return list(self.orphan_transactions_by_prev.get(prev_hash, []))

    def get_orphan_transaction(self, tx_hash: uint256) -> Optional[bytes]:
        """Get orphan transaction data"""
        with self.orphan_lock:
            return self.orphan_transactions.get(tx_hash)

    def has_orphan_transaction(self, tx_hash: uint256) -> bool:
        """Check if transaction is an orphan"""
        with self.orphan_lock:
            return tx_hash in self.orphan_transactions

    def get_all_transactions(self) -> List[Transaction]:
        """Get all transactions in pool"""
        with self.transactions_lock:
            return list(self.transactions.values())

    def get_transaction_count(self) -> int:
        """Get number of transactions in pool"""
        with self.transactions_lock:
            return len(self.transactions)

    def get_orphan_count(self) -> int:
        """Get number of orphan transactions"""
        with self.orphan_lock:
            return len(self.orphan_transactions)

    def clear(self):
        """Clear the mempool"""
        with self.transactions_lock:
            self.transactions.clear()
        with self.next_tx_lock:
            self.next_tx.clear()
        with self.orphan_lock:
            self.orphan_transactions.clear()
            self.orphan_transactions_by_prev.clear()
        self.transactions_updated += 1


# Global mempool instance
_mempool: Optional[Mempool] = None
_mempool_lock = threading.Lock()


def get_mempool() -> Mempool:
    """Get the global mempool instance"""
    global _mempool
    with _mempool_lock:
        if _mempool is None:
            _mempool = Mempool()
        return _mempool


def accept_transaction(
    tx: Transaction, check_inputs: bool = True, check_utxos: bool = False
) -> tuple[bool, Optional[bool]]:
    """
    Accept a transaction into the mempool

    Args:
        tx: Transaction to accept
        check_inputs: Whether to check inputs (requires UTXO management if True)
        check_utxos: Whether to check UTXOs (requires full UTXO management)

    Returns:
        (success, missing_inputs) where missing_inputs is True if inputs are missing
    """
    mempool = get_mempool()

    # Coinbase is only valid in a block, not as a loose transaction
    if tx.is_coinbase():
        error("AcceptTransaction() : coinbase as individual tx")
        return False, None

    # Basic transaction check (includes size limit check)
    if not tx.check_transaction():
        error("AcceptTransaction() : CheckTransaction failed")
        return False, None

    tx_hash = tx.get_hash()

    # Calculate minimum fee required (strict enforcement)
    # For mempool acceptance, use discount=false (strict fee requirement)
    n_min_fee = tx.get_min_fee(f_discount=False)

    # Do we already have it?
    if mempool.has_transaction(tx_hash):
        return False, None

    # Check for conflicts with in-memory transactions
    tx_old: Optional[Transaction] = None
    for i, txin in enumerate(tx.vin):
        outpoint = txin.prevout
        in_point = mempool.get_next_tx(outpoint)
        if in_point and not in_point.is_null():
            # Allow replacing with a newer version of the same transaction
            if i != 0:
                return False, None
            tx_old = in_point.tx
            if tx_old is None:
                continue

            # Check if new transaction is newer (simplified - just check if same inputs)
            if not _is_newer_than(tx, tx_old):
                return False, None

            # Verify all inputs are from the same old transaction
            for j, txin2 in enumerate(tx.vin):
                outpoint2 = txin2.prevout
                in_point2 = mempool.get_next_tx(outpoint2)
                if not in_point2 or in_point2.is_null() or in_point2.tx != tx_old:
                    return False, None
            break

    # Check inputs using ConnectInputs
    missing_inputs = False
    if check_inputs:
        from cryptogenesis.utxo import get_txdb

        txdb = get_txdb()

        # Use ConnectInputs to validate inputs with strict minimum fee enforcement
        success, fees = tx.connect_inputs(  # type: ignore[attr-defined]
            txdb,
            map_test_pool={},
            pos_this_tx=None,
            height=0,
            fees=0,
            is_block=False,
            is_miner=False,
            min_fee=n_min_fee,
        )

        if not success:
            # Check if it's due to missing inputs
            for txin in tx.vin:
                if txin.prevout.is_null():
                    continue
                outpoint = txin.prevout
                # Check if output exists in mempool or database
                if not mempool.has_transaction(outpoint.hash):
                    from cryptogenesis.chain import get_chain

                    chain = get_chain()
                    if not chain.has_block(outpoint.hash) and not txdb.contains_tx(outpoint.hash):
                        missing_inputs = True
                        break
            if not missing_inputs:
                error(
                    "AcceptTransaction() : ConnectInputs failed %s",
                    tx_hash.get_hex()[:6],
                )
            return False, missing_inputs

    # Store transaction in memory
    if tx_old:
        print(f"mapTransaction.erase({tx_old.get_hash().get_hex()[:6]}) replacing with new version")
        mempool.remove_transaction(tx_old.get_hash())

    mempool.add_transaction(tx)

    print(f"AcceptTransaction(): accepted {tx_hash.get_hex()[:6]}")
    return True, missing_inputs if missing_inputs else None


def _is_newer_than(tx_new: Transaction, tx_old: Transaction) -> bool:
    """Check if new transaction is newer than old transaction"""
    if len(tx_new.vin) != len(tx_old.vin):
        return False
    for i in range(len(tx_new.vin)):
        if tx_new.vin[i].prevout != tx_old.vin[i].prevout:
            return False
    # New transaction is newer if it has the same inputs
    return True
