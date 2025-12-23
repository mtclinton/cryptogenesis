"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Wallet functionality - CWallet, CWalletTx, CMerkleTx
"""

import threading
from typing import Dict, List, Optional, Set, Tuple

from cryptogenesis.block import Block
from cryptogenesis.chain import get_chain
from cryptogenesis.crypto import Key, hash160
from cryptogenesis.transaction import COINBASE_MATURITY, Script, Transaction, TxIn, TxOut
from cryptogenesis.uint256 import uint160, uint256
from cryptogenesis.util import error
from cryptogenesis.utxo import TxDB, get_txdb

# Global wallet state (matches Bitcoin v0.1)
map_wallet: Dict[uint256, "WalletTx"] = {}
wallet_lock = threading.Lock()
v_wallet_updated: List[Tuple[uint256, bool]] = []

# Key management (matches Bitcoin v0.1)
map_keys: Dict[bytes, bytes] = {}  # pubkey -> privkey
map_pub_keys: Dict[uint160, bytes] = {}  # hash160(pubkey) -> pubkey
keys_lock = threading.Lock()
key_user: Optional[Key] = None


class MerkleTx(Transaction):
    """
    A transaction with a merkle branch linking it to the block chain
    (CMerkleTx equivalent)
    """

    def __init__(self, tx: Optional[Transaction] = None):
        if tx:
            # Copy transaction data
            super().__init__()
            self.version = tx.version
            self.vin = tx.vin[:]
            self.vout = tx.vout[:]
            self.lock_time = tx.lock_time
        else:
            super().__init__()

        # Merkle branch info
        self.hash_block: uint256 = uint256(0)
        self.v_merkle_branch: List[uint256] = []
        self.n_index: int = -1
        self.f_merkle_verified: bool = False

    def set_merkle_branch(self, block: Optional[Block] = None) -> int:
        """
        Set merkle branch for this transaction

        Args:
            block: Block containing this transaction (if None, loads from disk)

        Returns:
            Depth in main chain, or 0 if not in main chain
        """
        from cryptogenesis.chain import get_chain

        chain = get_chain()

        if block is None:
            # Load the block this tx is in
            txdb = get_txdb()
            txindex = txdb.read_tx_index(self.get_hash())
            if not txindex or txindex.pos.is_null():
                return 0

            # For now, we'll need to find the block by hash
            # In a full implementation, we'd read from disk
            # For now, check if block is in chain
            # This is simplified - full version would read from disk
            return 0

        # Update the tx's hashBlock
        self.hash_block = block.get_hash()

        # Locate the transaction
        self.n_index = -1
        for i, tx in enumerate(block.transactions):
            if tx.get_hash() == self.get_hash():
                self.n_index = i
                break

        if self.n_index == -1:
            self.v_merkle_branch.clear()
            self.n_index = -1
            error("SetMerkleBranch() : couldn't find tx in block")
            return 0

        # Fill in merkle branch
        self.v_merkle_branch = block.get_merkle_branch(self.n_index)

        # Is the tx in a block that's in the main chain
        best_index = chain.get_best_index()
        if not best_index:
            return 0

        block_index = chain.get_block_index(self.hash_block)
        if not block_index or not block_index.is_in_main_chain(best_index):
            return 0

        best_height = chain.get_best_height()
        return best_height - block_index.height + 1

    def get_depth_in_main_chain(self) -> int:
        """Get depth of transaction in main chain"""
        if self.hash_block == uint256(0) or self.n_index == -1:
            return 0

        chain = get_chain()
        block_index = chain.get_block_index(self.hash_block)
        if not block_index:
            return 0

        best_index = chain.get_best_index()
        if not best_index or not block_index.is_in_main_chain(best_index):
            return 0

        # Make sure the merkle branch connects to this block
        if not self.f_merkle_verified:
            from cryptogenesis.block import Block

            merkle_root = Block.check_merkle_branch(
                self.get_hash(), self.v_merkle_branch, self.n_index
            )
            if merkle_root != block_index.merkle_root:
                return 0
            self.f_merkle_verified = True

        best_height = chain.get_best_height()
        return best_height - block_index.height + 1

    def is_in_main_chain(self) -> bool:
        """Check if transaction is in main chain"""
        return self.get_depth_in_main_chain() > 0

    def get_blocks_to_maturity(self) -> int:
        """Get blocks until coinbase is mature"""
        if not self.is_coinbase():
            return 0
        depth = self.get_depth_in_main_chain()
        return max(0, (COINBASE_MATURITY + 20) - depth)

    def get_credit(self) -> int:
        """
        Get credit (outputs that are mine)
        Must wait until coinbase is safely deep enough
        """
        # Must wait until coinbase is safely deep enough in the chain before valuing it
        if self.is_coinbase() and self.get_blocks_to_maturity() > 0:
            return 0
        return super().get_credit()  # type: ignore[misc]

    def accept_transaction(self, txdb: TxDB, f_check_inputs: bool = True) -> bool:
        """Accept transaction (CMerkleTx::AcceptTransaction)"""
        # For now, use mempool accept_transaction
        # In client mode, would use ClientConnectInputs
        from cryptogenesis.mempool import accept_transaction as accept_tx

        success, _ = accept_tx(self, f_check_inputs)
        return success


class WalletTx(MerkleTx):
    """
    A transaction with additional info that only the owner cares about
    (CWalletTx equivalent)
    """

    def __init__(self, tx: Optional[Transaction] = None):
        if isinstance(tx, MerkleTx):
            super().__init__(tx)
            # Copy merkle branch info
            self.hash_block = tx.hash_block
            self.v_merkle_branch = tx.v_merkle_branch[:]
            self.n_index = tx.n_index
            self.f_merkle_verified = tx.f_merkle_verified
        elif tx:
            super().__init__(tx)
        else:
            super().__init__()

        # Wallet-specific info
        self.vtx_prev: List[MerkleTx] = []
        self.map_value: Dict[str, str] = {}
        self.v_order_form: List[Tuple[str, str]] = []
        self.f_time_received_is_tx_time: bool = False
        self.n_time_received: int = 0
        self.f_from_me: bool = False
        self.f_spent: bool = False
        self.n_time_displayed: int = 0  # memory only

    def get_tx_time(self) -> int:
        """Get transaction time"""
        if not self.f_time_received_is_tx_time and self.hash_block != uint256(0):
            # If we did not receive the transaction directly, we rely on the block's
            # time to figure out when it happened.  We use the median over a range
            # of blocks to try to filter out inaccurate block times.
            chain = get_chain()
            block_index = chain.get_block_index(self.hash_block)
            if block_index:
                return block_index.get_median_time_past()
        return self.n_time_received

    def add_supporting_transactions(self, txdb: TxDB):
        """Add supporting transactions (vtxPrev)"""
        self.vtx_prev.clear()

        COPY_DEPTH = 3
        if self.set_merkle_branch() < COPY_DEPTH:
            v_work_queue: List[uint256] = []
            for txin in self.vin:
                v_work_queue.append(txin.prevout.hash)

            with wallet_lock:
                map_wallet_prev: Dict[uint256, MerkleTx] = {}
                set_already_done: Set[uint256] = set()

                i = 0
                while i < len(v_work_queue):
                    hash_tx = v_work_queue[i]
                    i += 1

                    if hash_tx in set_already_done:
                        continue
                    set_already_done.add(hash_tx)

                    tx = None
                    if hash_tx in map_wallet:
                        tx = MerkleTx(map_wallet[hash_tx])
                        for tx_wallet_prev in map_wallet[hash_tx].vtx_prev:
                            map_wallet_prev[tx_wallet_prev.get_hash()] = tx_wallet_prev
                    elif hash_tx in map_wallet_prev:
                        tx = map_wallet_prev[hash_tx]
                    else:
                        # Try to read from disk
                        tx_disk = txdb.read_disk_tx(hash_tx)
                        if tx_disk:
                            tx = MerkleTx(tx_disk)
                        else:
                            print(
                                f"ERROR: AddSupportingTransactions() : "
                                f"unsupported transaction {hash_tx.get_hex()[:6]}"
                            )
                            continue

                    n_depth = tx.set_merkle_branch()
                    self.vtx_prev.append(tx)

                    if n_depth < COPY_DEPTH:
                        for txin in tx.vin:
                            if txin.prevout.hash not in set_already_done:
                                v_work_queue.append(txin.prevout.hash)

                # Reverse to get chronological order
                self.vtx_prev.reverse()

    def accept_wallet_transaction(self, txdb: TxDB, f_check_inputs: bool = True) -> bool:
        """Accept wallet transaction"""
        from cryptogenesis.mempool import get_mempool

        mempool = get_mempool()

        # Accept supporting transactions
        for tx in self.vtx_prev:
            if not tx.is_coinbase():
                hash_tx = tx.get_hash()
                if not mempool.has_transaction(hash_tx) and not txdb.contains_tx(hash_tx):
                    from cryptogenesis.mempool import accept_transaction as accept_tx

                    success, _ = accept_tx(tx, f_check_inputs)
                    if not success:
                        return False

        # Accept this transaction
        if not self.is_coinbase():
            return self.accept_transaction(txdb, f_check_inputs)
        return True

    def relay_wallet_transaction(self, txdb: TxDB):
        """Relay wallet transaction to network"""
        from cryptogenesis.network import MSG_TX, Inv, relay_inventory

        # Relay supporting transactions
        for tx in self.vtx_prev:
            if not tx.is_coinbase():
                hash_tx = tx.get_hash()
                if not txdb.contains_tx(hash_tx):
                    inv = Inv(MSG_TX, hash_tx)
                    relay_inventory(inv)

        # Relay this transaction
        if not self.is_coinbase():
            hash_tx = self.get_hash()
            if not txdb.contains_tx(hash_tx):
                inv = Inv(MSG_TX, hash_tx)
                relay_inventory(inv)


# Key management functions


def add_key(key: Key) -> bool:
    """Add a key to the wallet"""
    global key_user

    pubkey = key.public_key
    privkey = key.private_key

    with keys_lock:
        map_keys[pubkey] = privkey
        pubkey_hash = hash160(pubkey)
        map_pub_keys[uint160(pubkey_hash)] = pubkey

    # Set as user key if not set
    if key_user is None:
        key_user = key

    # In full implementation, would write to wallet database
    # return CWalletDB().WriteKey(pubkey, privkey)
    return True


def generate_new_key() -> bytes:
    """Generate a new key and add it to wallet"""
    key = Key()
    key.generate_new_key()
    if not add_key(key):
        raise RuntimeError("GenerateNewKey() : AddKey failed")
    return key.public_key


# Wallet transaction management


def add_to_wallet(wtx_in: WalletTx) -> bool:
    """Add transaction to wallet (AddToWallet)"""
    hash_tx = wtx_in.get_hash()

    with wallet_lock:
        # Inserts only if not already there, returns tx inserted or tx found
        if hash_tx in map_wallet:
            wtx = map_wallet[hash_tx]
            f_inserted_new = False
        else:
            wtx = WalletTx(wtx_in)
            map_wallet[hash_tx] = wtx
            f_inserted_new = True
            from cryptogenesis.util import get_adjusted_time

            wtx.n_time_received = get_adjusted_time()

        print(f"AddToWallet {hash_tx.get_hex()[:6]}  {'new' if f_inserted_new else 'update'}")

        if not f_inserted_new:
            # Merge
            f_updated = False
            if wtx_in.hash_block != uint256(0) and wtx_in.hash_block != wtx.hash_block:
                wtx.hash_block = wtx_in.hash_block
                f_updated = True

            if wtx_in.n_index != -1 and wtx_in.n_index != wtx.n_index:
                wtx.n_index = wtx_in.n_index
                f_updated = True

            if wtx_in.v_merkle_branch and wtx_in.v_merkle_branch != wtx.v_merkle_branch:
                wtx.v_merkle_branch = wtx_in.v_merkle_branch[:]
                f_updated = True

            if f_updated:
                v_wallet_updated.append((hash_tx, False))

        # In full implementation, would write to wallet database
        # wtx.WriteToDisk()

        v_wallet_updated.append((hash_tx, f_inserted_new))

    return True


def add_to_wallet_if_mine(tx: Transaction, block: Optional[Block] = None) -> bool:
    """Add transaction to wallet if it's mine"""
    if tx.is_mine() or tx.get_hash() in map_wallet:  # type: ignore[attr-defined]
        wtx = WalletTx(tx)
        # Get merkle branch if transaction was found in a block
        if block:
            wtx.set_merkle_branch(block)
        return add_to_wallet(wtx)
    return True


def erase_from_wallet(hash_tx: uint256) -> bool:
    """Erase transaction from wallet"""
    with wallet_lock:
        if hash_tx in map_wallet:
            del map_wallet[hash_tx]
            # In full implementation, would erase from wallet database
            # CWalletDB().EraseTx(hash_tx)
    return True


def reaccept_wallet_transactions():
    """Reaccept any txes of ours that aren't already in a block"""
    txdb = get_txdb()
    with wallet_lock:
        for hash_tx, wtx in list(map_wallet.items()):
            if not wtx.is_coinbase() and not txdb.contains_tx(hash_tx):
                wtx.accept_wallet_transaction(txdb, False)


def relay_wallet_transactions():
    """Relay all wallet transactions to network"""
    txdb = get_txdb()
    with wallet_lock:
        for wtx in map_wallet.values():
            wtx.relay_wallet_transaction(txdb)


# IsMine functions


def is_mine(script_pubkey: Script) -> bool:
    """
    Check if script belongs to wallet (IsMine)
    Matches Bitcoin v0.1 Solver logic
    """
    # Templates for standard transaction types
    # Standard tx: pubkey OP_CHECKSIG
    # P2PKH tx: OP_DUP OP_HASH160 pubkeyhash OP_EQUALVERIFY OP_CHECKSIG

    # For now, simplified check - look for pubkey or pubkeyhash in script
    # Full implementation would use Solver to match templates

    with keys_lock:
        # Check if script contains any of our public keys
        for pubkey in map_keys.keys():
            if pubkey in script_pubkey.data:
                return True

        # Check if script contains any of our pubkey hashes
        for pubkey_hash, pubkey in map_pub_keys.items():
            hash_bytes = pubkey_hash.to_bytes()
            if hash_bytes in script_pubkey.data:
                return True

    return False


# Extend Transaction and TxOut with IsMine methods


def _txout_is_mine(self: TxOut) -> bool:
    """Check if output is mine"""
    return is_mine(self.script_pubkey)


def _txout_get_credit(self: TxOut) -> int:
    """Get credit (value if output is mine)"""
    if self.is_mine():  # type: ignore[attr-defined]
        return self.value
    return 0


def _txin_is_mine(self: TxIn) -> bool:
    """Check if input is mine"""
    with wallet_lock:
        if self.prevout.hash in map_wallet:
            prev = map_wallet[self.prevout.hash]
            if self.prevout.n < len(prev.vout):
                return prev.vout[self.prevout.n].is_mine()  # type: ignore[attr-defined]
    return False


def _txin_get_debit(self: TxIn) -> int:
    """Get debit (value spent) for input"""
    with wallet_lock:
        if self.prevout.hash in map_wallet:
            prev = map_wallet[self.prevout.hash]
            if self.prevout.n < len(prev.vout):
                if prev.vout[self.prevout.n].is_mine():  # type: ignore[attr-defined]
                    return prev.vout[self.prevout.n].value
    return 0


def _transaction_is_mine(self: Transaction) -> bool:
    """Check if transaction is mine"""
    for txout in self.vout:
        if txout.is_mine():  # type: ignore[attr-defined]
            return True
    return False


def _transaction_get_debit(self: Transaction) -> int:
    """Get total debit (value spent)"""
    n_debit = 0
    for txin in self.vin:
        n_debit += txin.get_debit()  # type: ignore[attr-defined]
    return n_debit


def _transaction_get_credit(self: Transaction) -> int:
    """Get total credit (value received)"""
    n_credit = 0
    for txout in self.vout:
        n_credit += txout.get_credit()  # type: ignore[attr-defined]
    return n_credit


# Add methods to existing classes (monkey-patching)
# These are added dynamically, so mypy won't see them without type: ignore
TxOut.is_mine = _txout_is_mine  # type: ignore[attr-defined]
TxOut.get_credit = _txout_get_credit  # type: ignore[attr-defined]
TxIn.is_mine = _txin_is_mine  # type: ignore[attr-defined]
TxIn.get_debit = _txin_get_debit  # type: ignore[attr-defined]
Transaction.is_mine = _transaction_is_mine  # type: ignore[attr-defined]
Transaction.get_debit = _transaction_get_debit  # type: ignore[attr-defined]
Transaction.get_credit = _transaction_get_credit  # type: ignore[attr-defined]


def get_balance() -> int:
    """Get wallet balance"""
    n_total = 0
    with wallet_lock:
        for wtx in map_wallet.values():
            n_total += wtx.get_credit()  # type: ignore[attr-defined]
            n_total -= wtx.get_debit()  # type: ignore[attr-defined]
    return n_total


# Module-level getters
def get_wallet() -> Dict[uint256, WalletTx]:
    """Get wallet map"""
    return map_wallet


def get_wallet_lock():
    """Get wallet lock"""
    return wallet_lock
