"""
Tests for mempool functionality
"""

from .context import cryptogenesis


def test_mempool_initialization():
    """Test mempool initialization"""
    mempool = cryptogenesis.get_mempool()
    assert isinstance(mempool, cryptogenesis.Mempool)
    assert mempool.get_transaction_count() == 0
    assert mempool.get_orphan_count() == 0


def test_add_transaction():
    """Test adding transaction to mempool"""
    mempool = cryptogenesis.get_mempool()
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    mempool.add_transaction(tx)
    assert mempool.get_transaction_count() == 1
    assert mempool.has_transaction(tx.get_hash())


def test_remove_transaction():
    """Test removing transaction from mempool"""
    mempool = cryptogenesis.get_mempool()
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    tx_hash = tx.get_hash()
    mempool.add_transaction(tx)
    assert mempool.has_transaction(tx_hash)

    mempool.remove_transaction(tx_hash)
    assert not mempool.has_transaction(tx_hash)
    assert mempool.get_transaction_count() == 0


def test_next_tx_tracking():
    """Test mapNextTx tracking"""
    mempool = cryptogenesis.get_mempool()

    # Create a transaction with an output
    tx1 = cryptogenesis.Transaction()
    tx1.vin = [cryptogenesis.TxIn()]
    tx1.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
    tx1_hash = tx1.get_hash()
    mempool.add_transaction(tx1)

    # Create a second transaction that spends the first
    outpoint = cryptogenesis.OutPoint(tx1_hash, 0)
    tx2 = cryptogenesis.Transaction()
    tx2.vin = [cryptogenesis.TxIn(outpoint, cryptogenesis.Script())]
    tx2.vout = [cryptogenesis.TxOut(5 * cryptogenesis.COIN, cryptogenesis.Script())]

    mempool.add_transaction(tx2)

    # Check that mapNextTx tracks the spending
    in_point = mempool.get_next_tx(outpoint)
    assert in_point is not None
    assert not in_point.is_null()
    assert in_point.tx == tx2
    assert in_point.n == 0


def test_orphan_transaction():
    """Test orphan transaction handling"""
    mempool = cryptogenesis.get_mempool()

    # Create a transaction that references a non-existent output
    fake_hash = cryptogenesis.uint256(12345)
    outpoint = cryptogenesis.OutPoint(fake_hash, 0)
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn(outpoint, cryptogenesis.Script())]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    # Serialize transaction
    stream = cryptogenesis.DataStream()
    tx.serialize(stream)
    tx_data = bytes(stream.vch)

    # Add as orphan
    mempool.add_orphan_transaction(tx_data)
    assert mempool.get_orphan_count() == 1
    assert mempool.has_orphan_transaction(tx.get_hash())

    # Check indexing by previous hash
    orphan_hashes = mempool.get_orphan_transactions_by_prev(fake_hash)
    assert len(orphan_hashes) == 1
    assert orphan_hashes[0] == tx.get_hash()


def test_accept_transaction():
    """Test accept_transaction function"""
    mempool = cryptogenesis.get_mempool()
    mempool.clear()

    # Create a valid transaction (non-coinbase)
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    success, missing = cryptogenesis.accept_transaction(tx, check_inputs=False)
    assert success
    assert missing is None
    assert mempool.has_transaction(tx.get_hash())


def test_accept_transaction_coinbase():
    """Test that coinbase transactions are rejected"""
    mempool = cryptogenesis.get_mempool()
    mempool.clear()

    # Create a coinbase transaction
    tx = cryptogenesis.Transaction()
    txin = cryptogenesis.TxIn()
    txin.prevout.set_null()
    tx.vin = [txin]
    tx.vout = [cryptogenesis.TxOut(50 * cryptogenesis.COIN, cryptogenesis.Script())]

    success, _ = cryptogenesis.accept_transaction(tx, check_inputs=False)
    assert not success  # Coinbase should be rejected


def test_orphan_processing():
    """Test processing orphan transactions when parent arrives"""
    mempool = cryptogenesis.get_mempool()
    mempool.clear()

    # Create parent transaction
    parent_tx = cryptogenesis.Transaction()
    parent_tx.vin = [cryptogenesis.TxIn()]
    parent_tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
    parent_hash = parent_tx.get_hash()

    # Create child transaction that depends on parent
    outpoint = cryptogenesis.OutPoint(parent_hash, 0)
    child_tx = cryptogenesis.Transaction()
    child_tx.vin = [cryptogenesis.TxIn(outpoint, cryptogenesis.Script())]
    child_tx.vout = [cryptogenesis.TxOut(5 * cryptogenesis.COIN, cryptogenesis.Script())]

    # Serialize child as orphan
    stream = cryptogenesis.DataStream()
    child_tx.serialize(stream)
    child_data = bytes(stream.vch)

    mempool.add_orphan_transaction(child_data)
    assert mempool.has_orphan_transaction(child_tx.get_hash())

    # Accept parent transaction
    cryptogenesis.accept_transaction(parent_tx, check_inputs=False)

    # Check that orphan is indexed by parent
    orphan_hashes = mempool.get_orphan_transactions_by_prev(parent_hash)
    assert child_tx.get_hash() in orphan_hashes


def test_erase_orphan():
    """Test erasing orphan transactions"""
    mempool = cryptogenesis.get_mempool()
    mempool.clear()

    fake_hash = cryptogenesis.uint256(12345)
    outpoint = cryptogenesis.OutPoint(fake_hash, 0)
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn(outpoint, cryptogenesis.Script())]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    stream = cryptogenesis.DataStream()
    tx.serialize(stream)
    tx_data = bytes(stream.vch)

    mempool.add_orphan_transaction(tx_data)
    assert mempool.has_orphan_transaction(tx.get_hash())

    mempool.erase_orphan_transaction(tx.get_hash())
    assert not mempool.has_orphan_transaction(tx.get_hash())
    assert mempool.get_orphan_count() == 0
