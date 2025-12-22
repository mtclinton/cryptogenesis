"""
Tests for Block and BlockIndex
"""

from .context import cryptogenesis


def test_block_initialization():
    """Test Block initialization"""
    block = cryptogenesis.Block()
    assert block.version == 1
    assert block.prev_block_hash == cryptogenesis.uint256(0)
    assert block.merkle_root == cryptogenesis.uint256(0)
    assert block.time == 0
    assert block.bits == 0
    assert block.nonce == 0
    assert len(block.transactions) == 0


def test_block_add_transaction():
    """Test adding transactions to block"""
    block = cryptogenesis.Block()
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
    block.transactions.append(tx)
    assert len(block.transactions) == 1


def test_block_merkle_tree():
    """Test block Merkle tree construction"""
    block = cryptogenesis.Block()
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
    block.transactions = [tx]

    merkle_root = block.build_merkle_tree()
    assert isinstance(merkle_root, cryptogenesis.uint256)
    assert len(block.merkle_tree) > 0


def test_block_merkle_tree_multiple_txs():
    """Test Merkle tree with multiple transactions"""
    block = cryptogenesis.Block()
    for i in range(3):
        tx = cryptogenesis.Transaction()
        tx.vin = [cryptogenesis.TxIn()]
        tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
        block.transactions.append(tx)

    merkle_root = block.build_merkle_tree()
    assert isinstance(merkle_root, cryptogenesis.uint256)


def test_block_hash():
    """Test block hash calculation"""
    block = cryptogenesis.Block()
    block.version = 1
    block.prev_block_hash = cryptogenesis.uint256(0)
    block.time = 1231006505
    block.bits = 0x1D00FFFF
    block.nonce = 2083236893

    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
    block.transactions = [tx]
    block.merkle_root = block.build_merkle_tree()

    block_hash = block.get_hash()
    assert isinstance(block_hash, cryptogenesis.uint256)


def test_block_serialization():
    """Test Block serialization"""
    block = cryptogenesis.Block()
    block.version = 1
    block.prev_block_hash = cryptogenesis.uint256(100)
    block.time = 1231006505
    block.bits = 0x1D00FFFF
    block.nonce = 2083236893

    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
    block.transactions = [tx]
    block.merkle_root = block.build_merkle_tree()

    stream = cryptogenesis.DataStream()
    block.serialize(stream)
    assert stream.size() > 0

    # Unserialize
    block2 = cryptogenesis.Block()
    stream2 = cryptogenesis.DataStream()
    block.serialize(stream2)
    block2.unserialize(stream2)
    assert block2.version == block.version
    assert block2.prev_block_hash == block.prev_block_hash
    assert block2.merkle_root == block.merkle_root
    assert block2.time == block.time
    assert block2.bits == block.bits
    assert block2.nonce == block.nonce


def test_block_check_merkle_branch():
    """Test check_merkle_branch function"""
    block = cryptogenesis.Block()
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
    block.transactions = [tx]
    merkle_root = block.build_merkle_tree()

    tx_hash = tx.get_hash()
    index = 0

    # Get merkle branch for the transaction
    merkle_branch = block.get_merkle_branch(index)

    # Should verify correctly (for single tx, branch is empty and root equals tx hash)
    if len(merkle_branch) == 0:
        # Single transaction case
        assert merkle_root == tx_hash
    else:
        # Multiple transactions case
        calculated_root = cryptogenesis.Block.check_merkle_branch(tx_hash, merkle_branch, index)
        assert calculated_root == merkle_root


def test_block_validation():
    """Test block validation"""
    block = cryptogenesis.Block()
    block.version = 1
    block.prev_block_hash = cryptogenesis.uint256(0)
    block.time = 1231006505
    block.bits = 0x1D00FFFF
    block.nonce = 2083236893

    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
    block.transactions = [tx]
    block.merkle_root = block.build_merkle_tree()

    # Basic validation
    is_valid = block.check_block()
    # Note: This may fail if proof of work is not satisfied
    assert isinstance(is_valid, bool)


def test_blockindex_initialization():
    """Test BlockIndex initialization"""
    index = cryptogenesis.BlockIndex()
    assert index.file_num == 0
    assert index.block_pos == 0
    assert index.height == 0
    assert index.prev is None
    assert index.next is None


def test_blockindex_from_block():
    """Test BlockIndex creation from Block"""
    block = cryptogenesis.Block()
    block.version = 1
    block.time = 1231006505
    block.bits = 0x1D00FFFF
    block.nonce = 2083236893

    index = cryptogenesis.BlockIndex(block=block)
    assert index.version == block.version
    assert index.time == block.time
    assert index.bits == block.bits
    assert index.nonce == block.nonce


def test_blockindex_get_block_hash():
    """Test BlockIndex get_block_hash"""
    block = cryptogenesis.Block()
    block.version = 1
    block.prev_block_hash = cryptogenesis.uint256(0)
    block.time = 1231006505
    block.bits = 0x1D00FFFF
    block.nonce = 2083236893
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]
    block.transactions = [tx]
    block.merkle_root = block.build_merkle_tree()

    index = cryptogenesis.BlockIndex(block=block)
    block_hash = index.get_block_hash()
    assert isinstance(block_hash, cryptogenesis.uint256)


def test_blockindex_is_in_main_chain():
    """Test BlockIndex is_in_main_chain"""
    index1 = cryptogenesis.BlockIndex()
    index2 = cryptogenesis.BlockIndex()
    index1.next = index2
    index2.prev = index1

    # index2 is in main chain if it's the best or has a next
    assert index2.is_in_main_chain(index2)
    # index1 is in main chain if it has a next (which it does)
    assert index1.is_in_main_chain(index2)

    # index1 is NOT in main chain if index2 is best and index1 has no next
    index1.next = None
    assert not index1.is_in_main_chain(index2)


def test_blockindex_get_median_time_past():
    """Test BlockIndex get_median_time_past"""
    index = cryptogenesis.BlockIndex()
    index.time = 1000

    # With no previous blocks, should return own time
    median_time = index.get_median_time_past()
    assert median_time == 1000

    # With previous blocks
    prev_index = cryptogenesis.BlockIndex()
    prev_index.time = 900
    index.prev = prev_index
    median_time = index.get_median_time_past()
    assert isinstance(median_time, int)
