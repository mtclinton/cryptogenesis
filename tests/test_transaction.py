"""
Tests for Transaction, TxIn, TxOut, and OutPoint
"""

from .context import cryptogenesis


def test_outpoint_initialization():
    """Test OutPoint initialization"""
    op = cryptogenesis.OutPoint()
    assert op.hash == cryptogenesis.uint256(0)
    assert op.n == 0

    hash_val = cryptogenesis.uint256(100)
    op2 = cryptogenesis.OutPoint(hash_val, 1)
    assert op2.hash == hash_val
    assert op2.n == 1


def test_outpoint_set_null():
    """Test OutPoint set_null"""
    op = cryptogenesis.OutPoint()
    op.set_null()
    assert op.is_null()
    assert op.n == -1


def test_outpoint_is_null():
    """Test OutPoint is_null check"""
    op = cryptogenesis.OutPoint()
    assert not op.is_null()

    op.set_null()
    assert op.is_null()


def test_outpoint_serialization():
    """Test OutPoint serialization"""
    op = cryptogenesis.OutPoint()
    op.hash = cryptogenesis.uint256(100)
    op.n = 1

    stream = cryptogenesis.DataStream()
    op.serialize(stream)
    assert stream.size() == 36  # 32 bytes hash + 4 bytes n

    # Unserialize
    op2 = cryptogenesis.OutPoint()
    op2.unserialize(stream)
    assert op2.hash == op.hash
    assert op2.n == op.n


def test_outpoint_null_serialization():
    """Test OutPoint null serialization (n = -1)"""
    op = cryptogenesis.OutPoint()
    op.set_null()

    stream = cryptogenesis.DataStream()
    op.serialize(stream)

    op2 = cryptogenesis.OutPoint()
    op2.unserialize(stream)
    assert op2.is_null()


def test_outpoint_equality():
    """Test OutPoint equality"""
    hash1 = cryptogenesis.uint256(100)
    hash2 = cryptogenesis.uint256(200)

    op1 = cryptogenesis.OutPoint(hash1, 1)
    op2 = cryptogenesis.OutPoint(hash1, 1)
    op3 = cryptogenesis.OutPoint(hash2, 1)

    assert op1 == op2
    assert op1 != op3


def test_txin_initialization():
    """Test TxIn initialization"""
    txin = cryptogenesis.TxIn()
    # prevout is not null by default (it's OutPoint with hash=0, n=0)
    assert isinstance(txin.prevout, cryptogenesis.OutPoint)
    assert isinstance(txin.script_sig, cryptogenesis.Script)
    assert txin.sequence == 0xFFFFFFFF


def test_txin_serialization():
    """Test TxIn serialization"""
    txin = cryptogenesis.TxIn()
    txin.prevout.hash = cryptogenesis.uint256(100)
    txin.prevout.n = 1
    txin.script_sig.push_data(b"test")

    stream = cryptogenesis.DataStream()
    txin.serialize(stream)
    assert stream.size() > 0

    # Unserialize
    txin2 = cryptogenesis.TxIn()
    txin2.unserialize(stream)
    assert txin2.prevout.hash == txin.prevout.hash
    assert txin2.prevout.n == txin.prevout.n


def test_txout_initialization():
    """Test TxOut initialization"""
    txout = cryptogenesis.TxOut()
    assert txout.value == 0
    assert isinstance(txout.script_pubkey, cryptogenesis.Script)

    txout2 = cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())
    assert txout2.value == 10 * cryptogenesis.COIN


def test_txout_serialization():
    """Test TxOut serialization"""
    txout = cryptogenesis.TxOut()
    txout.value = 10 * cryptogenesis.COIN
    txout.script_pubkey.push_data(b"test")

    stream = cryptogenesis.DataStream()
    txout.serialize(stream)
    assert stream.size() > 0

    # Unserialize
    txout2 = cryptogenesis.TxOut()
    txout2.unserialize(stream)
    assert txout2.value == txout.value


def test_transaction_initialization():
    """Test Transaction initialization"""
    tx = cryptogenesis.Transaction()
    assert tx.version == 1
    assert len(tx.vin) == 0
    assert len(tx.vout) == 0
    assert tx.lock_time == 0


def test_transaction_add_input():
    """Test adding inputs to transaction"""
    tx = cryptogenesis.Transaction()
    txin = cryptogenesis.TxIn()
    tx.vin.append(txin)
    assert len(tx.vin) == 1


def test_transaction_add_output():
    """Test adding outputs to transaction"""
    tx = cryptogenesis.Transaction()
    txout = cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())
    tx.vout.append(txout)
    assert len(tx.vout) == 1


def test_transaction_serialization():
    """Test Transaction serialization"""
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    stream = cryptogenesis.DataStream()
    tx.serialize(stream)
    assert stream.size() > 0

    # Unserialize
    tx2 = cryptogenesis.Transaction()
    stream2 = cryptogenesis.DataStream()
    tx.serialize(stream2)
    tx2.unserialize(stream2)
    assert tx2.version == tx.version
    assert len(tx2.vin) == len(tx.vin)
    assert len(tx2.vout) == len(tx.vout)
    assert tx2.lock_time == tx.lock_time


def test_transaction_hash():
    """Test Transaction hash calculation"""
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    tx_hash = tx.get_hash()
    assert isinstance(tx_hash, cryptogenesis.uint256)


def test_transaction_check():
    """Test Transaction validation"""
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    # Basic transaction should pass
    assert tx.check_transaction()

    # Empty transaction should fail
    tx2 = cryptogenesis.Transaction()
    assert not tx2.check_transaction()


def test_transaction_is_coinbase():
    """Test Transaction is_coinbase check"""
    # Regular transaction
    tx = cryptogenesis.Transaction()
    txin = cryptogenesis.TxIn()
    txin.prevout.hash = cryptogenesis.uint256(100)
    tx.vin = [txin]
    assert not tx.is_coinbase()

    # Coinbase transaction
    tx2 = cryptogenesis.Transaction()
    txin2 = cryptogenesis.TxIn()
    txin2.prevout.set_null()
    tx2.vin = [txin2]
    assert tx2.is_coinbase()


def test_transaction_size():
    """Test Transaction size calculation"""
    from cryptogenesis.serialize import get_serialize_size

    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    size = get_serialize_size(tx)
    assert size > 0


def test_transaction_string_representation():
    """Test Transaction string representation"""
    tx = cryptogenesis.Transaction()
    tx.vin = [cryptogenesis.TxIn()]
    tx.vout = [cryptogenesis.TxOut(10 * cryptogenesis.COIN, cryptogenesis.Script())]

    str_repr = str(tx)
    assert isinstance(str_repr, str)
    assert len(str_repr) > 0
