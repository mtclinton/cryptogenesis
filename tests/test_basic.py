"""
Basic tests for Cryptogenesis
"""

from .context import cryptogenesis


def test_genesis_block():
    """Test genesis block creation"""
    block = cryptogenesis.Block()
    block.version = 1
    block.prev_block_hash = cryptogenesis.uint256(0)
    block.time = 1231006505
    block.bits = 0x1D00FFFF
    block.nonce = 2083236893

    # Create genesis transaction
    from cryptogenesis import Script, Transaction, TxIn, TxOut

    tx = Transaction()
    tx.vin = [TxIn()]
    tx.vin[0].prevout.set_null()
    tx.vin[0].script_sig = Script()
    timestamp = b"The Times 03/Jan/2009 Chancellor on brink of " b"second bailout for banks"
    tx.vin[0].script_sig.push_int(486604799, force_bignum=True)
    tx.vin[0].script_sig.push_int(4, force_bignum=True)
    tx.vin[0].script_sig.push_data(timestamp)

    tx.vout = [TxOut()]
    tx.vout[0].value = 50 * cryptogenesis.COIN
    tx.vout[0].script_pubkey = Script()
    genesis_pubkey_hex = (
        "5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE"
        "611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704"
    )
    genesis_pubkey_be = bytes.fromhex(genesis_pubkey_hex)
    genesis_pubkey_le = bytes(reversed(genesis_pubkey_be))
    tx.vout[0].script_pubkey.push_data(genesis_pubkey_le)
    from cryptogenesis.transaction import OP_CHECKSIG

    tx.vout[0].script_pubkey.push_opcode(OP_CHECKSIG)

    block.transactions = [tx]
    block.merkle_root = block.build_merkle_tree()

    block_hash = block.get_hash()
    expected_hash = cryptogenesis.HASH_GENESIS_BLOCK

    assert (
        block_hash == expected_hash
    ), f"Expected {expected_hash.get_hex()}, got {block_hash.get_hex()}"


def test_transaction_creation():
    """Test transaction creation"""
    from cryptogenesis import Script, Transaction, TxIn, TxOut

    key = cryptogenesis.Key()
    key.generate_new_key()
    pubkey = key.public_key

    tx = Transaction()
    tx.vin = [TxIn()]
    tx.vout = [TxOut(10 * cryptogenesis.COIN, Script())]
    tx.vout[0].script_pubkey.push_data(pubkey)
    from cryptogenesis.transaction import OP_CHECKSIG

    tx.vout[0].script_pubkey.push_opcode(OP_CHECKSIG)

    assert tx.check_transaction()
    assert len(tx.vin) == 1
    assert len(tx.vout) == 1


def test_uint256():
    """Test uint256 operations"""
    a = cryptogenesis.uint256(100)
    b = cryptogenesis.uint256(200)
    assert a < b
    assert a != b
    assert a == cryptogenesis.uint256(100)
