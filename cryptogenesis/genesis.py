"""
Genesis block factory.

Single definition of the mainnet genesis block, shared by the node entry point
and the visualization server (previously each duplicated it / loaded run_node.py
by file path). Its hash MUST stay
000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f.
"""

from cryptogenesis.block import Block
from cryptogenesis.transaction import COIN, OP_CHECKSIG, Script, Transaction, TxIn, TxOut
from cryptogenesis.uint256 import uint256


def create_genesis_block() -> Block:
    """Build the mainnet genesis block from its canonical parameters."""
    # Coinbase timestamp (The Times, 03/Jan/2009).
    timestamp = b"The Times 03/Jan/2009 Chancellor on brink of " b"second bailout for banks"

    tx_new = Transaction()
    tx_new.vin = [TxIn()]
    tx_new.vin[0].prevout.set_null()
    tx_new.vin[0].script_sig = Script()
    tx_new.vin[0].script_sig.push_int(486604799, force_bignum=True)
    tx_new.vin[0].script_sig.push_int(4, force_bignum=True)
    tx_new.vin[0].script_sig.push_data(timestamp)

    tx_new.vout = [TxOut()]
    tx_new.vout[0].value = 50 * COIN
    tx_new.vout[0].script_pubkey = Script()
    genesis_pubkey_hex = (
        "5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE"
        "611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704"
    )
    genesis_pubkey_le = bytes(reversed(bytes.fromhex(genesis_pubkey_hex)))
    tx_new.vout[0].script_pubkey.push_data(genesis_pubkey_le)
    tx_new.vout[0].script_pubkey.push_opcode(OP_CHECKSIG)

    block = Block()
    block.transactions = [tx_new]
    block.prev_block_hash = uint256(0)
    block.merkle_root = block.build_merkle_tree()
    block.version = 1
    block.time = 1231006505
    block.bits = 0x1D00FFFF
    block.nonce = 2083236893

    return block
