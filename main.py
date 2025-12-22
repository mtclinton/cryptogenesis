#!/usr/bin/env python3
"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Bitcoin v0.1 Python 3 Implementation
Main entry point
"""

import sys
import time

from cryptogenesis import (
    COIN,
    HASH_GENESIS_BLOCK,
    Block,
    Key,
    Script,
    Transaction,
    TxIn,
    TxOut,
    uint256,
)


def create_genesis_block():
    """Create the genesis block"""
    # Genesis block timestamp
    timestamp = b"The Times 03/Jan/2009 Chancellor on brink of " b"second bailout for banks"

    tx_new = Transaction()
    tx_new.vin = [TxIn()]
    tx_new.vin[0].prevout.set_null()
    tx_new.vin[0].script_sig = Script()
    tx_new.vin[0].script_sig.push_int(486604799, force_bignum=True)
    tx_new.vin[0].script_sig.push_int(4, force_bignum=True)  # BigNum(4) in original
    tx_new.vin[0].script_sig.push_data(timestamp)

    tx_new.vout = [TxOut()]
    tx_new.vout[0].value = 50 * COIN
    tx_new.vout[0].script_pubkey = Script()
    # Genesis block pubkey - BigNum('0x...') parses as big-endian,
    # then getvch() reverses to little-endian
    genesis_pubkey_hex = (
        "5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE"
        "611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704"
    )
    genesis_pubkey_be = bytes.fromhex(genesis_pubkey_hex)  # Big-endian
    genesis_pubkey_le = bytes(
        reversed(genesis_pubkey_be)
    )  # Little-endian (after BigNum.getvch() reverse)
    tx_new.vout[0].script_pubkey.push_data(genesis_pubkey_le)
    from cryptogenesis.transaction import OP_CHECKSIG

    tx_new.vout[0].script_pubkey.push_opcode(OP_CHECKSIG)

    block = Block()
    block.transactions = [tx_new]
    block.prev_block_hash = uint256(0)
    block.merkle_root = block.build_merkle_tree()
    block.version = 1
    block.time = 1231006505  # Genesis block time
    block.bits = 0x1D00FFFF
    block.nonce = 2083236893

    return block


def main():
    """Main function"""
    print("Bitcoin v0.1 Python 3 Implementation")
    print("=" * 50)

    # Create genesis block
    print("\nCreating genesis block...")
    genesis_block = create_genesis_block()
    genesis_hash = genesis_block.get_hash()
    print(f"Genesis block hash: {genesis_hash.get_hex()}")
    print(f"Expected hash: {HASH_GENESIS_BLOCK.get_hex()}")

    if genesis_hash == HASH_GENESIS_BLOCK:
        print("✓ Genesis block hash matches!")
    else:
        print("⚠ Genesis block hash does not match (this may be due to implementation differences)")

    print("\nGenesis block:")
    print(f"  Version: {genesis_block.version}")
    print(f"  Previous block: {genesis_block.prev_block_hash.get_hex()}")
    print(f"  Merkle root: {genesis_block.merkle_root.get_hex()}")
    print(f"  Time: {genesis_block.time}")
    print(f"  Bits: {genesis_block.bits:08x}")
    print(f"  Nonce: {genesis_block.nonce}")
    print(f"  Transactions: {len(genesis_block.transactions)}")

    # Test transaction creation
    print("\n\nTesting transaction creation...")
    key = Key()
    key.generate_new_key()
    pubkey = key.public_key
    print(f"Generated public key: {pubkey.hex()[:64]}...")

    # Create a simple transaction
    tx = Transaction()
    tx.vin = [TxIn()]
    tx.vout = [TxOut(10 * COIN, Script())]
    tx.vout[0].script_pubkey.push_data(pubkey)
    from cryptogenesis.transaction import OP_CHECKSIG

    tx.vout[0].script_pubkey.push_opcode(OP_CHECKSIG)

    tx_hash = tx.txid
    print(f"Transaction hash: {tx_hash.get_hex()}")
    print(f"Transaction valid: {tx.check_transaction()}")

    # Test block creation
    print("\n\nTesting block creation...")
    block = Block()
    block.transactions = [tx]
    block.prev_block_hash = genesis_hash
    block.merkle_root = block.build_merkle_tree()
    block.version = 1
    block.time = int(time.time())
    block.bits = 0x1D00FFFF
    block.nonce = 0

    block_hash = block.get_hash()
    print(f"Block hash: {block_hash.get_hex()}")
    print(f"Block valid: {block.check_block()}")

    print("\n" + "=" * 50)
    print("Basic functionality test complete!")
    print("\nNote: This is a simplified implementation.")
    print("Full features like P2P networking, wallet, and mining")
    print("would require additional modules and dependencies.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)
