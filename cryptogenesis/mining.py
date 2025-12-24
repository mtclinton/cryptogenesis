"""
Copyright (c) 2009 Satoshi Nakamoto
Distributed under the MIT/X11 software license

Bitcoin mining functionality
"""

import hashlib
import struct
import threading
import time
from typing import Dict

from cryptogenesis.block import Block, get_next_work_required
from cryptogenesis.chain import get_chain
from cryptogenesis.crypto import Key, hash_to_uint256
from cryptogenesis.mempool import get_mempool
from cryptogenesis.serialize import SER_NETWORK, get_serialize_size
from cryptogenesis.transaction import Script, Transaction, TxIn, TxOut
from cryptogenesis.uint256 import uint256
from cryptogenesis.util import get_time
from cryptogenesis.utxo import DiskTxPos, TxIndex, get_txdb

# Mining control
f_generate_bitcoins = False
f_generate_bitcoins_lock = threading.Lock()
n_transactions_updated = 0
n_transactions_updated_lock = threading.Lock()
# Mining rate control (for testing)
MIN_BLOCK_INTERVAL = 30  # Minimum seconds between blocks (for testing)


def set_generate_bitcoins(value: bool):
    """Set whether to generate bitcoins"""
    global f_generate_bitcoins
    with f_generate_bitcoins_lock:
        f_generate_bitcoins = value


def get_generate_bitcoins() -> bool:
    """Get whether to generate bitcoins"""
    with f_generate_bitcoins_lock:
        return f_generate_bitcoins


def format_hash_blocks(pbuffer: bytearray, length: int) -> int:
    """
    Format buffer for SHA256 hashing (matches Bitcoin v0.1 FormatHashBlocks)
    Pads buffer to 64-byte blocks with SHA256 padding
    """
    blocks = 1 + ((length + 8) // 64)
    total_size = blocks * 64
    result = bytearray(total_size)
    result[:length] = pbuffer[:length]
    # Add 0x80 marker
    if length < total_size:
        result[length] = 0x80
    # Add length in bits (little-endian)
    bits = length * 8
    result[total_size - 1] = (bits >> 0) & 0xFF
    result[total_size - 2] = (bits >> 8) & 0xFF
    result[total_size - 3] = (bits >> 16) & 0xFF
    result[total_size - 4] = (bits >> 24) & 0xFF
    return blocks


def block_sha256(pin: bytearray, n_blocks: int) -> bytes:
    """
    SHA256 hash optimized for block mining (matches Bitcoin v0.1 BlockSHA256)
    Uses standard SHA256 but optimized for multiple blocks
    """
    result = bytearray()
    for n in range(n_blocks):
        block_data = pin[n * 64 : (n + 1) * 64]
        if len(block_data) < 64:
            block_data += bytearray(64 - len(block_data))
        result.extend(hashlib.sha256(bytes(block_data)).digest())
    return bytes(result)


def create_new_block(key: Key, extra_nonce: int, n_bits: int, prev_hash: uint256) -> Block:
    """
    Create a new block with coinbase transaction (matches Bitcoin v0.1 CreateNewBlock logic)
    """
    # Create coinbase transaction
    tx_new = Transaction()
    tx_new.vin = [TxIn()]
    tx_new.vin[0].prevout.set_null()

    # Coinbase script: nBits + extraNonce
    script_sig = Script()
    script_sig.push_int(n_bits)
    script_sig.push_int(extra_nonce)
    tx_new.vin[0].script_sig = script_sig

    # Output to miner's public key
    tx_new.vout = [TxOut()]
    pubkey = key.get_pubkey()
    script_pubkey = Script()
    script_pubkey.push_data(pubkey)
    script_pubkey.push_opcode(0xAC)  # OP_CHECKSIG
    tx_new.vout[0].script_pubkey = script_pubkey

    # Create block
    block = Block()
    block.version = 1
    block.prev_block_hash = prev_hash
    block.transactions = [tx_new]

    # Collect transactions from mempool
    mempool = get_mempool()
    txdb = get_txdb()
    chain = get_chain()

    n_fees = 0
    map_test_pool: Dict[uint256, TxIndex] = {}
    vf_already_added = set()
    n_block_size = 0
    MAX_SIZE = 0x02000000

    # Get all transactions
    all_txs = mempool.get_all_transactions()

    print(f"create_new_block: Mempool has {len(all_txs)} transactions")
    if len(all_txs) > 0:
        tx_hashes = [tx.get_hash().get_hex()[:16] for tx in all_txs]
        print(f"create_new_block: Transaction hashes: {tx_hashes}")
    f_found_something = True
    transactions_added = 0
    transactions_skipped = 0
    while f_found_something and n_block_size < MAX_SIZE // 2:
        f_found_something = False
        for tx in all_txs:
            tx_hash = tx.get_hash()
            if tx_hash in vf_already_added:
                continue
            if tx.is_coinbase():
                transactions_skipped += 1
                continue
            if not tx.is_final(chain.best_height + 1):
                transactions_skipped += 1
                print(f"create_new_block: Transaction {tx_hash.get_hex()[:16]} not final")
                continue

            # Try to connect inputs with minimum fee check
            # Transaction fee requirements, mainly only needed for flood control
            # Under 10K (about 80 inputs) is free for first 100 transactions
            # Base rate is 0.01 per KB (matches Bitcoin v0.1)
            n_min_fee = tx.get_min_fee(f_discount=len(block.transactions) < 100)
            map_test_pool_tmp = map_test_pool.copy()
            try:
                # Log transaction inputs for debugging
                tx_hash_hex = tx_hash.get_hex()[:16]
                print(
                    f"create_new_block: Validating transaction {tx_hash_hex} "
                    f"with {len(tx.vin)} inputs"
                )
                for i, txin in enumerate(tx.vin):
                    prev_hash = txin.prevout.hash.get_hex()[:16]
                    prev_n = txin.prevout.n
                    print(f"create_new_block:   Input {i}: prevout={prev_hash}:{prev_n}")
                    # Check if prevout exists in txdb or map_test_pool
                    prev_txindex = txdb.read_tx_index(txin.prevout.hash)
                    found_in_txdb = prev_txindex is not None
                    found_in_pool = txin.prevout.hash in map_test_pool_tmp
                    if found_in_txdb:
                        print("create_new_block:     Found in txdb")
                    elif found_in_pool:
                        print("create_new_block:     Found in map_test_pool")
                    else:
                        print("create_new_block:     NOT FOUND in txdb or map_test_pool!")

                success, fees = tx.connect_inputs(  # type: ignore[attr-defined]
                    txdb,
                    map_test_pool_tmp,
                    DiskTxPos(1, 1, 1),
                    height=chain.best_height + 1,
                    fees=0,
                    is_block=False,
                    is_miner=True,
                    min_fee=n_min_fee,
                )
                if success:
                    map_test_pool = map_test_pool_tmp
                    block.transactions.append(tx)
                    n_block_size += get_serialize_size(tx, SER_NETWORK)
                    vf_already_added.add(tx_hash)
                    n_fees += fees
                    f_found_something = True
                    transactions_added += 1
                    print(
                        f"create_new_block: Added transaction {tx_hash.get_hex()[:16]}, fees={fees}"
                    )
                else:
                    transactions_skipped += 1
                    tx_hash_hex = tx_hash.get_hex()[:16]
                    print(
                        f"create_new_block: Transaction {tx_hash_hex} "
                        f"connect_inputs failed (success=False)"
                    )
                    # Try to get more details about why it failed
                    print(
                        f"create_new_block: Transaction has {len(tx.vin)} inputs, "
                        f"{len(tx.vout)} outputs"
                    )
                    # Check each input to see if it's already spent
                    for i, txin in enumerate(tx.vin):
                        prev_hash = txin.prevout.hash.get_hex()[:16]
                        prev_n = txin.prevout.n
                        prev_txindex = txdb.read_tx_index(txin.prevout.hash)
                        if prev_txindex:
                            if prev_txindex.spent and prev_n < len(prev_txindex.spent):
                                spent_pos = prev_txindex.spent[prev_n]
                                if not spent_pos.is_null():
                                    print(
                                        f"create_new_block:   Input {i} prevout "
                                        f"{prev_hash}:{prev_n} is already spent at {spent_pos}"
                                    )
                                else:
                                    print(
                                        f"create_new_block:   Input {i} prevout "
                                        f"{prev_hash}:{prev_n} is NOT spent (can be used)"
                                    )
                            else:
                                spent_len = len(prev_txindex.spent) if prev_txindex.spent else 0
                                print(
                                    f"create_new_block:   Input {i} prevout "
                                    f"{prev_hash}:{prev_n} spent array issue: "
                                    f"spent={prev_txindex.spent}, len={spent_len}, "
                                    f"prev_n={prev_n}"
                                )
                        else:
                            print(
                                f"create_new_block:   Input {i} prevout "
                                f"{prev_hash}:{prev_n} not found in txdb"
                            )
            except Exception as e:
                transactions_skipped += 1
                print(f"create_new_block: Transaction {tx_hash.get_hex()[:16]} exception: {e}")
                import traceback

                traceback.print_exc()
                continue

    print(
        f"create_new_block: Added {transactions_added} transactions, skipped {transactions_skipped}"
    )

    # Set block values
    block.bits = n_bits
    # Get reasonable time value
    current_time = get_time()  # Use actual time, not adjusted (adjusted can be way off)
    median_time = chain.best_index.get_median_time_past() + 1 if chain.best_index else current_time
    time_value = max(median_time, current_time)
    # Clamp to uint32 range, but also ensure it's not too far in the future
    # Max reasonable future time: current + 2 hours (7200 seconds)
    max_future_time = current_time + 7200
    block.time = max(current_time, min(time_value, max_future_time, 0xFFFFFFFF))
    block.nonce = 1

    # Set coinbase value
    block_value = block.get_block_value(n_fees, chain.best_height + 1)
    block.transactions[0].vout[0].value = block_value

    # Build merkle tree
    block.merkle_root = block.build_merkle_tree()

    return block


def bitcoin_miner() -> bool:
    """
    Main mining function (matches Bitcoin v0.1 BitcoinMiner)
    """
    import os

    print("BitcoinMiner started")
    from cryptogenesis.wallet import add_key

    key = Key()
    key.generate_new_key()
    bn_extra_nonce = 0

    # Check if we should enforce minimum block interval (for testing)
    test_mode = os.environ.get("TEST_MODE", "").lower() in ("1", "true", "yes")
    min_interval = MIN_BLOCK_INTERVAL if test_mode else 0

    while get_generate_bitcoins():
        time.sleep(0.05)  # Sleep 50ms

        # Wait for network connections (simplified - just check if we have a chain)
        chain = get_chain()
        if chain.best_height < 0:
            time.sleep(1.0)
            continue

        n_transactions_updated_last = n_transactions_updated
        pindex_prev = chain.best_index
        if not pindex_prev:
            continue

        # Enforce minimum time between blocks (for testing)
        # Check the chain's best block time (works for both our blocks and network blocks)
        if min_interval > 0:
            best_block = chain.get_block(pindex_prev.block_hash)
            if best_block and hasattr(best_block, "time"):
                best_block_time = best_block.time
                time_since_last = time.time() - best_block_time
                if time_since_last < min_interval:
                    sleep_time = min_interval - time_since_last
                    if sleep_time > 0:
                        time.sleep(sleep_time)

        n_bits = get_next_work_required(pindex_prev)

        # Create coinbase and block
        bn_extra_nonce += 1
        block = create_new_block(key, bn_extra_nonce, n_bits, pindex_prev.block_hash)

        mempool_tx_count = len(block.transactions) - 1  # Exclude coinbase
        print(
            f"\n\nRunning BitcoinMiner with {len(block.transactions)} transactions "
            f"({mempool_tx_count} from mempool) in block\n"
        )
        if mempool_tx_count == 0:
            mempool = get_mempool()
            all_txs = mempool.get_all_transactions()
            print(f"  Mempool has {len(all_txs)} transactions, but none were included")
            if len(all_txs) > 0:
                print("  This suggests transactions failed validation during block creation")

        # IMPORTANT: Ensure merkle root is built before mining
        # The merkle root must match the transactions in the block
        block.merkle_root = block.build_merkle_tree()

        # Prebuild hash buffer (matches Bitcoin v0.1 structure)
        # Structure: block header (80 bytes) + padding + hash1 + padding
        # IMPORTANT: Use same format as block.get_hash() - signed int for version
        block_header = bytearray(80)
        struct.pack_into("<i", block_header, 0, block.version)  # Use signed int to match get_hash()
        block_header[4:36] = block.prev_block_hash.to_bytes()
        block_header[36:68] = block.merkle_root.to_bytes()
        struct.pack_into("<I", block_header, 68, block.time)
        struct.pack_into("<I", block_header, 72, block.bits)
        struct.pack_into("<I", block_header, 76, block.nonce)

        # Search for proof-of-work
        n_start = get_time()
        hash_target = block.get_target()
        hash_result = uint256(0)

        # Debug: log mining start
        print(f"Mining: target={hash_target.pn[0]:08x}..., nonce starting at {block.nonce}")

        # IMPORTANT: Use the same hashing method as block.get_hash()
        # block.get_hash() uses double_sha256() which does:
        #   hash1 = sha256(header)
        #   hash2 = sha256(hash1)
        # We need to use the same method for consistency
        from cryptogenesis.crypto import double_sha256

        while True:
            # Rebuild header with current nonce (nonce is updated in the loop)
            current_header = bytearray(80)
            struct.pack_into("<i", current_header, 0, block.version)
            current_header[4:36] = block.prev_block_hash.to_bytes()
            current_header[36:68] = block.merkle_root.to_bytes()
            struct.pack_into("<I", current_header, 68, block.time)
            struct.pack_into("<I", current_header, 72, block.bits)
            struct.pack_into("<I", current_header, 76, block.nonce)

            # Use double_sha256 directly on the header (matching block.get_hash())
            header_bytes = bytes(current_header)
            hash_result = hash_to_uint256(double_sha256(header_bytes))

            if hash_result <= hash_target:
                # Block fields are already set correctly (we rebuild header each iteration)
                # Verify hash using block's get_hash() method
                block_hash = block.get_hash()

                if hash_result != block_hash:
                    # Hash mismatch - this means block structure doesn't match mining structure
                    # This can happen if:
                    # 1. Transactions were modified after block creation
                    # 2. Merkle root calculation differs from mining calculation
                    # 3. Block header format differs
                    print(
                        f"ERROR: Hash mismatch: "
                        f"mining={hash_result.get_hex()[:16]}, "
                        f"block.get_hash()={block_hash.get_hex()[:16]}"
                    )
                    print(f"  Block time: {block.time}, nonce: {block.nonce}")
                    print(f"  Merkle root: {block.merkle_root.get_hex()[:16]}")
                    print(f"  Transactions: {len(block.transactions)}")

                    # Rebuild block header to match what we mined
                    # The mined hash is correct, so we need to ensure block matches
                    # Recalculate everything from scratch
                    block.merkle_root = block.build_merkle_tree()
                    block_hash = block.get_hash()

                    if hash_result != block_hash:
                        print(
                            f"ERROR: Hash still mismatched after rebuild: "
                            f"mining={hash_result.get_hex()[:16]}, "
                            f"block.get_hash()={block_hash.get_hex()[:16]}"
                        )
                        print("  Skipping this block - hash mismatch indicates structural issue")
                        # Skip this block and create a new one
                        time.sleep(0.5)
                        break
                    else:
                        print("✓ Hash matches after rebuild")

                print("BitcoinMiner: proof-of-work found")
                try:
                    hash_hex = hash_result.get_hex()
                    print(f"  hash: {hash_hex}")
                except Exception as e:
                    print(f"  hash: (error getting hex: {e})")
                    import traceback

                    traceback.print_exc()
                # Target might be too large for get_hex(), so format manually
                try:
                    target_hex = hash_target.get_hex()
                    print(f"target: {target_hex}")
                except (struct.error, OverflowError):
                    # Target is too large, format from pn array directly
                    # Show first few uint32 values as hex
                    target_hex = (
                        f"{hash_target.pn[0]:08x}{hash_target.pn[1]:08x}... (target too large)"
                    )
                    print(f"target: {target_hex}")
                print(f"Block: {block}")
                print("BitcoinMiner: About to save key and process block...")

                # Save key and process block
                if not add_key(key):
                    return False
                key.generate_new_key()

                # Process this block
                block_hash_str = block.get_hash().get_hex()[:16]
                print(f"Processing block with hash: {block_hash_str}...")
                print(
                    f"  Block details: version={block.version}, "
                    f"time={block.time}, nonce={block.nonce}"
                )
                print(f"  Block prev_hash: {block.prev_block_hash.get_hex()[:16]}")
                print(f"  Block merkle_root: {block.merkle_root.get_hex()[:16]}")

                process_result = chain.process_block(block)
                if not process_result:
                    print(
                        f"ERROR in BitcoinMiner: ProcessBlock returned False "
                        f"for block {block_hash_str}"
                    )
                    print("  This means the block was not accepted into the chain")
                    # Get more details about why it failed
                    import sys
                    import traceback

                    print("Full traceback:", file=sys.stderr)
                    traceback.print_exc(file=sys.stderr)
                    print("Full traceback:", file=sys.stdout)
                    traceback.print_exc(file=sys.stdout)
                else:
                    print(f"✓ Block accepted! Height: {chain.best_height}")

                # Break out of inner mining loop to create a new block
                # The outer loop will continue and create a new block
                break

            # Increment nonce
            block.nonce += 1

            # Debug: log progress every 1M nonces
            if block.nonce % 1000000 == 0:
                print(f"Mining: tried {block.nonce:,} nonces, still searching...")

            # Update time every 0x3ffff iterations
            if (block.nonce & 0x3FFFF) == 0:
                if block.nonce == 0:
                    break
                if pindex_prev != chain.best_index:
                    break
                if (
                    n_transactions_updated != n_transactions_updated_last
                    and get_time() - n_start > 60
                ):
                    break
                if not get_generate_bitcoins():
                    break
                # Update time during mining (use actual time, not adjusted)
                current_time = get_time()
                median_time = pindex_prev.get_median_time_past() + 1
                new_time = max(median_time, current_time)
                # Clamp to reasonable range
                max_future_time = current_time + 7200  # Max 2 hours in future
                block.time = max(current_time, min(new_time, max_future_time, 0xFFFFFFFF))

    return True


def start_mining():
    """Start mining in a background thread"""
    set_generate_bitcoins(True)
    thread = threading.Thread(target=bitcoin_miner, daemon=True)
    thread.start()
    return thread


def stop_mining():
    """Stop mining"""
    set_generate_bitcoins(False)
