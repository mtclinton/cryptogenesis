#!/usr/bin/env python3
"""
Bitcoin Node Runner
Starts a Bitcoin node with networking, mining, and transaction creation

NOTE: This implementation uses in-memory storage. All data is lost when
the container stops. Each node starts fresh with the genesis block.
"""

import argparse
import os
import signal
import socket
import sys
import time
from typing import List

# Force unbuffered output for Docker logs (must be before other imports)
os.environ["PYTHONUNBUFFERED"] = "1"  # noqa: E402

from cryptogenesis.chain import get_chain  # noqa: E402
from cryptogenesis.mining import start_mining, stop_mining  # noqa: E402
from cryptogenesis.network import Address, connect_node, start_node, stop_node  # noqa: E402
from cryptogenesis.transaction import COIN, Script, Transaction, TxIn, TxOut  # noqa: E402
from cryptogenesis.wallet import add_key  # noqa: E402


def create_genesis_block():
    """Create the genesis block (matches main.py)"""
    from cryptogenesis.block import Block
    from cryptogenesis.transaction import OP_CHECKSIG
    from cryptogenesis.uint256 import uint256

    # Genesis block timestamp
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
    # Genesis block pubkey
    genesis_pubkey_hex = (
        "5F1DF16B2B704C8A578D0BBAF74D385CDE12C11EE50455F3C438EF4C3FBCF649B6DE"
        "611FEAE06279A60939E028A8D65C10B73071A6F16719274855FEB0FD8A6704"
    )
    genesis_pubkey_be = bytes.fromhex(genesis_pubkey_hex)
    genesis_pubkey_le = bytes(reversed(genesis_pubkey_be))
    tx_new.vout[0].script_pubkey.push_data(genesis_pubkey_le)
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


def parse_peers(peers_str: str) -> List[tuple]:
    """Parse peer list from string like 'node1:8333,node2:8333'"""
    if not peers_str:
        return []
    peers = []
    for peer in peers_str.split(","):
        if ":" in peer:
            host, port = peer.split(":")
            peers.append((host, int(port)))
    return peers


def create_test_transaction(node_id: int) -> Transaction:
    """Create a test transaction"""
    # Generate a key for this node
    # generate_new_key() returns bytes (public key), not Key object
    from cryptogenesis.crypto import Key

    key = Key()
    key.generate_new_key()
    add_key(key)

    # Create a simple transaction
    tx = Transaction()
    tx.vin = [TxIn()]
    tx.vout = [TxOut(10 * COIN, Script())]
    tx.vout[0].script_pubkey.push_data(key.get_pubkey())
    from cryptogenesis.transaction import OP_CHECKSIG

    tx.vout[0].script_pubkey.push_opcode(OP_CHECKSIG)

    return tx


def main():
    parser = argparse.ArgumentParser(description="Run a Bitcoin node")
    parser.add_argument("--node-id", type=int, required=True, help="Node ID (1-10)")
    parser.add_argument("--port", type=int, default=8333, help="Port to listen on")
    parser.add_argument(
        "--peers",
        type=str,
        default="",
        help="Comma-separated list of peers (host:port)",
    )
    args = parser.parse_args()

    node_id = args.node_id
    port = args.port

    print(f"=== Bitcoin Node {node_id} Starting ===")
    print(f"Port: {port}")
    print(f"Peers: {args.peers}")
    print("NOTE: Using in-memory storage - all data lost on container restart")

    # Initialize chain with genesis block
    chain = get_chain()
    if chain.best_height < 0:
        print("\nInitializing blockchain with genesis block...")
        genesis_block = create_genesis_block()
        # Use accept_block for genesis block to properly initialize chain
        if not chain.accept_block(genesis_block):
            print("ERROR: Failed to accept genesis block")
            sys.exit(1)
        print(
            f"Genesis block processed. Height: {chain.best_height}, "
            f"Hash: {genesis_block.get_hash().get_hex()[:16]}"
        )

    # Start network node
    print("\nStarting network node...")
    success, error = start_node()
    if not success:
        print(f"ERROR: Failed to start node: {error}")
        sys.exit(1)
    print("Network node started successfully")

    # Connect to peers
    peers = parse_peers(args.peers)
    if peers:
        print(f"\nConnecting to {len(peers)} peers...")
        time.sleep(2)  # Wait for network to be ready

        for host, peer_port in peers:
            try:
                # Convert hostname to IP (Docker service names resolve to IPs)
                ip = socket.gethostbyname(host)
                ip_int = int.from_bytes(socket.inet_aton(ip), byteorder="big")
                port_net = socket.htons(peer_port)
                addr = Address(ip_int, port_net, 1)

                print(f"Connecting to {host}:{peer_port} ({ip})...")
                node = connect_node(addr, timeout=5)
                if node:
                    print(f"  ✓ Connected to {host}:{peer_port}")
                else:
                    print(f"  ✗ Failed to connect to {host}:{peer_port}")
            except Exception as e:
                print(f"  ✗ Error connecting to {host}:{peer_port}: {e}")

    # Start mining
    print("\nStarting mining...")
    start_mining()
    print("Mining started")

    # Create periodic transactions - send coins randomly to other nodes
    def create_transactions():
        """Create transactions to randomly send coins to other nodes"""
        import random

        from cryptogenesis.crypto import Key
        from cryptogenesis.mempool import accept_transaction
        from cryptogenesis.transaction import OP_CHECKSIG
        from cryptogenesis.uint256 import uint256
        from cryptogenesis.wallet import get_balance, get_wallet

        while True:
            try:
                time.sleep(60)  # Check every 60 seconds

                # Get wallet balance
                balance = get_balance()
                if balance <= 0:
                    print(f"[Node {node_id}] No balance, skipping transaction creation")
                    continue

                print(f"\n[Node {node_id}] Balance: {balance / COIN:.2f} BTC")

                # Get wallet to find available UTXOs
                wallet = get_wallet()
                if not wallet or len(wallet) == 0:
                    print(f"[Node {node_id}] No wallet transactions, skipping")
                    continue

                # Find spendable outputs
                # Get outputs that are confirmed in blocks and belong to us
                from cryptogenesis.chain import get_chain

                chain = get_chain()
                spendable_outputs = []

                for wtx_hash, wtx in wallet.items():
                    try:
                        # WalletTx IS a Transaction (inherits from it), so use wtx directly
                        # Check if transaction is confirmed (has block hash)
                        if hasattr(wtx, "hash_block") and wtx.hash_block != uint256(0):
                            # For coinbase transactions, check maturity
                            if wtx.is_coinbase():
                                # Coinbase must be at least 1 block deep in TEST_MODE
                                # IMPORTANT: Check maturity relative to NEXT block (best_height + 1)
                                # because transactions will be included in the next block
                                from cryptogenesis.chain import get_chain

                                chain = get_chain()
                                best_height = chain.get_best_height()
                                next_block_height = best_height + 1

                                # Get the block containing this coinbase
                                if wtx.hash_block != uint256(0):
                                    block_index = chain.get_block_index(wtx.hash_block)
                                    if block_index:
                                        # Depth relative to NEXT block being built
                                        depth = next_block_height - block_index.height
                                        required_maturity = 1  # TEST_MODE requires 1 block
                                        if depth < required_maturity:
                                            print(
                                                f"[Node {node_id}] Coinbase "
                                                f"{wtx_hash.get_hex()[:16]} "
                                                f"not mature for next block: "
                                                f"depth={depth} "
                                                f"(coinbase_height={block_index.height}, "
                                                f"next_block_height={next_block_height}, "
                                                f"required={required_maturity})"
                                            )
                                            continue
                                        else:
                                            print(
                                                f"[Node {node_id}] Coinbase "
                                                f"{wtx_hash.get_hex()[:16]} "
                                                f"is mature for next block: depth={depth}"
                                            )
                                    else:
                                        # Can't find block, skip it
                                        continue
                                else:
                                    # No block hash, skip it
                                    continue
                            # Transaction is confirmed (and mature if coinbase), check outputs
                            if hasattr(wtx, "vout") and wtx.vout:
                                # Check if transaction is spent
                                is_tx_spent = getattr(wtx, "f_spent", False)
                                if not is_tx_spent:
                                    # Check each output to see if it's ours and spendable
                                    for i, txout in enumerate(wtx.vout):
                                        if txout.value > 0:
                                            # Check if this output exists in UTXO set
                                            # (simplified check - in real implementation
                                            # would verify)
                                            spendable_outputs.append((wtx, i, txout))
                    except Exception as e:
                        # Skip this wallet transaction if there's an error
                        print(f"[Node {node_id}] Error processing wallet tx: {e}")
                        import traceback

                        traceback.print_exc()
                        continue

                if not spendable_outputs:
                    wallet_count = len(wallet)
                    print(
                        f"[Node {node_id}] No spendable outputs "
                        f"(wallet has {wallet_count} transactions), skipping"
                    )
                    continue

                print(f"[Node {node_id}] Found {len(spendable_outputs)} spendable outputs")

                # Randomly decide how many transactions to create (1-5)
                num_transactions = random.randint(1, min(5, len(spendable_outputs)))

                # Randomly select which other nodes to send to (exclude self)
                other_nodes = [i for i in range(1, 11) if i != node_id]
                if not other_nodes:
                    print(f"[Node {node_id}] No other nodes to send to")
                    continue

                # Create multiple transactions
                for tx_num in range(num_transactions):
                    if not spendable_outputs:
                        break

                    # Pick random output to spend
                    tx_source, vout_idx, txout = random.choice(spendable_outputs)
                    spendable_outputs.remove((tx_source, vout_idx, txout))

                    # Pick random destination node
                    dest_node_id = random.choice(other_nodes)

                    # Generate a key for the destination (simulate another node's key)
                    # In a real scenario, we'd get the public key from the network
                    dest_key = Key()
                    dest_key.generate_new_key()

                    # Calculate amount to send (random portion of available,
                    # but leave some for fees)
                    available = txout.value

                    # We'll create the transaction first, then calculate the fee
                    # and adjust outputs to ensure we meet minimum fee requirement
                    # Start with a reasonable fee estimate
                    estimated_fee = 10000
                    max_send = available - estimated_fee

                    if max_send <= 0:
                        continue

                    # Send random amount (10% to 90% of available)
                    send_amount = random.randint(int(max_send * 0.1), int(max_send * 0.9))
                    change_amount = available - send_amount - estimated_fee

                    # Create transaction first to calculate actual size and fee
                    tx = Transaction()
                    txin = TxIn()
                    txin.prevout.hash = tx_source.get_hash()
                    txin.prevout.n = vout_idx
                    tx.vin = [txin]

                    # Outputs: send to destination and change back to us
                    tx.vout = []

                    # Output to destination
                    txout_dest = TxOut()
                    txout_dest.value = send_amount
                    txout_dest.script_pubkey = Script()
                    txout_dest.script_pubkey.push_data(dest_key.get_pubkey())
                    txout_dest.script_pubkey.push_opcode(OP_CHECKSIG)
                    tx.vout.append(txout_dest)

                    # Change output (if any)
                    if change_amount > 0:
                        # Get our key for change
                        our_key = Key()
                        our_key.generate_new_key()
                        add_key(our_key)  # Add to wallet

                        txout_change = TxOut()
                        txout_change.value = change_amount
                        txout_change.script_pubkey = Script()
                        txout_change.script_pubkey.push_data(our_key.get_pubkey())
                        txout_change.script_pubkey.push_opcode(OP_CHECKSIG)
                        tx.vout.append(txout_change)

                    # Now calculate the actual minimum fee for this transaction
                    # IMPORTANT: Calculate fee with and without discount to ensure we meet both
                    # The miner will apply discount when including in block, but we need
                    # to ensure the transaction has enough fee for both cases
                    from cryptogenesis.serialize import SER_NETWORK, get_serialize_size

                    tx_size = get_serialize_size(tx, SER_NETWORK)
                    min_fee_no_discount = tx.get_min_fee(f_discount=False)
                    min_fee_with_discount = tx.get_min_fee(f_discount=True)

                    # Use the higher of the two to ensure we pass validation
                    # (miner might not apply discount if block already has many transactions)
                    min_fee = max(min_fee_no_discount, min_fee_with_discount)

                    print(
                        f"[Node {node_id}] Transaction size: {tx_size} bytes, "
                        f"min_fee_no_discount={min_fee_no_discount}, "
                        f"min_fee_with_discount={min_fee_with_discount}, "
                        f"using min_fee={min_fee}"
                    )

                    # Calculate actual fee: value_in - value_out
                    # We need to ensure this meets min_fee
                    actual_fee = (
                        available - send_amount - (change_amount if change_amount > 0 else 0)
                    )

                    if actual_fee < min_fee:
                        # Need to increase fee - reduce change amount
                        fee_shortfall = min_fee - actual_fee
                        if change_amount >= fee_shortfall:
                            change_amount -= fee_shortfall
                            # Update change output
                            if change_amount > 0:
                                tx.vout[-1].value = change_amount
                            else:
                                # Remove change output if it's too small
                                tx.vout.pop()
                        else:
                            # Can't meet fee requirement, skip this transaction
                            print(
                                f"[Node {node_id}] Cannot meet minimum fee requirement: "
                                f"min_fee={min_fee}, available={available}, "
                                f"send_amount={send_amount}, change_amount={change_amount}"
                            )
                            continue

                    final_fee = (
                        available - send_amount - (change_amount if change_amount > 0 else 0)
                    )
                    print(
                        f"[Node {node_id}] Transaction fee: {final_fee} satoshis "
                        f"(min_fee={min_fee}, available={available}, "
                        f"send={send_amount}, change={change_amount})"
                    )

                    # Create transaction
                    tx = Transaction()

                    # Input: spend from our UTXO
                    txin = TxIn()
                    txin.prevout.hash = tx_source.get_hash()
                    txin.prevout.n = vout_idx
                    tx.vin = [txin]

                    # Outputs: send to destination and change back to us
                    tx.vout = []

                    # Output to destination
                    txout_dest = TxOut()
                    txout_dest.value = send_amount
                    txout_dest.script_pubkey = Script()
                    txout_dest.script_pubkey.push_data(dest_key.get_pubkey())
                    txout_dest.script_pubkey.push_opcode(OP_CHECKSIG)
                    tx.vout.append(txout_dest)

                    # Change output (if any)
                    if change_amount > 0:
                        # Get our key for change
                        our_key = Key()
                        our_key.generate_new_key()
                        add_key(our_key)  # Add to wallet

                        txout_change = TxOut()
                        txout_change.value = change_amount
                        txout_change.script_pubkey = Script()
                        txout_change.script_pubkey.push_data(our_key.get_pubkey())
                        txout_change.script_pubkey.push_opcode(OP_CHECKSIG)
                        tx.vout.append(txout_change)

                    # Sign transaction (simplified - in real implementation would sign properly)
                    # For now, we'll skip strict signing and let the mempool accept it

                    print(
                        f"[Node {node_id}] Creating transaction #{tx_num + 1}: "
                        f"Sending {send_amount / COIN:.4f} BTC to node {dest_node_id}"
                    )

                    # Try to accept transaction with proper checks
                    # First try with checks enabled, then fallback to disabled if needed
                    print(
                        f"[Node {node_id}] Attempting to accept transaction #{tx_num + 1} "
                        f"with check_inputs=True, check_utxos=True"
                    )
                    success, missing = accept_transaction(tx, check_inputs=True, check_utxos=True)
                    if not success:
                        # If it fails with checks, try without (for testing)
                        print(
                            f"[Node {node_id}] Transaction #{tx_num + 1} failed with checks: "
                            f"success={success}, missing={missing}"
                        )
                        print(
                            f"[Node {node_id}] Trying without checks "
                            f"(check_inputs=False, check_utxos=False)"
                        )
                        success, missing = accept_transaction(
                            tx, check_inputs=False, check_utxos=False
                        )
                        if success:
                            tx_num_display = tx_num + 1
                            print(
                                f"[Node {node_id}] Transaction #{tx_num_display} "
                                f"accepted without checks"
                            )
                        else:
                            print(
                                f"[Node {node_id}] Transaction #{tx_num + 1} still failed: "
                                f"success={success}, missing={missing}"
                            )

                    if success:
                        print(
                            f"[Node {node_id}] Transaction #{tx_num + 1} created: "
                            f"{tx.get_hash().get_hex()[:16]}, "
                            f"amount: {send_amount / COIN:.4f} BTC"
                        )
                    else:
                        print(f"[Node {node_id}] Transaction #{tx_num + 1} rejected: {missing}")

                    # Small delay between transactions
                    time.sleep(2)

            except Exception as e:
                print(f"[Node {node_id}] Error creating transactions: {e}")
                import traceback

                traceback.print_exc()

    import threading

    tx_thread = threading.Thread(target=create_transactions, daemon=True)
    tx_thread.start()

    # Signal handler for graceful shutdown
    def signal_handler(sig, frame):
        print(f"\n\n[Node {node_id}] Shutting down...")
        stop_mining()
        stop_node()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start HTTP API server for blockchain data (for visualization)
    def start_api_server():
        """Start simple HTTP server to expose blockchain data"""
        import json
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class BlockchainAPIHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/api/blockchain":
                    try:
                        chain = get_chain()
                        best_index = chain.get_best_index()

                        blocks = []
                        current = best_index
                        height = 0
                        while current and height < 100:
                            try:
                                block = chain.get_block(current.block_hash)
                                if not block:
                                    break

                                blocks.append(
                                    {
                                        "hash": current.block_hash.get_hex(),
                                        "height": current.height,
                                        "prev_hash": (
                                            current.prev.block_hash.get_hex()
                                            if current.prev
                                            else None
                                        ),
                                        "time": (block.time if hasattr(block, "time") else 0),
                                        "transactions": (
                                            len(block.transactions)
                                            if hasattr(block, "transactions")
                                            else 0
                                        ),
                                    }
                                )
                                current = current.prev
                                height += 1
                            except Exception:
                                break

                        data = {
                            "height": (
                                chain.best_height
                                if hasattr(chain, "best_height")
                                else (best_index.height if best_index else 0)
                            ),
                            "blocks": blocks,
                            "timestamp": time.time(),
                        }

                        self.send_response(200)
                        self.send_header("Content-type", "application/json")
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(json.dumps(data).encode())
                    except Exception as e:
                        self.send_error(500, str(e))
                else:
                    self.send_error(404)

            def log_message(self, format, *args):
                pass  # Suppress logging

        try:
            api_server = HTTPServer(("0.0.0.0", 8081), BlockchainAPIHandler)
            api_thread = threading.Thread(target=api_server.serve_forever, daemon=True)
            api_thread.start()
            print(f"[Node {node_id}] API server started on port 8081")
        except Exception as e:
            print(f"[Node {node_id}] Failed to start API server: {e}")

    start_api_server()

    # Main loop - print status periodically
    print(f"\n[Node {node_id}] Running... (Press Ctrl+C to stop)")
    try:
        while True:
            time.sleep(60)
            best = chain.get_best_index()
            if best:
                print(
                    f"[Node {node_id}] Height: {chain.best_height}, "
                    f"Hash: {best.block_hash.get_hex()[:16]}"
                )
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
