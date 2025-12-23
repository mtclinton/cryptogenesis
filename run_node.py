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

    # Create periodic transactions
    def create_transactions():
        """Create test transactions periodically"""
        from cryptogenesis.mempool import accept_transaction

        while True:
            try:
                time.sleep(30)  # Create transaction every 30 seconds
                tx = create_test_transaction(node_id)
                print(f"\n[Node {node_id}] Creating test transaction...")
                success, missing = accept_transaction(tx, check_inputs=False, check_utxos=False)
                if success:
                    print(
                        f"[Node {node_id}] Transaction created: " f"{tx.get_hash().get_hex()[:16]}"
                    )
                else:
                    print(f"[Node {node_id}] Transaction rejected")
            except Exception as e:
                print(f"[Node {node_id}] Error creating transaction: {e}")

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
